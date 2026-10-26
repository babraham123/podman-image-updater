#!/usr/bin/env python3
# Keeps a host's Podman container images current behind a vulnerability scan. For each
# image in the config's update order whose quadlet is installed: compare the upstream
# digest with the one handled last, download a changed one, scan it with Trivy (fixable
# HIGH or CRITICAL blocks it), load it under its localhost/ name and let `podman
# auto-update` restart the containers on it. Quadlets only name localhost/ images with
# AutoUpdate=local, so nothing unscanned reaches a container. Images built on the host
# pass through the same gate. Design and config format: README.md. Standard library only.
# Usage:
#   image_updater [--config FILE] [--host NAME]        # the nightly timer
#   image_updater --dry-run                            # check and scan; loads and restarts nothing
#   image_updater install SERVICE                      # before copying SERVICE's quadlets
#   sudo image_updater accept CONTAINER                # a person, after reading the findings
# --config defaults to $IMAGE_UPDATER_CONFIG, then /etc/image_updater/config.json; --host
# picks the config's `hosts` entry, default the short hostname.
# Overrides for a blocked image, both needing a person: the image's trivyignore file
# (`CVE-… exp:YYYY-MM-DD`, with a `#` line giving the reason) covers every digest until it
# expires; `accept` rescans, prints the findings and passes that exact digest, or for a
# built image that exact set of build script inputs.

import argparse
import base64
import fcntl
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path

DEFAULT_CONFIG = "/etc/image_updater/config.json"
# Top-level config keys, and a host entry's, with their defaults. deadline_s: no image is
# started after this many seconds, so a run stays inside its slot and what's left runs the
# next night; 0 is no deadline. boot_delay_s: a run this soon after boot waits until then.
DEFAULTS = {
  "images": [],
  "ntfy": None,
  "registry_auth": {},
  "deadline_s": 0,
  "boot_delay_s": 0,
  "state_dir": "/var/lib/image_updater",
  "metrics_file": "/var/lib/node_exporter/textfile_collector/image_updater.prom",
  "trivy_cache": "/var/cache/trivy",
  "quadlet_dir": "/etc/containers/systemd",
  "path": "/usr/sbin:/usr/bin:/sbin:/bin",
}
RETRY_DELAY_S = 60
NTFY_RETRY_DELAY_S = 30


class Fatal(Exception):
  """die: ends the run, or the one image's attempt it was raised in."""


class Result(Exception):
  """Ends an image's attempt with its outcome: unchanged, pass (dry run), loaded,
  current, updated, failed, blocked or error."""

  def __init__(self, outcome, message=""):
    super().__init__(outcome)
    self.outcome, self.message = outcome, message


def log(message, stream=None):
  print(
    f"{datetime.now().astimezone().isoformat(timespec='seconds')} {message}",
    file=stream or sys.stdout,
    flush=True,
  )


def warn(message):
  log(f"warning: {message}", sys.stderr)


def die(message):
  raise Fatal(message)


def run(*cmd, check=True, capture=False, **kwargs):
  """Runs cmd, its output to the journal unless captured; raises on failure if check."""
  return subprocess.run(
    [str(c) for c in cmd],
    check=check,
    text=True,
    stdout=subprocess.PIPE if capture else None,
    **kwargs,
  )


def ok(*cmd):
  return run(*cmd, check=False, stderr=subprocess.DEVNULL).returncode == 0


def check_secret(spec, where):
  if spec is None:
    return
  if not (
    isinstance(spec, dict)
    and len(spec) == 1
    and (
      isinstance(spec.get("env"), str)
      or isinstance(spec.get("file"), str)
      or (isinstance(spec.get("command"), list) and spec["command"])
    )
  ):
    die(f'{where}: a secret is {{"env": NAME}}, {{"file": PATH}} or {{"command": [ARGV...]}}')


def check_image(entry, where):
  if not isinstance(entry, dict):
    die(f"{where}: not an object")
  for key in ("container", "image"):
    if not isinstance(entry.get(key), str):
      die(f"{where}: needs {key}")
  if ("upstream" in entry) == ("build" in entry):
    die(f"{where}: needs one of upstream or build")
  if "build" in entry and not isinstance(entry.get("build_script"), str):
    die(f"{where}: a build image needs build_script")
  unknown = set(entry) - {
    "service",
    "container",
    "image",
    "upstream",
    "build",
    "build_script",
    "trivyignore",
  }
  if unknown:
    die(f"{where}: unknown keys {', '.join(sorted(unknown))}")


def load_config(path, host):
  """The host's config: the file's top-level keys, overlaid by its hosts[HOST] entry if it
  has `hosts`, over DEFAULTS."""
  try:
    data = json.loads(Path(path).read_text())
  except OSError as e:
    die(f"can't read {path}: {e.strerror}")
  except ValueError as e:
    die(f"{path}: invalid JSON: {e}")
  if not isinstance(data, dict):
    die(f"{path}: not a JSON object")
  hosts = data.pop("hosts", None)
  if hosts is not None:
    if host not in hosts:
      die(f"{path}: no hosts entry for {host}")
    data.update(hosts[host])
  unknown = set(data) - set(DEFAULTS)
  if unknown:
    die(f"{path}: unknown keys {', '.join(sorted(unknown))}")
  config = {**DEFAULTS, **data}
  containers = set()
  for n, entry in enumerate(config["images"]):
    check_image(entry, f"{path}: images[{n}]")
    entry.setdefault("service", entry["container"])
    if entry["container"] in containers:
      die(f"{path}: images[{n}]: container {entry['container']} is listed twice")
    containers.add(entry["container"])
  if config["ntfy"] is not None:
    if not isinstance(config["ntfy"].get("url"), str):
      die(f"{path}: ntfy needs url")
    check_secret(config["ntfy"].get("token"), f"{path}: ntfy.token")
  for registry, creds in config["registry_auth"].items():
    for key in ("username", "password"):
      check_secret(creds.get(key), f"{path}: registry_auth.{registry}.{key}")
  return config


def secret(spec):
  """A secret's value, "" if unset. A command's trailing newline is dropped, and "null",
  what yq prints for a missing key, counts as unset."""
  if spec is None:
    return ""
  if "env" in spec:
    value = os.environ.get(spec["env"], "")
  elif "file" in spec:
    value = Path(spec["file"]).read_text()
  else:
    value = run(*spec["command"], capture=True).stdout
  value = value.rstrip("\n")
  return "" if value == "null" else value


def ntfy_post(url, token, priority, title, message, tags, attempts):
  """Posts to an ntfy topic and returns whether it got through. A timer run may start
  before ntfy is up after a reboot, so it retries; a rejected request (4xx other than 429)
  won't pass on a retry, so it fails at once."""
  headers = {"X-Title": title, "X-Priority": str(priority), "X-Tags": tags}
  if token:
    headers["Authorization"] = f"Bearer {token}"
  request = urllib.request.Request(url, data=message.encode(), headers=headers)
  for attempt in range(attempts):
    try:
      urllib.request.urlopen(request, timeout=15).close()
      return True
    except urllib.error.HTTPError as e:
      if 400 <= e.code < 500 and e.code != 429:
        return False
    except OSError:
      pass
    if attempt < attempts - 1:
      time.sleep(NTFY_RETRY_DELAY_S)
  return False


def notify(priority, title, message):
  if cfg["ntfy"] is None:
    return
  # A person running install or accept is waiting; only the timer may be up before ntfy is
  attempts = 9 if mode == "run" else 1
  if not ntfy_post(
    cfg["ntfy"]["url"],
    secret(cfg["ntfy"].get("token")),
    priority,
    f"{host}: {title}",
    message,
    cfg["ntfy"].get("tags", "package"),
    attempts,
  ):
    warn(f"ntfy post failed: {title}")


def registry_auth():
  """skopeo's --authfile for the registries with credentials, or nothing."""
  auths = {}
  for registry, creds in cfg["registry_auth"].items():
    user, password = secret(creds.get("username")), secret(creds.get("password"))
    if user and password:
      auths[registry] = {"auth": base64.b64encode(f"{user}:{password}".encode()).decode()}
    else:
      warn(f"no credentials for {registry}; pulling anonymously")
  if not auths:
    return []
  path = tmp / "auth.json"
  path.touch(mode=0o600)
  path.write_text(json.dumps({"auths": auths}))
  return ["--authfile", path]


# A scan never runs against a stale database: the caller fails when this does.
def trivy_refresh():
  cache = cfg["trivy_cache"]
  return ok("trivy", "image", "--quiet", "--cache-dir", cache, "--download-db-only") and ok(
    "trivy", "image", "--quiet", "--cache-dir", cache, "--download-java-db-only"
  )


def scan(entry, source, report):
  """Exit 0 passes, 3 has findings, anything else is an error."""
  ignore = entry.get("trivyignore")
  return run(
    "trivy",
    "image",
    "--quiet",
    "--cache-dir",
    cfg["trivy_cache"],
    "--cache-backend",
    "memory",
    "--skip-db-update",
    "--skip-java-db-update",
    "--scanners",
    "vuln",
    "--severity",
    "HIGH,CRITICAL",
    "--ignore-unfixed",
    "--exit-code",
    "3",
    "--format",
    "json",
    "--output",
    report,
    *(["--ignorefile", ignore] if ignore and Path(ignore).is_file() else []),
    "--input",
    source,
    check=False,
  ).returncode


def vulnerabilities(report):
  for result in json.loads(Path(report).read_text()).get("Results") or []:
    for v in result.get("Vulnerabilities") or []:
      yield result.get("Target"), v


def findings(report):
  for target, v in vulnerabilities(report):
    print(
      f"{v.get('Severity')} {v.get('VulnerabilityID')} {v.get('PkgName')} "
      f"{v.get('InstalledVersion')} -> {v.get('FixedVersion')} ({target})",
      flush=True,
    )


def last_digest(container):
  try:
    return (state / container).read_text().split(" ")[0].strip()
  except FileNotFoundError:
    return ""


def record(container, key, outcome):
  """The digest isn't handled again until upstream moves."""
  (state / container).write_text(f"{key} {outcome}\n")
  (state / f"{container}.blocked").unlink(missing_ok=True)


def attempt(check, entry):
  """Runs one image's check and returns its outcome, or broken if it failed. One image's
  failure doesn't end the run. An error (a registry or build input lookup that failed,
  before anything changed) is tried again twice, a minute apart, so a blip doesn't cost
  the night."""
  container = entry["container"]
  for try_ in range(3):
    try:
      check(entry)
      outcome = "broken"
      log(f"{container}: ended without an outcome")
    except Result as r:
      outcome = r.outcome
      if r.message:
        log(f"{container}: {r.message}")
    except Exception as e:
      outcome = "broken"
      log(f"error: {e}", sys.stderr)
    if outcome != "error" or try_ == 2:
      return outcome
    time.sleep(RETRY_DELAY_S)


def accept_command(container):
  return f"sudo {shlex.join(self_cmd)} accept {container}"


def blocked(entry, key, report):
  """The scan gate stopped KEY; the old image keeps running."""
  container = entry["container"]
  findings(report)
  if mode == "run":
    marker = state / f"{container}.blocked"
    if not marker.exists():
      marker.write_text(f"{int(time.time())}\n")
    days = (int(time.time()) - int(marker.read_text())) // 86400
    ids = sorted({v.get("VulnerabilityID") for _, v in vulnerabilities(report)})
    ids = ", ".join(ids[:10]) + (", …" if len(ids) > 10 else "")
    if days < 7:
      notify(
        3,
        f"{container} update blocked",
        f"{key} has fixable HIGH/CRITICAL CVEs: {ids}. The old image keeps running.",
      )
    else:
      ignore = entry.get("trivyignore")
      where = f"to {ignore} with an exp: date, or" if ignore else "to a trivyignore file, or"
      notify(
        5,
        f"{container} blocked for {days} days",
        f"{key} has fixable HIGH/CRITICAL CVEs: {ids}. To override after review, add them "
        f"{where} on {host} run: {accept_command(container)}",
      )
  elif mode == "install":
    log(f"after review, to override: {accept_command(container)}, then install again")


def is_accepted(container, key):
  try:
    return key in (accepted / container).read_text().splitlines()
  except FileNotFoundError:
    return False


def gate(entry, key, source):
  """Returns if the image at SOURCE passes the scan, else ends the attempt as blocked. KEY
  is the digest or build inputs `accept` would record."""
  container = entry["container"]
  if is_accepted(container, key):
    log(f"{container}: {key} was accepted; not gated")
    return
  report = tmp / f"{container}.json"
  rc = scan(entry, source, report)
  if rc == 0:
    log(f"{container}: scan passed")
  elif rc == 3:
    blocked(entry, key, report)
    raise Result("blocked", "blocked by the scan")
  else:
    die(f"trivy failed on {container} (exit {rc})")


def untagged(image):
  return image.rsplit(":", 1)[0]


def keep_rollback(image):
  """What IMAGE names now stays reachable as its :rollback."""
  if ok("podman", "image", "exists", image):
    run("podman", "tag", image, f"{untagged(image)}:rollback")


def auto_update_result(container):
  """What `podman auto-update` reports for CONTAINER's unit, "" if nothing. Exit codes
  aren't documented, so only the report counts."""
  out = run("podman", "auto-update", "--format", "json", check=False, capture=True).stdout
  for unit in json.loads(out or "[]") or []:
    if unit.get("Unit") == f"{container}.service":
      updated = unit.get("Updated")
      return str(updated).lower() if isinstance(updated, bool) else str(updated)
  return ""


def roll_out(container, image, key):
  """IMAGE names the new image now. Restarts the container on it, or puts the :rollback
  image back."""
  if mode == "install":
    record(container, key, "loaded")
    raise Result("loaded", f"loaded {key}")
  # Each call also acts on every other AutoUpdate=local container, which is why a failed
  # image is pointed back at :rollback below before the next one.
  updated = auto_update_result(container)
  if updated == "true":
    record(container, key, "updated")
    raise Result("updated", f"updated to {key}")
  if updated == "false":
    record(container, key, "current")
    raise Result("current", f"already running {key}")
  if updated == "":
    # Not running, or its quadlet doesn't use AutoUpdate=local
    record(container, key, "loaded")
    raise Result("loaded", f"loaded {key}; no running container uses it")
  if ok("podman", "image", "exists", f"{untagged(image)}:rollback"):
    run("podman", "tag", f"{untagged(image)}:rollback", image)
  if not ok("systemctl", "is-active", "--quiet", f"{container}.service"):
    ok("systemctl", "restart", f"{container}.service")
  record(container, key, "failed")
  notify(
    4,
    f"{container} update failed",
    f"{key} didn't start (auto-update: {updated}); back on the previous image. "
    "Not retried until upstream changes.",
  )
  raise Result("failed", f"update failed ({updated}); rolled back")


def upstream_digest(upstream):
  out = run("skopeo", "inspect", "--no-tags", *auth, f"docker://{upstream}", capture=True).stdout
  return json.loads(out)["Digest"]


def download(upstream, digest, oci_dir):
  """By digest, so what's scanned is what the inspect saw even if the tag moves meanwhile."""
  shutil.rmtree(oci_dir, ignore_errors=True)
  run(
    "skopeo", "copy", "--quiet", *auth, f"docker://{untagged(upstream)}@{digest}", f"oci:{oci_dir}"
  )


def check_upstream(entry):
  """One pulled image."""
  container, image, upstream = entry["container"], entry["image"], entry["upstream"]
  oci_dir = staging / container
  try:
    # Always remote against remote: a multi-arch tag's digest isn't the local image's.
    digest = upstream_digest(upstream)
  except (subprocess.CalledProcessError, ValueError, KeyError):
    raise Result("error", f"can't inspect {upstream}; trying again tomorrow")
  if last_digest(container) == digest and ok("podman", "image", "exists", image):
    raise Result("unchanged", f"unchanged at {digest}")
  log(f"{container}: {upstream} is at {digest}")
  try:
    download(upstream, digest, oci_dir)
  except subprocess.CalledProcessError:
    raise Result("error", f"can't download {upstream}; trying again tomorrow")
  gate(entry, digest, oci_dir)
  if mode == "dry-run":
    raise Result("pass", f"would load {digest} as {image}")
  keep_rollback(image)
  run("skopeo", "copy", "--quiet", f"oci:{oci_dir}", f"containers-storage:{image}")
  roll_out(container, image, digest)


def build_versions(entry):
  """The build script's inputs as one key, the one `accept` records for a built image."""
  script = entry["build_script"]
  if not os.access(script, os.X_OK):
    die(f"{entry['container']}: no executable {script}")
  return ",".join(run(script, "versions", capture=True).stdout.split())


def build_candidate(entry, archive):
  """Builds localhost/BUILD:candidate into ARCHIVE and returns its image ID. Scanned from a
  file, so Trivy doesn't need the podman socket. Untagged before the gate, so a blocked
  build is only a dangling image the next prune removes."""
  candidate = f"localhost/{entry['build']}:candidate"
  run(entry["build_script"], "build", "candidate")
  run("podman", "save", "-o", archive, candidate)
  built_id = json.loads(run("podman", "image", "inspect", candidate, capture=True).stdout)[0]["Id"]
  run("podman", "untag", candidate)
  return built_id


def check_build(entry):
  """One image built here, ending like check_upstream. The build script takes `versions`
  (print every input it builds from: commits, base image digests) and `build TAG` (build
  localhost/BUILD:TAG from them)."""
  container, image = entry["container"], entry["image"]
  archive = staging / f"{container}.tar"
  try:
    versions = build_versions(entry)
  except subprocess.CalledProcessError:
    raise Result("error", f"can't resolve {entry['build']}'s build inputs; trying again tomorrow")
  if last_digest(container) == versions and ok("podman", "image", "exists", image):
    raise Result("unchanged", f"unchanged at {versions}")
  log(f"{container}: building {versions}")
  built_id = build_candidate(entry, archive)
  gate(entry, versions, archive)
  if mode == "dry-run":
    raise Result("pass", f"would tag {versions} as {image}")
  keep_rollback(image)
  run("podman", "tag", built_id, image)
  roll_out(container, image, versions)


def check(entry):
  return check_upstream if "upstream" in entry else check_build


def wait_for_boot():
  """Every run waits for boot, inside the script: a timer firing during boot would
  otherwise hold boot open while its unit waits on it."""
  status = run("systemctl", "is-system-running", "--wait", check=False, capture=True).stdout.strip()
  if status == "degraded":
    failed = run(
      "systemctl", "list-units", "--failed", "--plain", "--no-legend", check=False, capture=True
    ).stdout
    warn(
      f"system degraded, failed units: {' '.join(line.split()[0] for line in failed.splitlines() if line)}"
    )
  elif status != "running":
    die(f"system is {status}")
  if not cfg["boot_delay_s"]:
    return
  up = int(float(Path("/proc/uptime").read_text().split()[0]))
  if up < cfg["boot_delay_s"]:
    log(f"waiting {cfg['boot_delay_s'] - up}s after boot")
    time.sleep(cfg["boot_delay_s"] - up)


def write_metrics(clean, count):
  """Keeps the previous success timestamp when this run wasn't clean, so an age alert
  counts from the last good run."""
  if not cfg["metrics_file"]:
    return
  metrics = Path(cfg["metrics_file"])
  name = "image_updater_last_success_timestamp_seconds"
  last = None
  if metrics.exists():
    last = next(
      (line.split()[1] for line in metrics.read_text().splitlines() if line.split()[:1] == [name]),
      None,
    )
  if clean:
    last = int(time.time())
  lines = [
    f"# HELP {name} Unix time of the last image_updater run with no broken or erroring image.",
    f"# TYPE {name} gauge",
  ]
  if last is not None:
    lines.append(f"{name} {last}")
  lines += [
    "# HELP image_updater_images Images in the last image_updater run, by result.",
    "# TYPE image_updater_images gauge",
  ]
  lines += [f'image_updater_images{{result="{r}"}} {n}' for r, n in count.items()]
  lines += [
    "# HELP image_updater_blocked_days Days since the scan gate first blocked the container's update.",
    "# TYPE image_updater_blocked_days gauge",
  ]
  for marker in sorted(state.glob("*.blocked")):
    days = (int(time.time()) - int(marker.read_text())) // 86400
    lines.append(f'image_updater_blocked_days{{container="{marker.stem}"}} {days}')
  metrics.parent.mkdir(parents=True, exist_ok=True)
  partial = metrics.with_name(f"{metrics.name}.tmp")
  partial.write_text("\n".join(lines) + "\n")
  partial.chmod(0o644)
  # node_exporter only reads *.prom, and the rename is atomic.
  partial.rename(metrics)


def finish(clean, count):
  """The end of a nightly run, whatever happened."""
  try:
    write_metrics(clean, count)
  except OSError as e:
    warn(f"writing metrics failed: {e}")
  sys.exit(0 if clean else 1)


def update_all():
  global auth
  dry = mode == "dry-run"
  count = Counter(
    {k: 0 for k in ("checked", "updated", "blocked", "failed", "error", "broken", "deferred")}
  )
  if not dry:
    wait_for_boot()
  auth = registry_auth()
  if not trivy_refresh():
    if dry:
      die("Trivy DB refresh failed")
    warn("Trivy DB refresh failed; nothing checked")
    notify(5, "Image updater broken", "Trivy DB refresh failed, so nothing was checked.")
    finish(False, count)
  started, broken = time.monotonic(), []
  for entry in cfg["images"]:
    container = entry["container"]
    if not (Path(cfg["quadlet_dir"]) / f"{container}.container").is_file():
      continue
    if not dry and cfg["deadline_s"] and time.monotonic() - started > cfg["deadline_s"]:
      log(f"{container}: past the deadline, left for tomorrow")
      count["deferred"] += 1
      continue
    count["checked"] += 1
    outcome = attempt(check(entry), entry)
    if outcome in ("updated", "blocked", "failed"):
      count[outcome] += 1
    # An error that outlasted its retries is broken too: expired registry credentials
    # would otherwise stop every update without an age alert ever firing.
    elif outcome in ("error", "broken"):
      count[outcome] += 1
      broken.append(container)
      warn(f"{container}: pipeline {outcome}")
  if dry:
    if broken:
      die(f"broken: {' '.join(broken)}")
    return
  if not ok("podman", "image", "prune", "-f"):
    warn("image prune failed")
  if broken:
    notify(
      5, "Image updater broken", f"Failed on: {' '.join(broken)}. See journalctl -u image_updater."
    )
    finish(False, count)
  finish(True, count)


def install_images(service):
  """Every image of SERVICE is loaded and passed the scan gate before its quadlets are
  copied, or the install stops here."""
  global auth
  ready = False
  for entry in cfg["images"]:
    if entry["service"] != service:
      continue
    if not ready:
      auth = registry_auth()
      if not trivy_refresh():
        die("Trivy DB refresh failed")
      ready = True
    outcome = attempt(check(entry), entry)
    if outcome == "blocked":
      die(f"{entry['container']}: blocked by the scan gate")
    if outcome not in ("unchanged", "loaded"):
      die(f"{entry['container']}: {outcome}")


def accept(container):
  """Passes the current upstream digest, or build inputs, through the scan gate."""
  global auth
  entry = next((e for e in cfg["images"] if e["container"] == container), None)
  if entry is None:
    die(f"no image for container {container} on {host}")
  auth = registry_auth()
  if not trivy_refresh():
    die("Trivy DB refresh failed")
  report = tmp / f"{container}.json"
  if "upstream" in entry:
    key = upstream_digest(entry["upstream"])
    source = staging / container
    download(entry["upstream"], key, source)
  else:
    # The next run builds again, so what this passes is the inputs, not this image.
    try:
      key = build_versions(entry)
    except subprocess.CalledProcessError:
      die(f"can't resolve {entry['build']}'s build inputs")
    source = staging / f"{container}.tar"
    log(f"{container}: building {key}")
    build_candidate(entry, source)
  rc = scan(entry, source, report)
  if rc == 0:
    log(f"{container}: {key} has no fixable HIGH/CRITICAL findings")
  elif rc == 3:
    findings(report)
  else:
    die(f"trivy failed (exit {rc})")
  with (accepted / container).open("a") as f:
    f.write(f"{key}\n")
  log(f"{container}: accepted {key}; the next run loads it")
  notify(3, f"{container} accepted", f"{key} was accepted past the scan gate.")


def parse_args(argv):
  parser = argparse.ArgumentParser(
    prog="image_updater", description="Podman image updates behind a Trivy scan gate."
  )
  parser.add_argument(
    "--config",
    default=os.environ.get("IMAGE_UPDATER_CONFIG", DEFAULT_CONFIG),
    help=f"config file (default: $IMAGE_UPDATER_CONFIG, then {DEFAULT_CONFIG})",
  )
  parser.add_argument(
    "--host", help="the config's hosts entry to use (default: the short hostname)"
  )
  parser.add_argument(
    "--dry-run", action="store_true", help="check and scan every image; load and restart nothing"
  )
  parser.add_argument(
    "command",
    nargs="?",
    choices=("install", "accept"),
    help="install SERVICE: load and gate its images; "
    "accept CONTAINER: pass its current image past the gate",
  )
  parser.add_argument("name", nargs="?", help="SERVICE or CONTAINER")
  args = parser.parse_args(argv)
  if bool(args.command) != bool(args.name) or (args.command and args.dry_run):
    parser.error("expected nothing, --dry-run, install SERVICE or accept CONTAINER")
  return args


def main(argv):
  global cfg, mode, tmp, auth, host, state, staging, accepted, self_cmd
  args = parse_args(argv)
  host = args.host or socket.gethostname().split(".")[0]
  self_cmd = [os.path.abspath(sys.argv[0])]
  if args.config != DEFAULT_CONFIG:
    self_cmd += ["--config", os.path.abspath(args.config)]
  if args.host:
    self_cmd += ["--host", args.host]
  if os.geteuid() != 0:
    die("must run as root")
  cfg = load_config(args.config, host)
  mode = args.command or ("dry-run" if args.dry_run else "run")
  os.environ["PATH"] = cfg["path"]
  var = Path(cfg["state_dir"])
  # state/<container>: "<remote digest or build inputs> <outcome>" of the one handled
  # last; state/<container>.blocked: when the scan gate first blocked it.
  # accepted/<container>: what `accept` passed, one per line.
  state, staging, accepted = var / "state", var / "staging", var / "accepted"
  for path in (var, state, staging, accepted):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
  with open(var / "lock", "w") as lock:
    try:
      fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
      die("another image_updater is running")
    tmp = Path(tempfile.mkdtemp())
    try:
      if mode == "install":
        install_images(args.name)
      elif mode == "accept":
        accept(args.name)
      else:
        update_all()
    finally:
      shutil.rmtree(tmp, ignore_errors=True)
      for path in staging.iterdir():
        shutil.rmtree(path) if path.is_dir() else path.unlink()


def cli(argv):
  """main's exit status; a nightly run's finish exits itself."""
  try:
    main(argv)
  except (Fatal, subprocess.CalledProcessError) as e:
    log(f"error: {e}", sys.stderr)
    return 1
  return 0


cfg, mode, tmp, auth, host, self_cmd = None, None, None, [], None, []
state = staging = accepted = None

if __name__ == "__main__":
  sys.exit(cli(sys.argv[1:]))

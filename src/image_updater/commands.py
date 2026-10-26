# The nightly run, install and accept.

import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from . import ctx
from .images import build_candidate, build_versions, check, download, registry_auth, upstream_digest
from .metrics import write_metrics
from .ntfy import notify
from .scan import findings, scan, trivy_refresh
from .util import Result, die, log, ok, run, warn

RETRY_DELAY_S = 60


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
  if not ctx.cfg["boot_delay_s"]:
    return
  up = int(float(Path("/proc/uptime").read_text().split()[0]))
  if up < ctx.cfg["boot_delay_s"]:
    log(f"waiting {ctx.cfg['boot_delay_s'] - up}s after boot")
    time.sleep(ctx.cfg["boot_delay_s"] - up)


def finish(clean, count):
  """The end of a nightly run, whatever happened."""
  try:
    write_metrics(clean, count)
  except OSError as e:
    warn(f"writing metrics failed: {e}")
  sys.exit(0 if clean else 1)


def update_all():
  dry = ctx.mode == "dry-run"
  count = Counter(
    {k: 0 for k in ("checked", "updated", "blocked", "failed", "error", "broken", "deferred")}
  )
  if not dry:
    wait_for_boot()
  ctx.auth = registry_auth()
  if not trivy_refresh():
    if dry:
      die("Trivy DB refresh failed")
    warn("Trivy DB refresh failed; nothing checked")
    notify(5, "Image updater broken", "Trivy DB refresh failed, so nothing was checked.")
    finish(False, count)
  started, broken = time.monotonic(), []
  for entry in ctx.cfg["images"]:
    container = entry["container"]
    if not (Path(ctx.cfg["quadlet_dir"]) / f"{container}.container").is_file():
      continue
    if not dry and ctx.cfg["deadline_s"] and time.monotonic() - started > ctx.cfg["deadline_s"]:
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
  ready = False
  for entry in ctx.cfg["images"]:
    if entry["service"] != service:
      continue
    if not ready:
      ctx.auth = registry_auth()
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
  entry = next((e for e in ctx.cfg["images"] if e["container"] == container), None)
  if entry is None:
    die(f"no image for container {container} on {ctx.host}")
  ctx.auth = registry_auth()
  if not trivy_refresh():
    die("Trivy DB refresh failed")
  report = ctx.tmp / f"{container}.json"
  if "upstream" in entry:
    key = upstream_digest(entry["upstream"])
    source = ctx.staging / container
    download(entry["upstream"], key, source)
  else:
    # The next run builds again, so what this passes is the inputs, not this image.
    try:
      key = build_versions(entry)
    except subprocess.CalledProcessError:
      die(f"can't resolve {entry['build']}'s build inputs")
    source = ctx.staging / f"{container}.tar"
    log(f"{container}: building {key}")
    build_candidate(entry, source)
  rc = scan(entry, source, report)
  if rc == 0:
    log(f"{container}: {key} has no fixable HIGH/CRITICAL findings")
  elif rc == 3:
    findings(report)
  else:
    die(f"trivy failed (exit {rc})")
  with (ctx.accepted / container).open("a") as f:
    f.write(f"{key}\n")
  log(f"{container}: accepted {key}; the next run loads it")
  notify(3, f"{container} accepted", f"{key} was accepted past the scan gate.")

# The Trivy scan gate.

import json
import os
import shlex
import time
from pathlib import Path

from . import ctx
from .util import Result, die, log, ok, run, write_atomic


# A scan never runs against a stale database: the caller fails when this does.
def trivy_refresh():
  # Trivy stages a download in TMPDIR, often a tmpfs too small for the ~1 GB Java DB, so it
  # stages beside the cache instead.
  cache = Path(ctx.cfg["trivy_cache"])
  cache.mkdir(parents=True, exist_ok=True)
  env = {**os.environ, "TMPDIR": str(cache)}
  dbs = ["--download-db-only"] + (["--download-java-db-only"] if ctx.cfg["java_db"] else [])
  return all(ok("trivy", "image", "--quiet", "--cache-dir", cache, db, env=env) for db in dbs)


def scan(entry, source, report):
  """Exit 0 passes, 3 has findings, anything else is an error."""
  ignore = entry.get("trivyignore")
  return run(
    "trivy",
    "image",
    "--quiet",
    "--cache-dir",
    ctx.cfg["trivy_cache"],
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


def accept_command(container):
  return f"sudo {shlex.join(ctx.self_cmd)} accept {container}"


def blocked_marker(container):
  return ctx.state / f"{container}.blocked"


def blocked_markers():
  return sorted(ctx.state.glob("*.blocked"))


def read_marker(marker):
  """(since, cves) of a blocked marker. One whose date doesn't parse is dated now and written
  back, so its days count up from here instead of restarting at 0 every run."""
  since, cves = (marker.read_text().splitlines() + ["", ""])[:2]
  try:
    return int(since), cves
  except ValueError:
    since = int(time.time())
    write_atomic(marker, f"{since}\n{cves}\n")
    return since, cves


def blocked(group, key, report):
  """The scan gate stopped KEY; the old image keeps running. No notification: each
  container's marker feeds image_updater_blocked_days, so one alert rule can list every
  blocked container."""
  findings(report)
  command = accept_command(group[0]["container"])
  if ctx.mode == "run":
    ids = sorted({v.get("VulnerabilityID") for _, v in vulnerabilities(report)})
    ids = ", ".join(ids[:10]) + (", …" if len(ids) > 10 else "")
    for entry in group:
      marker = blocked_marker(entry["container"])
      since = read_marker(marker)[0] if marker.exists() else int(time.time())
      write_atomic(marker, f"{since}\n{ids}\n")
    log(f"after review, to override: {command}")
  elif ctx.mode == "install":
    log(f"after review, to override: {command}, then install again")


def is_accepted(container, key):
  try:
    return key in (ctx.accepted / container).read_text().splitlines()
  except FileNotFoundError:
    return False


def gate(group, key, source):
  """Returns if the image at SOURCE passes the scan, else ends the attempt as blocked. KEY
  is the digest or build inputs `accept` would record; accepting it for any container on
  the image passes it for all of them."""
  container = group[0]["container"]
  if any(is_accepted(e["container"], key) for e in group):
    log(f"{container}: {key} was accepted; not gated")
    return
  report = ctx.tmp / f"{container}.json"
  rc = scan(group[0], source, report)
  if rc == 0:
    log(f"{container}: scan passed")
  elif rc == 3:
    blocked(group, key, report)
    raise Result("blocked", "blocked by the scan")
  else:
    die(f"trivy failed on {container} (exit {rc})")

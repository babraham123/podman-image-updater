# The Trivy scan gate.

import json
import os
import shlex
import time
from pathlib import Path

from . import ctx
from .ntfy import notify
from .util import Result, die, log, ok, run


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


def blocked(entry, key, report):
  """The scan gate stopped KEY; the old image keeps running."""
  container = entry["container"]
  findings(report)
  if ctx.mode == "run":
    marker = ctx.state / f"{container}.blocked"
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
        f"{where} on {ctx.host} run: {accept_command(container)}",
      )
  elif ctx.mode == "install":
    log(f"after review, to override: {accept_command(container)}, then install again")


def is_accepted(container, key):
  try:
    return key in (ctx.accepted / container).read_text().splitlines()
  except FileNotFoundError:
    return False


def gate(entry, key, source):
  """Returns if the image at SOURCE passes the scan, else ends the attempt as blocked. KEY
  is the digest or build inputs `accept` would record."""
  container = entry["container"]
  if is_accepted(container, key):
    log(f"{container}: {key} was accepted; not gated")
    return
  report = ctx.tmp / f"{container}.json"
  rc = scan(entry, source, report)
  if rc == 0:
    log(f"{container}: scan passed")
  elif rc == 3:
    blocked(entry, key, report)
    raise Result("blocked", "blocked by the scan")
  else:
    die(f"trivy failed on {container} (exit {rc})")

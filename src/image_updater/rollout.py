# Putting a gated image in place, and rolling back when it doesn't start.

import json

from . import ctx
from .ntfy import notify
from .scan import blocked_marker
from .util import Result, ok, run


def last_digest(container):
  try:
    return (ctx.state / container).read_text().split(" ")[0].strip()
  except FileNotFoundError:
    return ""


def handled(group, key, image):
  """Every container on IMAGE handled KEY last, and IMAGE is still there."""
  return all(last_digest(e["container"]) == key for e in group) and ok(
    "podman", "image", "exists", image
  )


def record(container, key, outcome):
  """The digest isn't handled again until upstream moves."""
  (ctx.state / container).write_text(f"{key} {outcome}\n")
  blocked_marker(container).unlink(missing_ok=True)


def untagged(image):
  return image.rsplit(":", 1)[0]


def keep_rollback(image):
  """What IMAGE names now stays reachable as its :rollback."""
  if ok("podman", "image", "exists", image):
    run("podman", "tag", image, f"{untagged(image)}:rollback")


def auto_update():
  """`podman auto-update`'s exit status and each unit's Updated: "true", "false", "failed",
  "rolled back". It exits non-zero when any unit on the host fails, so the report is what
  counts."""
  proc = run("podman", "auto-update", "--format", "json", check=False, capture=True)
  units = {}
  for unit in json.loads(proc.stdout or "[]") or []:
    updated = unit.get("Updated")
    units[unit.get("Unit")] = str(updated).lower() if isinstance(updated, bool) else str(updated)
  return proc.returncode, units


def roll_out(group, image, key):
  """IMAGE names the new image now, for every container in GROUP. Restarts them on it, or
  puts the :rollback image back for all of them. Returns each container's Result."""
  containers = [e["container"] for e in group]
  if ctx.mode == "install":
    for c in containers:
      record(c, key, "loaded")
    return {c: Result("loaded", f"loaded {key}") for c in containers}
  # One call restarts every container on IMAGE, in no set order, and also acts on every
  # other AutoUpdate=local container, which is why a failed image is pointed back at
  # :rollback before the next one.
  rc, units = auto_update()
  status = {c: units.get(f"{c}.service") for c in containers}
  results = {}
  if rc != 0:
    # A unit podman couldn't handle (a DBus or task error) is left out of a failed report,
    # and its container still runs the old image.
    for c, s in status.items():
      if s is None:
        results[c] = Result("error", f"missing from a failed auto-update; {key} not recorded")
  failed = {c: s for c, s in status.items() if s not in (None, "true", "false")}
  if failed:
    return rolled_back(image, key, status, failed, results)
  outcomes = {
    "true": ("updated", f"updated to {key}"),
    "false": ("current", f"already running {key}"),
    # Not running, or its quadlet doesn't use AutoUpdate=local
    None: ("loaded", f"loaded {key}; no running container uses it"),
  }
  for c, s in status.items():
    if c not in results:
      outcome, message = outcomes[s]
      record(c, key, outcome)
      results[c] = Result(outcome, message)
  return results


def rolled_back(image, key, status, failed, results):
  """KEY didn't start on the FAILED containers, so it fails for every container on IMAGE:
  they share one tag, which can't be new for some and old for others."""
  if ok("podman", "image", "exists", f"{untagged(image)}:rollback"):
    run("podman", "tag", f"{untagged(image)}:rollback", image)
  for c, s in status.items():
    # A sibling restarted before the failure, or one already on KEY, keeps running it
    # until restarted.
    if s in ("true", "false") or (
      s is not None and not ok("systemctl", "is-active", "--quiet", f"{c}.service")
    ):
      ok("systemctl", "restart", f"{c}.service")
    if c in results:
      continue
    record(c, key, "failed")
    if c in failed:
      results[c] = Result("failed", f"update failed ({s}); rolled back")
    else:
      results[c] = Result("failed", f"rolled back with {', '.join(failed)}")
  why = ", ".join(f"{c}: {s}" for c, s in failed.items())
  notify(
    4,
    f"{', '.join(status)} update failed",
    f"{key} didn't start (auto-update {why}); back on the previous image. "
    "Not retried until upstream changes.",
  )
  return results

# Putting a gated image in place, and rolling back when it doesn't start.

import json

from . import ctx
from .ntfy import notify
from .util import Result, ok, run


def last_digest(container):
  try:
    return (ctx.state / container).read_text().split(" ")[0].strip()
  except FileNotFoundError:
    return ""


def record(container, key, outcome):
  """The digest isn't handled again until upstream moves."""
  (ctx.state / container).write_text(f"{key} {outcome}\n")
  (ctx.state / f"{container}.blocked").unlink(missing_ok=True)


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
  if ctx.mode == "install":
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

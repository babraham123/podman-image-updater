# ntfy notifications.

import time
import urllib.error
import urllib.request

from . import ctx
from .config import secret
from .util import warn

NTFY_RETRY_DELAY_S = 30


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
  if ctx.cfg["ntfy"] is None:
    return
  # A person running install or accept is waiting; only the timer may be up before ntfy is
  attempts = 9 if ctx.mode == "run" else 1
  if not ntfy_post(
    ctx.cfg["ntfy"]["url"],
    secret(ctx.cfg["ntfy"].get("token")),
    priority,
    f"{ctx.host}: {title}",
    message,
    ctx.cfg["ntfy"].get("tags", "package"),
    attempts,
  ):
    warn(f"ntfy post failed: {title}")

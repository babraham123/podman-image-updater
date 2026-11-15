# node_exporter textfile metrics.

import time
from pathlib import Path

from . import ctx
from .scan import blocked_markers, read_marker
from .util import write_atomic


def write_metrics(clean, count):
  """Keeps the previous success timestamp when this run wasn't clean, so an age alert
  counts from the last good run."""
  if not ctx.cfg["metrics_file"]:
    return
  metrics = Path(ctx.cfg["metrics_file"])
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
    "# HELP image_updater_blocked_days Days since the scan gate first blocked the container's "
    "update; cves lists what blocked it last.",
    "# TYPE image_updater_blocked_days gauge",
  ]
  for marker in blocked_markers():
    since, cves = read_marker(marker)
    days = (int(time.time()) - since) // 86400
    cves = cves.replace("\\", "\\\\").replace('"', '\\"')
    lines.append(f'image_updater_blocked_days{{container="{marker.stem}",cves="{cves}"}} {days}')
  metrics.parent.mkdir(parents=True, exist_ok=True)
  # node_exporter only reads *.prom, so it never sees the temp file.
  write_atomic(metrics, "\n".join(lines) + "\n", 0o644)

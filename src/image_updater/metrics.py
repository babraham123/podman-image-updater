# node_exporter textfile metrics.

import time
from pathlib import Path

from . import ctx


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
    "# HELP image_updater_blocked_days Days since the scan gate first blocked the container's update.",
    "# TYPE image_updater_blocked_days gauge",
  ]
  for marker in sorted(ctx.state.glob("*.blocked")):
    days = (int(time.time()) - int(marker.read_text())) // 86400
    lines.append(f'image_updater_blocked_days{{container="{marker.stem}"}} {days}')
  metrics.parent.mkdir(parents=True, exist_ok=True)
  partial = metrics.with_name(f"{metrics.name}.tmp")
  partial.write_text("\n".join(lines) + "\n")
  partial.chmod(0o644)
  # node_exporter only reads *.prom, and the rename is atomic.
  partial.rename(metrics)

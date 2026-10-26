# Arguments, run-wide setup and the lock.
# Usage:
#   image_updater [--config FILE] [--host NAME]        # the nightly timer
#   image_updater --dry-run                            # check and scan; loads and restarts nothing
#   image_updater install SERVICE                      # before copying SERVICE's quadlets
#   sudo image_updater accept CONTAINER                # a person, after reading the findings
# --config defaults to $IMAGE_UPDATER_CONFIG, then /etc/image_updater/config.json; --host
# picks the config's `hosts` entry, default the short hostname.

import argparse
import fcntl
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from . import ctx
from .commands import accept, install_images, update_all
from .config import DEFAULT_CONFIG, load_config
from .util import Fatal, die, log


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
  args = parse_args(argv)
  ctx.host = args.host or socket.gethostname().split(".")[0]
  ctx.self_cmd = [os.path.abspath(sys.argv[0])]
  if args.config != DEFAULT_CONFIG:
    ctx.self_cmd += ["--config", os.path.abspath(args.config)]
  if args.host:
    ctx.self_cmd += ["--host", args.host]
  if os.geteuid() != 0:
    die("must run as root")
  ctx.cfg = load_config(args.config, ctx.host)
  ctx.mode = args.command or ("dry-run" if args.dry_run else "run")
  os.environ["PATH"] = ctx.cfg["path"]
  var = Path(ctx.cfg["state_dir"])
  ctx.state, ctx.staging, ctx.accepted = var / "state", var / "staging", var / "accepted"
  for path in (var, ctx.state, ctx.staging, ctx.accepted):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
  with open(var / "lock", "w") as lock:
    try:
      fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
      die("another image_updater is running")
    ctx.tmp = Path(tempfile.mkdtemp())
    try:
      if ctx.mode == "install":
        install_images(args.name)
      elif ctx.mode == "accept":
        accept(args.name)
      else:
        update_all()
    finally:
      shutil.rmtree(ctx.tmp, ignore_errors=True)
      for path in ctx.staging.iterdir():
        shutil.rmtree(path) if path.is_dir() else path.unlink()


def cli(argv):
  """main's exit status; a nightly run's finish exits itself."""
  try:
    main(argv)
  except (Fatal, subprocess.CalledProcessError) as e:
    log(f"error: {e}", sys.stderr)
    return 1
  return 0


def entry():
  """The zipapp's entry point."""
  sys.exit(cli(sys.argv[1:]))

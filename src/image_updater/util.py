# Outcomes, logging and running commands.

import subprocess
import sys
from datetime import datetime


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


def ok(*cmd, **kwargs):
  return run(*cmd, check=False, stderr=subprocess.DEVNULL, **kwargs).returncode == 0

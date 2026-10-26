# The config file and the secrets it names.

import json
import os
from pathlib import Path

from .util import die, run

DEFAULT_CONFIG = "/etc/image_updater/config.json"
# Top-level config keys, and a host entry's, with their defaults. deadline_s: no image is
# started after this many seconds, so a run stays inside its slot and what's left runs the
# next night; 0 is no deadline. boot_delay_s: a run this soon after boot waits until then.
DEFAULTS = {
  "images": [],
  "ntfy": None,
  "registry_auth": {},
  "deadline_s": 0,
  "boot_delay_s": 0,
  "state_dir": "/var/lib/image_updater",
  "metrics_file": "/var/lib/node_exporter/textfile_collector/image_updater.prom",
  "trivy_cache": "/var/cache/trivy",
  "java_db": True,
  "quadlet_dir": "/etc/containers/systemd",
  "path": "/usr/sbin:/usr/bin:/sbin:/bin",
}


def check_secret(spec, where):
  if spec is None:
    return
  if not (
    isinstance(spec, dict)
    and len(spec) == 1
    and (
      isinstance(spec.get("env"), str)
      or isinstance(spec.get("file"), str)
      or (isinstance(spec.get("command"), list) and spec["command"])
    )
  ):
    die(f'{where}: a secret is {{"env": NAME}}, {{"file": PATH}} or {{"command": [ARGV...]}}')


def check_image(entry, where):
  if not isinstance(entry, dict):
    die(f"{where}: not an object")
  for key in ("container", "image"):
    if not isinstance(entry.get(key), str):
      die(f"{where}: needs {key}")
  if ("upstream" in entry) == ("build" in entry):
    die(f"{where}: needs one of upstream or build")
  if "build" in entry and not isinstance(entry.get("build_script"), str):
    die(f"{where}: a build image needs build_script")
  unknown = set(entry) - {
    "service",
    "container",
    "image",
    "upstream",
    "build",
    "build_script",
    "trivyignore",
  }
  if unknown:
    die(f"{where}: unknown keys {', '.join(sorted(unknown))}")


def load_config(path, host):
  """The host's config: the file's top-level keys, overlaid by its hosts[HOST] entry if it
  has `hosts`, over DEFAULTS."""
  try:
    data = json.loads(Path(path).read_text())
  except OSError as e:
    die(f"can't read {path}: {e.strerror}")
  except ValueError as e:
    die(f"{path}: invalid JSON: {e}")
  if not isinstance(data, dict):
    die(f"{path}: not a JSON object")
  hosts = data.pop("hosts", None)
  if hosts is not None:
    if host not in hosts:
      die(f"{path}: no hosts entry for {host}")
    data.update(hosts[host])
  unknown = set(data) - set(DEFAULTS)
  if unknown:
    die(f"{path}: unknown keys {', '.join(sorted(unknown))}")
  config = {**DEFAULTS, **data}
  containers = set()
  for n, entry in enumerate(config["images"]):
    check_image(entry, f"{path}: images[{n}]")
    entry.setdefault("service", entry["container"])
    if entry["container"] in containers:
      die(f"{path}: images[{n}]: container {entry['container']} is listed twice")
    containers.add(entry["container"])
  if config["ntfy"] is not None:
    if not isinstance(config["ntfy"].get("url"), str):
      die(f"{path}: ntfy needs url")
    check_secret(config["ntfy"].get("token"), f"{path}: ntfy.token")
  for registry, creds in config["registry_auth"].items():
    for key in ("username", "password"):
      check_secret(creds.get(key), f"{path}: registry_auth.{registry}.{key}")
  return config


def secret(spec):
  """A secret's value, "" if unset. A command's trailing newline is dropped, and "null",
  what yq prints for a missing key, counts as unset."""
  if spec is None:
    return ""
  if "env" in spec:
    value = os.environ.get(spec["env"], "")
  elif "file" in spec:
    value = Path(spec["file"]).read_text()
  else:
    value = run(*spec["command"], capture=True).stdout
  value = value.rstrip("\n")
  return "" if value == "null" else value

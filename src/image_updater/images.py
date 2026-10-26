# One image's check: a pulled image from its registry, or one built on the host.

import base64
import json
import os
import shutil
import subprocess

from . import ctx
from .config import secret
from .rollout import keep_rollback, last_digest, roll_out, untagged
from .scan import gate
from .util import Result, die, log, ok, run, warn


def registry_auth():
  """skopeo's --authfile for the registries with credentials, or nothing."""
  auths = {}
  for registry, creds in ctx.cfg["registry_auth"].items():
    user, password = secret(creds.get("username")), secret(creds.get("password"))
    if user and password:
      auths[registry] = {"auth": base64.b64encode(f"{user}:{password}".encode()).decode()}
    else:
      warn(f"no credentials for {registry}; pulling anonymously")
  if not auths:
    return []
  path = ctx.tmp / "auth.json"
  path.touch(mode=0o600)
  path.write_text(json.dumps({"auths": auths}))
  return ["--authfile", path]


def upstream_digest(upstream):
  out = run(
    "skopeo", "inspect", "--no-tags", *ctx.auth, f"docker://{upstream}", capture=True
  ).stdout
  return json.loads(out)["Digest"]


def download(upstream, digest, oci_dir):
  """By digest, so what's scanned is what the inspect saw even if the tag moves meanwhile."""
  shutil.rmtree(oci_dir, ignore_errors=True)
  run(
    "skopeo",
    "copy",
    "--quiet",
    *ctx.auth,
    f"docker://{untagged(upstream)}@{digest}",
    f"oci:{oci_dir}",
  )


def check_upstream(entry):
  """One pulled image."""
  container, image, upstream = entry["container"], entry["image"], entry["upstream"]
  oci_dir = ctx.staging / container
  try:
    # Always remote against remote: a multi-arch tag's digest isn't the local image's.
    digest = upstream_digest(upstream)
  except (subprocess.CalledProcessError, ValueError, KeyError):
    raise Result("error", f"can't inspect {upstream}; trying again tomorrow")
  if last_digest(container) == digest and ok("podman", "image", "exists", image):
    raise Result("unchanged", f"unchanged at {digest}")
  log(f"{container}: {upstream} is at {digest}")
  try:
    download(upstream, digest, oci_dir)
  except subprocess.CalledProcessError:
    raise Result("error", f"can't download {upstream}; trying again tomorrow")
  gate(entry, digest, oci_dir)
  if ctx.mode == "dry-run":
    raise Result("pass", f"would load {digest} as {image}")
  keep_rollback(image)
  run("skopeo", "copy", "--quiet", f"oci:{oci_dir}", f"containers-storage:{image}")
  roll_out(container, image, digest)


def build_versions(entry):
  """The build script's inputs as one key, the one `accept` records for a built image."""
  script = entry["build_script"]
  if not os.access(script, os.X_OK):
    die(f"{entry['container']}: no executable {script}")
  return ",".join(run(script, "versions", capture=True).stdout.split())


def build_candidate(entry, archive):
  """Builds localhost/BUILD:candidate into ARCHIVE and returns its image ID. Scanned from a
  file, so Trivy doesn't need the podman socket. Untagged before the gate, so a blocked
  build is only a dangling image the next prune removes."""
  candidate = f"localhost/{entry['build']}:candidate"
  run(entry["build_script"], "build", "candidate")
  run("podman", "save", "-o", archive, candidate)
  built_id = json.loads(run("podman", "image", "inspect", candidate, capture=True).stdout)[0]["Id"]
  run("podman", "untag", candidate)
  return built_id


def check_build(entry):
  """One image built here, ending like check_upstream. The build script takes `versions`
  (print every input it builds from: commits, base image digests) and `build TAG` (build
  localhost/BUILD:TAG from them)."""
  container, image = entry["container"], entry["image"]
  archive = ctx.staging / f"{container}.tar"
  try:
    versions = build_versions(entry)
  except subprocess.CalledProcessError:
    raise Result("error", f"can't resolve {entry['build']}'s build inputs; trying again tomorrow")
  if last_digest(container) == versions and ok("podman", "image", "exists", image):
    raise Result("unchanged", f"unchanged at {versions}")
  log(f"{container}: building {versions}")
  built_id = build_candidate(entry, archive)
  gate(entry, versions, archive)
  if ctx.mode == "dry-run":
    raise Result("pass", f"would tag {versions} as {image}")
  keep_rollback(image)
  run("podman", "tag", built_id, image)
  roll_out(container, image, versions)


def check(entry):
  return check_upstream if "upstream" in entry else check_build

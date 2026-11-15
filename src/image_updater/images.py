# One image's check: a pulled image from its registry, or one built on the host.

import base64
import json
import os
import shutil
import subprocess

from . import ctx
from .config import secret
from .rollout import handled, keep_rollback, roll_out, untagged
from .scan import gate
from .util import Result, die, log, run, warn


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


def check_upstream(group):
  """One pulled image, for every container in GROUP that runs it."""
  lead = group[0]
  container, image, upstream = lead["container"], lead["image"], lead["upstream"]
  oci_dir = ctx.staging / container
  try:
    # Always remote against remote: a multi-arch tag's digest isn't the local image's.
    digest = upstream_digest(upstream)
  except (subprocess.CalledProcessError, ValueError, KeyError):
    raise Result("error", f"can't inspect {upstream}; trying again tomorrow")
  if handled(group, digest, image):
    raise Result("unchanged", f"unchanged at {digest}")
  log(f"{container}: {upstream} is at {digest}")
  try:
    download(upstream, digest, oci_dir)
  except subprocess.CalledProcessError:
    raise Result("error", f"can't download {upstream}; trying again tomorrow")
  gate(group, digest, oci_dir)
  if ctx.mode == "dry-run":
    raise Result("pass", f"would load {digest} as {image}")
  keep_rollback(image)
  run("skopeo", "copy", "--quiet", f"oci:{oci_dir}", f"containers-storage:{image}")
  return roll_out(group, image, digest)


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
  # Names the tag: a bare `podman untag IMAGE` drops every tag on the image, and a fully
  # cached build is the running image itself, so that would take its tag too.
  run("podman", "untag", candidate, candidate)
  return built_id


def check_build(group):
  """One image built here, ending like check_upstream. The build script takes `versions`
  (print every input it builds from: commits, base image digests) and `build TAG` (build
  localhost/BUILD:TAG from them)."""
  lead = group[0]
  container, image = lead["container"], lead["image"]
  archive = ctx.staging / f"{container}.tar"
  try:
    versions = build_versions(lead)
  except subprocess.CalledProcessError:
    raise Result("error", f"can't resolve {lead['build']}'s build inputs; trying again tomorrow")
  if handled(group, versions, image):
    raise Result("unchanged", f"unchanged at {versions}")
  log(f"{container}: building {versions}")
  built_id = build_candidate(lead, archive)
  gate(group, versions, archive)
  if ctx.mode == "dry-run":
    raise Result("pass", f"would tag {versions} as {image}")
  keep_rollback(image)
  run("podman", "tag", built_id, image)
  return roll_out(group, image, versions)


def check(group):
  """GROUP: the entries sharing one image, which agree on how it's made."""
  return check_upstream(group) if "upstream" in group[0] else check_build(group)

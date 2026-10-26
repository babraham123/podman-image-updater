# image_updater end to end, against the fakes in tests/fakebin (podman, skopeo, trivy,
# systemctl) and a local ntfy stand-in. Expected behavior is the README's: what a run
# loads, records, notifies and reports for each outcome.
# Usage:
#   python3 -m unittest discover -s tests

import base64
import io
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

import build  # noqa: E402
from image_updater import cli, commands, config  # noqa: E402

NGINX = {
  "service": "web",
  "container": "web",
  "image": "localhost/library/nginx:stable",
  "upstream": "docker.io/library/nginx:stable",
}
REPORT = {
  "Results": [
    {
      "Target": "debian 12",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2026-2",
          "Severity": "CRITICAL",
          "PkgName": "libc",
          "InstalledVersion": "2.36",
          "FixedVersion": "2.37",
        },
        {
          "VulnerabilityID": "CVE-2026-1",
          "Severity": "HIGH",
          "PkgName": "openssl",
          "InstalledVersion": "3.0.1",
          "FixedVersion": "3.0.2",
        },
      ],
    }
  ]
}


def key(ref):
  return ref.replace("/", "_").replace(":", "_").replace("@", "_")


class Ntfy(BaseHTTPRequestHandler):
  def do_POST(self):
    body = self.rfile.read(int(self.headers["Content-Length"])).decode()
    self.server.posts.append(
      {
        "priority": int(self.headers["X-Priority"]),
        "title": self.headers["X-Title"],
        "body": body,
        "auth": self.headers.get("Authorization"),
      }
    )
    self.send_response(200)
    self.end_headers()

  def log_message(self, *args):
    pass


class UpdaterTest(unittest.TestCase):
  def setUp(self):
    self.dir = Path(tempfile.mkdtemp())
    self.addCleanup(shutil.rmtree, self.dir)
    self.fake = self.dir / "fake"
    (self.fake / "digest").mkdir(parents=True)
    (self.fake / "images").mkdir()
    self.quadlets = self.dir / "quadlets"
    self.quadlets.mkdir()
    self.var = self.dir / "var"
    self.metrics_file = self.dir / "metrics" / "image_updater.prom"
    self.ntfy = ThreadingHTTPServer(("127.0.0.1", 0), Ntfy)
    self.ntfy.posts = []
    threading.Thread(target=self.ntfy.serve_forever, args=(0.05,), daemon=True).start()
    self.addCleanup(self.ntfy.server_close)
    self.addCleanup(self.ntfy.shutdown)
    self.config_file = self.dir / "config.json"
    self.config = {
      "images": [dict(NGINX)],
      "ntfy": {"url": f"http://127.0.0.1:{self.ntfy.server_port}/alert"},
      "state_dir": str(self.var),
      "metrics_file": str(self.metrics_file),
      "trivy_cache": str(self.dir / "cache"),
      "quadlet_dir": str(self.quadlets),
      "path": f"{ROOT / 'tests' / 'fakebin'}:/usr/bin:/bin",
    }

  # Fixtures

  def quadlet(self, container):
    (self.quadlets / f"{container}.container").touch()

  def upstream(self, ref, digest):
    (self.fake / "digest" / key(ref)).write_text(digest)

  def image(self, name, source="old"):
    (self.fake / "images" / key(name)).write_text(f"{source}\n")

  def fake_file(self, name, content):
    (self.fake / name).write_text(content)

  def build_script(self, versions):
    script = self.dir / "build.sh"
    script.write_text(
      f'#!/bin/sh\necho "build.sh $*" >> "$FAKE/calls"\n'
      f"[ \"$1\" != versions ] || printf '%s\\n' {versions}\n"
    )
    script.chmod(0o755)
    return str(script)

  # Running it

  def run_updater(self, *args, euid=0, env=None):
    """Exit status and output of one run as `--host node1`."""
    self.config_file.write_text(json.dumps(self.config))
    (self.fake / "calls").write_text("")
    out = io.StringIO()
    environ = {"FAKE": str(self.fake), "NO_PROXY": "*", "no_proxy": "*", **(env or {})}
    with (
      mock.patch.dict(os.environ, environ),
      mock.patch("os.geteuid", return_value=euid),
      mock.patch.object(commands, "RETRY_DELAY_S", 0),
      redirect_stdout(out),
      redirect_stderr(out),
    ):
      try:
        code = cli.cli(["--config", str(self.config_file), "--host", "node1", *args])
      except SystemExit as e:
        code = e.code
    self.output = out.getvalue()
    return code

  # Results

  def calls(self, prefix=""):
    return [c for c in (self.fake / "calls").read_text().splitlines() if c.startswith(prefix)]

  def scans(self):
    return [c for c in self.calls("trivy ") if "--input" in c]

  def state(self, name):
    path = self.var / "state" / name
    return path.read_text() if path.exists() else None

  def loaded(self, name):
    path = self.fake / "images" / key(name)
    return path.read_text().strip() if path.exists() else None

  def metrics(self):
    """The textfile's samples, {name{labels}: value}."""
    return dict(
      line.rsplit(" ", 1)
      for line in self.metrics_file.read_text().splitlines()
      if not line.startswith("#")
    )

  def posts(self):
    return [(p["priority"], p["title"]) for p in self.ntfy.posts]


class NightlyRun(UpdaterTest):
  def test_new_digest_is_downloaded_by_digest_scanned_loaded_and_rolled_out(self):
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.image(NGINX["image"])
    self.fake_file("auto_update.json", '[{"Unit": "web.service", "Updated": true}]')
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertIn(
      f"skopeo copy --quiet docker://docker.io/library/nginx@sha256:new oci:{self.var}/staging/web",
      self.calls(),
    )
    self.assertEqual(len(self.scans()), 1)
    self.assertEqual(self.loaded("localhost/library/nginx:rollback"), "old")
    self.assertEqual(self.loaded(NGINX["image"]), f"oci:{self.var}/staging/web")
    self.assertEqual(self.state("web"), "sha256:new updated\n")
    metrics = self.metrics()
    self.assertEqual(metrics['image_updater_images{result="checked"}'], "1")
    self.assertEqual(metrics['image_updater_images{result="updated"}'], "1")
    self.assertAlmostEqual(
      int(metrics["image_updater_last_success_timestamp_seconds"]), time.time(), delta=60
    )
    self.assertEqual(self.posts(), [])
    self.assertEqual(list((self.var / "staging").iterdir()), [])

  def test_digest_handled_last_is_left_alone_while_its_image_exists(self):
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:same")
    (self.var / "state").mkdir(parents=True)
    (self.var / "state" / "web").write_text("sha256:same updated\n")
    self.image(NGINX["image"])
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertEqual(self.calls("skopeo copy"), [])
    self.assertEqual(self.scans(), [])
    self.assertIn("web: unchanged at sha256:same", self.output)
    # Without the image, the same digest is loaded again
    (self.fake / "images" / key(NGINX["image"])).unlink()
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertEqual(self.loaded(NGINX["image"]), f"oci:{self.var}/staging/web")
    self.assertEqual(self.state("web"), "sha256:same loaded\n")

  def test_image_without_an_installed_quadlet_is_skipped(self):
    self.upstream(NGINX["upstream"], "sha256:new")
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertEqual(self.calls("skopeo"), [])
    self.assertEqual(self.metrics()['image_updater_images{result="checked"}'], "0")

  def test_fixable_findings_block_the_image_and_notify(self):
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.image(NGINX["image"])
    self.fake_file("rc", "3")
    self.fake_file("report.json", json.dumps(REPORT))
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertEqual(self.loaded(NGINX["image"]), "old")
    self.assertIsNone(self.state("web"))
    self.assertTrue((self.var / "state" / "web.blocked").exists())
    self.assertIn("HIGH CVE-2026-1 openssl 3.0.1 -> 3.0.2 (debian 12)", self.output)
    self.assertEqual(self.posts(), [(3, "node1: web update blocked")])
    self.assertIn("CVE-2026-1, CVE-2026-2", self.ntfy.posts[0]["body"])
    self.assertIn("The old image keeps running", self.ntfy.posts[0]["body"])
    metrics = self.metrics()
    self.assertEqual(metrics['image_updater_images{result="blocked"}'], "1")
    self.assertEqual(metrics['image_updater_blocked_days{container="web"}'], "0")
    self.assertIn("image_updater_last_success_timestamp_seconds", metrics)

  def test_block_older_than_a_week_escalates_with_the_override_commands(self):
    self.config["images"][0]["trivyignore"] = "/srv/web/.trivyignore"
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.fake_file("rc", "3")
    self.fake_file("report.json", json.dumps(REPORT))
    (self.var / "state").mkdir(parents=True)
    (self.var / "state" / "web.blocked").write_text(f"{int(time.time()) - 8 * 86400}\n")
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertEqual(self.posts(), [(5, "node1: web blocked for 8 days")])
    body = self.ntfy.posts[0]["body"]
    self.assertIn("add them to /srv/web/.trivyignore with an exp: date", body)
    self.assertIn("on node1 run: sudo ", body)
    self.assertTrue(body.endswith(f" --config {self.config_file} --host node1 accept web"), body)
    self.assertEqual(self.metrics()['image_updater_blocked_days{container="web"}'], "8")

  def test_failed_update_goes_back_to_the_rollback_image(self):
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.image(NGINX["image"])
    self.fake_file("auto_update.json", '[{"Unit": "web.service", "Updated": "failed"}]')
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertEqual(self.loaded(NGINX["image"]), "old")
    self.assertEqual(self.state("web"), "sha256:new failed\n")
    self.assertEqual(self.posts(), [(4, "node1: web update failed")])
    self.assertEqual(self.metrics()['image_updater_images{result="failed"}'], "1")

  def test_registry_error_is_retried_then_reported_broken(self):
    self.quadlet("web")
    self.metrics_file.parent.mkdir()
    self.metrics_file.write_text("image_updater_last_success_timestamp_seconds 123\n")
    self.assertEqual(self.run_updater(), 1, self.output)
    self.assertEqual(len(self.calls("skopeo inspect")), 3)
    self.assertEqual(self.posts(), [(5, "node1: Image updater broken")])
    self.assertIn("Failed on: web.", self.ntfy.posts[0]["body"])
    metrics = self.metrics()
    self.assertEqual(metrics["image_updater_last_success_timestamp_seconds"], "123")
    self.assertEqual(metrics['image_updater_images{result="error"}'], "1")

  def test_trivy_db_refresh_failure_checks_nothing(self):
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.fake_file("db_rc", "1")
    self.assertEqual(self.run_updater(), 1, self.output)
    self.assertEqual(self.calls("skopeo"), [])
    self.assertEqual(self.posts(), [(5, "node1: Image updater broken")])
    self.assertNotIn("image_updater_last_success_timestamp_seconds", self.metrics())

  def test_db_downloads_stage_beside_the_cache(self):
    self.assertEqual(self.run_updater("--dry-run"), 0, self.output)
    self.assertEqual(
      [c for c in self.calls("trivy") if "--download" in c],
      [
        f"trivy image --quiet --cache-dir {self.dir / 'cache'} --download-db-only",
        f"trivy image --quiet --cache-dir {self.dir / 'cache'} --download-java-db-only",
      ],
    )
    self.assertEqual((self.fake / "download_tmpdir").read_text().strip(), str(self.dir / "cache"))

  def test_java_db_off_downloads_only_the_vulnerability_db(self):
    self.config["java_db"] = False
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.assertEqual(self.run_updater("--dry-run"), 0, self.output)
    self.assertEqual(
      [c for c in self.calls("trivy") if "--download" in c],
      [f"trivy image --quiet --cache-dir {self.dir / 'cache'} --download-db-only"],
    )
    self.assertEqual(len(self.scans()), 1)

  def test_trivyignore_is_passed_once_it_exists(self):
    ignore = self.dir / ".trivyignore"
    self.config["images"][0]["trivyignore"] = str(ignore)
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.assertEqual(self.run_updater("--dry-run"), 0, self.output)
    self.assertNotIn("--ignorefile", self.scans()[0])
    ignore.write_text("# Not reachable\nCVE-2026-1 exp:2099-01-01\n")
    self.assertEqual(self.run_updater("--dry-run"), 0, self.output)
    self.assertIn(f"--ignorefile {ignore} ", self.scans()[0])

  def test_deadline_defers_the_rest_to_the_next_night(self):
    self.config["deadline_s"] = 1500
    self.config["images"].append(
      {
        "container": "db",
        "image": "localhost/library/postgres:18",
        "upstream": "docker.io/library/postgres:18",
      }
    )
    for container in ("web", "db"):
      self.quadlet(container)
    self.upstream(NGINX["upstream"], "sha256:new")
    self.upstream("docker.io/library/postgres:18", "sha256:new")
    clock = itertools.count(0, 1000)
    fake_time = types.SimpleNamespace(
      monotonic=lambda: next(clock), time=time.time, sleep=time.sleep
    )
    with mock.patch.object(commands, "time", fake_time):
      self.assertEqual(self.run_updater(), 0, self.output)
    self.assertEqual(self.state("web"), "sha256:new loaded\n")
    self.assertIsNone(self.state("db"))
    self.assertIn("db: past the deadline, left for tomorrow", self.output)
    self.assertEqual(self.metrics()['image_updater_images{result="deferred"}'], "1")

  def test_dry_run_scans_but_loads_records_and_restarts_nothing(self):
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.image(NGINX["image"])
    self.assertEqual(self.run_updater("--dry-run"), 0, self.output)
    self.assertEqual(len(self.scans()), 1)
    self.assertIn("would load sha256:new as localhost/library/nginx:stable", self.output)
    self.assertEqual(self.loaded(NGINX["image"]), "old")
    self.assertEqual(self.calls("podman auto-update") + self.calls("systemctl"), [])
    self.assertIsNone(self.state("web"))
    self.assertFalse(self.metrics_file.exists())


class BuiltImage(UpdaterTest):
  def setUp(self):
    super().setUp()
    self.config["images"] = [
      {
        "container": "app",
        "image": "localhost/app:latest",
        "build": "app",
        "build_script": self.build_script("app@abc base@sha256:1"),
      }
    ]
    self.quadlet("app")

  def test_new_build_inputs_build_scan_and_load_the_candidate(self):
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertIn("build.sh build candidate", self.calls())
    self.assertIn(
      f"podman save -o {self.var}/staging/app.tar localhost/app:candidate", self.calls()
    )
    self.assertIn("podman untag localhost/app:candidate", self.calls())
    self.assertTrue(self.scans()[0].endswith(f"--input {self.var}/staging/app.tar"))
    self.assertIn("podman tag built123 localhost/app:latest", self.calls())
    self.assertEqual(self.state("app"), "app@abc,base@sha256:1 loaded\n")
    # The same inputs don't build again
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertNotIn("build.sh build candidate", self.calls())


class Install(UpdaterTest):
  def setUp(self):
    super().setUp()
    self.config["images"].append(
      {
        "service": "db",
        "container": "db",
        "image": "localhost/library/postgres:18",
        "upstream": "docker.io/library/postgres:18",
      }
    )
    self.upstream(NGINX["upstream"], "sha256:new")
    self.upstream("docker.io/library/postgres:18", "sha256:new")

  def test_install_loads_only_the_services_images_before_its_quadlets_exist(self):
    self.assertEqual(self.run_updater("install", "web"), 0, self.output)
    self.assertEqual(self.state("web"), "sha256:new loaded\n")
    self.assertIsNone(self.state("db"))
    self.assertEqual(self.calls("podman auto-update"), [])

  def test_blocked_image_stops_the_install_with_the_accept_command(self):
    self.fake_file("rc", "3")
    self.fake_file("report.json", json.dumps(REPORT))
    self.assertEqual(self.run_updater("install", "web"), 1, self.output)
    self.assertIsNone(self.loaded(NGINX["image"]))
    self.assertIn("web: blocked by the scan gate", self.output)
    self.assertIn(
      f"--config {self.config_file} --host node1 accept web, then install again", self.output
    )
    self.assertEqual(self.posts(), [])


class Accept(UpdaterTest):
  def test_accepted_digest_skips_the_gate_on_the_next_run(self):
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.fake_file("rc", "3")
    self.fake_file("report.json", json.dumps(REPORT))
    self.assertEqual(self.run_updater("accept", "web"), 0, self.output)
    self.assertIn("CRITICAL CVE-2026-2 libc 2.36 -> 2.37 (debian 12)", self.output)
    self.assertEqual((self.var / "accepted" / "web").read_text(), "sha256:new\n")
    self.assertEqual(self.posts(), [(3, "node1: web accepted")])
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertEqual(self.scans(), [])
    self.assertEqual(self.state("web"), "sha256:new loaded\n")
    # A new digest is gated again
    self.upstream(NGINX["upstream"], "sha256:newer")
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertEqual(len(self.scans()), 1)
    self.assertEqual(self.state("web"), "sha256:new loaded\n")

  def test_unknown_container(self):
    self.assertEqual(self.run_updater("accept", "nope"), 1)
    self.assertIn("no image for container nope on node1", self.output)


class Config(UpdaterTest):
  def test_hosts_entry_overlays_the_top_level(self):
    images = self.config.pop("images")
    self.config["hosts"] = {"node1": {"images": images}, "node2": {"images": []}}
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.assertEqual(self.run_updater(), 0, self.output)
    self.assertEqual(self.state("web"), "sha256:new loaded\n")

  def test_example_config_loads(self):
    loaded = config.load_config(ROOT / "config.example.json", "any")
    self.assertEqual([i["container"] for i in loaded["images"]], ["nginx", "app", "ntfy"])
    self.assertEqual(loaded["images"][2]["service"], "notify")

  def test_zipapp_runs_as_one_file(self):
    app = build.build(self.dir / "image_updater")
    self.assertTrue(os.access(app, os.X_OK))
    out = subprocess.run([app, "--help"], capture_output=True, text=True, cwd=self.dir)
    self.assertEqual(out.returncode, 0, out.stderr)
    self.assertIn("usage: image_updater", out.stdout)

  def test_host_without_an_entry(self):
    self.config["hosts"] = {"node2": {}}
    self.assertEqual(self.run_updater(), 1)
    self.assertIn(f"{self.config_file}: no hosts entry for node1", self.output)

  def test_invalid_image_entry(self):
    self.config["images"][0]["build"] = "web"
    self.assertEqual(self.run_updater(), 1)
    self.assertIn("images[0]: needs one of upstream or build", self.output)

  def test_unknown_key(self):
    self.config["ntfy_url"] = "http://x"
    self.assertEqual(self.run_updater(), 1)
    self.assertIn("unknown keys ntfy_url", self.output)

  def test_needs_root(self):
    self.assertEqual(self.run_updater(euid=1000), 1)
    self.assertIn("must run as root", self.output)

  def test_registry_credentials_from_secrets(self):
    self.quadlet("web")
    self.upstream(NGINX["upstream"], "sha256:new")
    self.config["registry_auth"] = {
      "docker.io": {"username": {"env": "REG_USER"}, "password": {"command": ["/bin/echo", "tok"]}}
    }
    self.assertEqual(self.run_updater(env={"REG_USER": "me"}), 0, self.output)
    auth = json.loads((self.fake / "authfile").read_text())
    self.assertEqual(auth, {"auths": {"docker.io": {"auth": base64.b64encode(b"me:tok").decode()}}})
    # yq's "null" for a missing secret is unset
    self.config["registry_auth"]["docker.io"]["password"] = {"command": ["/bin/echo", "null"]}
    self.assertEqual(self.run_updater("--dry-run", env={"REG_USER": "me"}), 0, self.output)
    self.assertIn("no credentials for docker.io; pulling anonymously", self.output)
    self.assertFalse(any("--authfile" in c for c in self.calls("skopeo")))

  def test_ntfy_token_from_a_file(self):
    token = self.dir / "token"
    token.write_text("secret-token\n")
    self.config["ntfy"]["token"] = {"file": str(token)}
    self.fake_file("db_rc", "1")
    self.assertEqual(self.run_updater(), 1, self.output)
    self.assertEqual(self.ntfy.posts[0]["auth"], "Bearer secret-token")


if __name__ == "__main__":
  unittest.main()

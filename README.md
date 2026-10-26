# podman-image-updater

Nightly Podman image updates that only reach a container after a Trivy scan passes.

For each image, in config order, `image_updater` compares the upstream digest with the last one it
handled, downloads a changed one by digest and scans it with Trivy. If the scan passes, it tags the
current image `:rollback`, loads the new one as `localhost/NAME` and runs `podman auto-update`; a
failed update rolls back to `:rollback`. Images built on the host go through the same gate.

`image_updater.py` is one file using only the Python 3 standard library, so it runs on a bare host.

## Why

Standard `AutoUpdate=registry` pulls and runs unscanned images immediately. This tool ensures:

- Quadlets only use local images (`localhost/`, `AutoUpdate=local`), preventing unscanned starts.
- Updates block on fixable HIGH or CRITICAL findings. Old images keep running.
- A person can override with a `trivyignore` entry (expiry and reason) or by running `accept` as
  root for one exact digest or set of build inputs.
- `image_updater install SERVICE` gates new services before copying quadlets.
- ntfy notifications and textfile metrics are provided.

Trade-offs:

- Each host downloads/scans its own images (requires registry credentials to avoid rate limits).
- `deadline_s` stops starting images after a duration; remaining images wait for the next night.
- Unfixable CVEs do not block updates.
- No health checks: misbehaving images that start successfully must be rolled back manually.

## Install

Requires Podman with quadlets, `skopeo`, `trivy` ([Aqua's apt
repo](https://trivy.dev/latest/getting-started/installation/)), systemd, and Python 3.9+.

```bash
sudo install -D image_updater.py /usr/local/bin/image_updater
sudo install -D -m 600 config.example.json /etc/image_updater/config.json   # then edit it
sudo install -D -m 644 -t /etc/systemd/system systemd/image_updater.service systemd/image_updater.timer
sudo systemctl daemon-reload
# Load every image once before switching over: each must pass the gate
sudo image_updater install SERVICE   # per service
sudo systemctl disable --now podman-auto-update.timer
sudo systemctl enable --now image_updater.timer
```

To pin a version, fetch the file at a commit and check its hash:

```bash
commit=COMMIT
sha=SHA256
url="https://raw.githubusercontent.com/babraham123/podman-image-updater/${commit}/image_updater.py"
wget -O image_updater.py "$url"
echo "${sha}  image_updater.py" | sha256sum --check
```

Each quadlet must use the `localhost/` name and enable local updates:

```ini
[Container]
Image=localhost/library/nginx:stable
AutoUpdate=local
```

## Usage

```bash
image_updater                      # the nightly run (image_updater.timer)
image_updater --dry-run            # check and scan every image; loads and restarts nothing
image_updater install SERVICE      # load and gate SERVICE's images, before copying its quadlets
image_updater accept CONTAINER     # pass CONTAINER's current upstream digest or build inputs
```

All modes run as root. Options `--config FILE` (default `$IMAGE_UPDATER_CONFIG` or
`/etc/image_updater/config.json`) and `--host NAME` (default short hostname) apply to all commands.

The nightly run exits 1 if an image breaks, fails after two retries a minute apart, or if the
Trivy DB refresh fails. Blocked or rolled-back images count as a clean run.

`accept` rescans, prints findings, records the digest, and notifies; the next run loads it. For a
built image it builds, scans and records the build inputs, so the next build of the same inputs
passes. Keep it off any remote dispatcher: only a person who has read the findings should run it.

## Config

JSON. Every key is optional except `images`:

| Key | Default | Meaning |
| --- | --- | --- |
| `images` | `[]` | Images in update order, below |
| `ntfy` | none | `{"url", "token", "tags"}`: the ntfy topic URL, a token secret, tags (default `package`). No notifications without it |
| `registry_auth` | `{}` | `{REGISTRY: {"username", "password"}}`, both secrets; a registry missing either pulls anonymously |
| `deadline_s` | `0` | Start no image after this many seconds; 0 is no deadline |
| `boot_delay_s` | `0` | A run this soon after boot waits until then, e.g. for ntfy to come up |
| `state_dir` | `/var/lib/image_updater` | State, staging downloads, accepted keys, the lock |
| `metrics_file` | `/var/lib/node_exporter/`<br>`textfile_collector/`<br>`image_updater.prom` | Textfile metrics; `null` for none |
| `trivy_cache` | `/var/cache/trivy` | Trivy's DB cache |
| `quadlet_dir` | `/etc/containers/systemd` | Where `<container>.container` must exist for a nightly run to update it |
| `path` | `/usr/sbin:/usr/bin:/sbin:/bin` | `PATH` for every command it runs |
| `hosts` | none | `{HOST: {key: value}}`: one file for several hosts; the entry for `--host` overlays the top-level keys |

Each image:

| Key | Meaning |
| --- | --- |
| `container` | Quadlet and unit name: `<quadlet_dir>/<container>.container`, `<container>.service` |
| `image` | The `localhost/` name its quadlet's `Image=` uses |
| `upstream` | Pulled: full ref with registry host (`docker.io/library/nginx:stable`) |
| `build`, `build_script` | Built on the host instead: the image name and the script that builds it |
| `service` | The group `install SERVICE` loads together; default the container |
| `trivyignore` | Trivy ignore file, used once it exists |

A secret is `{"env": NAME}`, `{"file": PATH}` or `{"command": [ARGV...]}`. Trailing newlines are
dropped, and `null` (what `yq` prints for a missing key) counts as unset.
[config.example.json](config.example.json) has one of each kind of image.

If one host's updates can interrupt notifications, put the notification path (ntfy, its proxy) last,
and give the host running it the last slot and no deadline. Nightly runs skip images whose quadlet
isn't installed, so one file can list images a host doesn't run yet.

### Built images

A build script takes two commands:

- `versions`: print every input, one per line: source commits, base image digests
  (`skopeo inspect --no-tags docker://REF | jq -r .Digest`), local file hashes. Any change triggers
  a rebuild through the gate.
- `build TAG`: build `localhost/<build>:TAG` from those inputs, with `podman build --pull=always` so
  base images match what `versions` reported.

Candidates build as `:candidate`, save via `podman save`, and scan from the archive (no Podman
socket needed for Trivy), then untag. Blocked builds become dangling images removed by next prune.

### Overrides

A trivyignore entry covers every digest until it expires:

```text
# Not reachable: the vulnerable parser only reads files from the image itself
CVE-2026-12345 exp:2026-12-31
```

## Notifications and metrics

| ntfy notification | Priority |
| --- | --- |
| Update blocked by the scan, daily | 3; 5 after 7 days, with the override commands |
| Update failed, rolled back to the previous image | 4 |
| Updater broken: an image still failing after two retries, or the Trivy DB refresh failed | 5 |
| `accept` passed an image | 3 |

Titles start with the host name. Nightly runs retry notifications for 4 minutes; `install` and
`accept` try once.

Metrics are written atomically after every nightly run:

- `image_updater_last_success_timestamp_seconds`: last run with nothing broken; kept from the
  previous clean run otherwise.
- `image_updater_images{result}`: checked, updated, blocked, failed, error, broken, deferred.
- `image_updater_blocked_days{container}`: days since the gate first blocked it.

Alert on age rather than `absent()` to keep powered-off hosts quiet:

```yaml
- alert: ImageUpdaterStale
  expr: time() - image_updater_last_success_timestamp_seconds > 36 * 3600
```

## State

Under `state_dir`:

- `state/<container>`: `<digest or build inputs> <outcome>` of the last handled image. It isn't
  handled again until upstream moves, so a failed update isn't retried every night.
- `state/<container>.blocked`: when the gate first blocked it
- `accepted/<container>`: what `accept` passed, one per line
- `staging/`: downloads and build archives, emptied after every run

Roll back manually:

```bash
podman tag localhost/NAME:rollback localhost/NAME:TAG
systemctl restart CONTAINER
```

## Tests

```bash
python3 -m unittest discover -s tests
```

Runs end-to-end against fake `podman`, `skopeo`, `trivy` and `systemctl` (`tests/fakebin`) and a
local ntfy stand-in.

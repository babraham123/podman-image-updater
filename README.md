# podman-image-updater

Nightly Podman image updates that only reach a container after a Trivy scan passes. For each
image, in the config's order, `image_updater` compares the upstream digest with the one it handled
last, downloads a changed one by digest, scans it, tags the current image `:rollback`, loads the
new one under its `localhost/` name and runs `podman auto-update`. A container whose update fails
is pointed back at `:rollback`. Images built on the host go through the same gate.

`image_updater.py` is one file, Python 3 standard library only, so it runs on a bare host.

## Why

With `AutoUpdate=registry`, whatever upstream pushes to a tag is pulled and restarted the same
night, unscanned. A compromised or broken upstream image reaches the containers with nothing in
between, and a failed update is only noticed when a service breaks. Here:

- Quadlets name `localhost/` images only, with `AutoUpdate=local`: nothing in a quadlet can pull,
  so an unscanned image can't reach a container.
- The scan gate blocks on fixable HIGH or CRITICAL findings only (`--ignore-unfixed`); the old
  image keeps running. Two overrides, both needing a person: a trivyignore entry with an `exp:`
  date and a reason, or `accept` run as root on the host, which passes one exact digest, or one
  exact set of build inputs for a built image.
- Installing a service goes through the same gate: run `image_updater install SERVICE` before
  copying its quadlets, and a block stops the install.
- The updater reports itself: ntfy notifications by outcome, and node_exporter textfile metrics
  for an age alert.

Considered and rejected:

- **A central scanning registry** (e.g. zot): one scan per image instead of one per host, but a
  registry, its auth, certs and firewall rules to run, and that host on every update's path.
- **`Pull=newer` in quadlets**: still pulls unscanned images, on every restart instead of nightly.
- **Pinned digests in git**, updated by hand or a bot: every update becomes a commit and a
  deploy, which in practice means updates stop.
- **An `OnFailure=` hook on `podman-auto-update.service`**: it reports failures but scans nothing.

Consequences:

- Each host downloads and scans its own images: a Trivy DB refresh and a few downloads a night,
  and registry credentials on each, since Docker Hub's anonymous pull limit is per IP and shared by
  every host behind one router.
- A run must fit its slot: `deadline_s` stops starting images after that long and leaves the rest
  for the next night.
- A CVE with no fix doesn't block, so a known-vulnerable image still runs until a fix ships.
- No health checks gate the rollout: an image that starts but misbehaves stays until monitoring
  catches it, then is rolled back by hand from `:rollback`.

## Install

Needs Podman with quadlets, `skopeo`, `trivy` ([Aqua's apt
repo](https://trivy.dev/latest/getting-started/installation/)), systemd and Python 3.9+.

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

Each quadlet names its image's `localhost/` name and lets `podman auto-update` restart it on a new
local image:

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

Every mode runs as root. `--config FILE` (default `$IMAGE_UPDATER_CONFIG`, then
`/etc/image_updater/config.json`) and `--host NAME` (default the short hostname) apply to all of
them. The nightly run exits 1 when an image broke or still failed after two retries a minute apart,
or the Trivy DB refresh failed; a blocked or rolled-back image is a clean run.

`accept` rescans, prints the findings, records the digest and notifies; the next run loads it. For
a built image it builds and scans, and records the build inputs, so the next run's build of the
same inputs passes. Keep it off any remote dispatcher: only a person who has read the findings
should run it.

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
| `metrics_file` | `/var/lib/node_exporter/textfile_collector/image_updater.prom` | Textfile metrics; `null` for none |
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

Update order matters when one host's updates can interrupt notifications: put the notification
path (ntfy, its proxy) last, and give the host running it the last slot and no deadline. A
nightly run skips images whose quadlet isn't installed, so one file can list images a host doesn't
run yet.

### Built images

A build script takes two commands:

- `versions`: print every input the image builds from, one per line: source commits, base image
  digests (`skopeo inspect --no-tags docker://REF | jq -r .Digest`), hashes of local files. Any of
  them moving rebuilds the image through the gate.
- `build TAG`: build `localhost/<build>:TAG` from those inputs, pulling base images
  (`podman build --pull=always`) so they are the ones `versions` reported.

The candidate is built as `:candidate`, saved with `podman save` and scanned from the archive, so
Trivy doesn't need the Podman socket, then untagged: a blocked build is only a dangling image the
next prune removes.

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

Titles start with the host name. A nightly run retries a notification for 4 minutes, in case ntfy
is still starting; `install` and `accept` try once.

Metrics, written atomically after every nightly run:

- `image_updater_last_success_timestamp_seconds`: the last run with nothing broken; kept from the
  previous clean run otherwise
- `image_updater_images{result}`: checked, updated, blocked, failed, error, broken, deferred
- `image_updater_blocked_days{container}`: days since the gate first blocked it

Alert on age rather than `absent()`, so a powered-off host stays quiet:

```yaml
- alert: ImageUpdaterStale
  expr: time() - image_updater_last_success_timestamp_seconds > 36 * 3600
```

## State

Under `state_dir`:

- `state/<container>`: `<digest or build inputs> <outcome>` of the one handled last. That digest
  isn't handled again until upstream moves, so a failed update isn't retried every night.
- `state/<container>.blocked`: when the gate first blocked it
- `accepted/<container>`: what `accept` passed, one per line
- `staging/`: downloads and build archives, emptied after every run

Roll back by hand with `podman tag localhost/NAME:rollback localhost/NAME:TAG`, then `systemctl
restart CONTAINER`.

## Tests

```bash
python3 -m unittest discover -s tests
```

End to end against fake `podman`, `skopeo`, `trivy` and `systemctl` (`tests/fakebin`) and a local
ntfy stand-in.

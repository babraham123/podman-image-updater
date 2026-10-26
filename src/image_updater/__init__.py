# Keeps a host's Podman container images current behind a vulnerability scan. For each
# image in the config's update order whose quadlet is installed: compare the upstream
# digest with the one handled last, download a changed one, scan it with Trivy (fixable
# HIGH or CRITICAL blocks it), load it under its localhost/ name and let `podman
# auto-update` restart the containers on it. Quadlets only name localhost/ images with
# AutoUpdate=local, so nothing unscanned reaches a container. Images built on the host
# pass through the same gate. Design and config format: README.md. Standard library only,
# shipped as one zipapp built by build.py.
# Overrides for a blocked image, both needing a person: the image's trivyignore file
# (`CVE-… exp:YYYY-MM-DD`, with a `#` line giving the reason) covers every digest until it
# expires; `accept` rescans, prints the findings and passes that exact digest, or for a
# built image that exact set of build script inputs.

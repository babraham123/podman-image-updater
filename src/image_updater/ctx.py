# Run-wide state, set by cli.main before any command runs. mode: run, dry-run, install or
# accept. self_cmd: this command with its --config and --host, for the `accept` a
# notification suggests. tmp: scan reports and the authfile. auth: skopeo's --authfile
# arguments. Under state_dir: state/<container> is "<remote digest or build inputs>
# <outcome>" of the one handled last, state/<container>.blocked when the scan gate first
# blocked it; accepted/<container> is what `accept` passed, one per line; staging/ holds
# downloads and build archives.

cfg, mode, host, self_cmd = None, None, None, []
tmp, auth = None, []
state = staging = accepted = None

# Linux package assets

Install with:

```sh
make package VERSION=<release>
tar -xzf build/hub-net-<release>-linux-amd64.tar.gz
sudo hub-net-<release>-linux-amd64/packaging/linux/install
sudo systemctl enable --now hub-net
```

Launcher may use package-local `install`, `check-for-updates`, `update`, and
`uninstall` commands. `check-for-updates` exits successfully only when its
expected version differs from the installed binary. `update` preserves service
state: it restarts a running unit but does not start an inactive unit.

Uninstall removes binary and systemd package files, but deliberately preserves
the `hub-net` user and `/var/lib/hub-net`. Reinstall therefore keeps agent
identity and WireGuard key ownership.

Service runs as dedicated `hub-net` user with only `CAP_NET_ADMIN` and
`CAP_NET_RAW`. State is stored in `/var/lib/hub-net`; local service IPC uses
`/run/hub-net/agent.sock`. Add trusted local service users to `hub-net` group
when they need IPC access.

Agent fails before identity creation and Hub registration when capabilities
are absent or current platform lacks production tunnel support.

## Ubuntu acceptance

Sync from the Mac source workspace and run all ordinary checks:

```sh
rsync -a --delete --exclude '.git/' /Users/v57/Documents/Hub/ ubuntu:~/Hub/
ssh ubuntu 'bash -lc "cd ~/Hub/hub-net/agent && go test -race ./... && go vet ./... && make build"'
```

The `v57u` Tailscale address is inside Hub's reserved IPv4 overlay, so the
agent correctly reports a route conflict from Tailscale's policy-routing table
on the host. Verify fail-closed detection without creating an interface:

```sh
ssh ubuntu 'bash -lc "
  cd ~/Hub/hub-net/agent
  sudo HUB_NET_WG_CONFLICT_DEVICE=hubwgconflict \
    /home/v57/.local/bin/go test ./wireguard \
    -run TestLinuxAdapterRejectsLiveRouteConflict -count=1 -v
"'
```

Exercise the real kernel WireGuard lifecycle in an isolated network namespace:

```sh
ssh ubuntu 'bash -lc "
  sudo ip netns add hub-net-test
  trap \"sudo ip netns del hub-net-test\" EXIT
  cd ~/Hub/hub-net/agent
  sudo ip netns exec hub-net-test env PATH=\"\$PATH\" \
    HUB_NET_WG_DEVICE=hubwgtest \
    go test -race ./wireguard -run TestLinuxAdapterLifecycle -count=1 -v
"'
```

Run live systemd-resolved and nftables lifecycle checks on the host:

```sh
ssh ubuntu 'bash -lc "
  cd ~/Hub/hub-net/agent
  sudo env PATH=\"\$PATH\" HUB_NET_PRIVILEGED=1 \
    go test -race ./dnsresolver ./enforcement \
    -run PrivilegedLifecycle -count=1 -v
"'
```

Run opt-in, two-phase machine-restart persistence acceptance on a disposable
Linux test host with an installed agent and existing identity:

```sh
sudo HUB_NET_MACHINE_RESTART_ACCEPTANCE=1 \
  integration/machine_restart.sh prepare
sudo reboot
# After reconnecting:
sudo HUB_NET_MACHINE_RESTART_ACCEPTANCE=1 \
  integration/machine_restart.sh verify
```

The prepare phase records root-only hashes and prior service state, then enables
the unit. The verify phase requires a changed kernel boot ID, verifies the
installed version plus persistent profile identity and WireGuard key, and
restores the prior enabled/active state.

Both privileged suites create uniquely named temporary state and remove it
during test cleanup.

Run release-package acceptance after conformance:

```sh
ssh ubuntu 'bash -lc "
  cd ~/Hub/hub-net/agent
  sudo env PATH=\"\$PATH\" make integration-linux-package
"'
```

This builds old/new Linux amd64 archives, validates portable SHA-256 manifests,
static stripped architecture and size, package file modes, required runtime
commands, systemd hardening, inactive-service upgrade behavior, and uninstall
without identity or WireGuard-key loss. It restores the previously installed
version and service state on exit. Release signing/provenance is not currently
configured; SHA-256 manifests are the available integrity metadata.

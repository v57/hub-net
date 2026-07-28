# hub-net

Local Hub Network agent. Owns WireGuard, scoped routes, split DNS, and the
local IPC server that issues share attestations. Implemented in Go on top of
`hub-service-go`.

## Status

Scaffold (HN-300). Subsequent tasks wire real platform adapters, profile
registration, IPC attestation, route/DNS lifecycle, grant enforcement, control
APIs, and end-to-end tests.

| Task | Area |
| --- | --- |
| HN-300 | Module scaffold, config, key storage, structured logging |
| HN-301 | Profile registration, identity, WireGuard key lifecycle, reconnect |
| HN-302 | Local IPC server: nonce, service-proof, local-target check, attestation |
| HN-303 | Portable WireGuard adapter with deterministic config tests |
| HN-304 | Overlay address assignment, scoped routes, rollback |
| HN-305 | Reserved-suffix DNS resolver, canonical lookup, teardown |
| HN-306 | Complete: trusted-Hub grant verification, replay/generation checks, on-demand outbound peer configuration |
| HN-307 | Complete: exact signed TCP/UDP tuple rules, transactional generation/expiry revocation, runtime expiry loop, Linux nftables enforcement, conntrack flow termination, fail-closed unsupported platforms |
| HN-308 | Provider connection orchestration, candidate checks, idle cleanup |
| HN-309 | Permission-controlled Hub APIs and streams |
| HN-310 | Complete: two-agent local end-to-end test harness (`agent/e2e`) — real Unix-socket IPC attestation, Hub-signed grant verification, WireGuard peer install, exact-tuple firewall enforcement, authorized TCP/UDP shares, blocked-port rejection across layers |
| HN-311 | Complete: production adapter selection, pre-registration privilege checks, registration-bound interface lifecycle, deferred link-scoped systemd-resolved split DNS, command and hardened systemd package assets; privileged WireGuard/routes, nftables, DNS, restart, identity persistence, and cleanup verified on Ubuntu amd64 |

See `../PLATFORMS.md` for the platform matrix and
`../../openspec/changes/hub-network/protocol-foundations.md` for frozen
naming, identity, and overlay constants.

## Layout

```
agent/
  agent.go            # Agent entry point
  cmd/hub-net/        # production command
  config/             # configuration document + defaults
  connection/         # grant-verified direct WireGuard peer orchestration
  control/            # permission-gated Hub APIs/streams
  dnsresolver/        # suffix-scoped UDP DNS, resource view, install lifecycle
  e2e/                # two-agent local end-to-end test harness (HN-310)
  enforcement/        # fail-closed per-resource TCP/UDP authorization
  grant/              # Hub connection-grant verification
  ipc/                # local IPC server, attestation flow, peer checks
  keychain/           # identity + WireGuard key persistence (0600)
  profile/            # network profile lifecycle state
  wireguard/          # portable Adapter interface + FakeAdapter
  logging/            # slog helpers
  version/            # build version
  examples/basic/     # minimal run entry point
```

## Build

```
go build ./...
go test -race ./...
```

Production entry point uses `hubnet0` by default; `-interface <name>` selects
a distinct WireGuard interface for isolated multi-agent deployments and
acceptance environments. On Linux it exits before identity creation or Hub registration unless both
`CAP_NET_ADMIN` and `CAP_NET_RAW` are effective. Other Go platforms currently
fail the same preflight as unsupported; tests and embedders must explicitly
inject fake adapters instead of receiving one from the production command.

Linux package build:

```sh
make VERSION=<release>
sudo make install
```

Package installs dedicated-user systemd service with only `CAP_NET_ADMIN` and
`CAP_NET_RAW`, plus sysusers/tmpfiles definitions for `/var/lib/hub-net` and
`/run/hub-net`. See `packaging/linux/README.md`.

`hub-service-go` and `channel-go` are wired through local `replace` directives
until the monorepo publishes tagged module versions (mirrors HN-056/HN-078).

## Key separation

Per the network-agent spec "Keys are separated and protected":

- `keychain.IdentityStorage` holds the Hub profile identity (base64 PKCS8+SPKI,
  matching the Bun/Go SDK keychain) at `StateDir/profile.identity`.
- `keychain.WireGuardStorage` holds the WireGuard Curve25519 private key (32
  raw bytes) at `StateDir/wireguard.key`.

Both files are written with mode `0600`. Rotation of either key never touches
the other; Hub binds a new WireGuard public key to the same profile through a
fresh short-lived grant.

## Split DNS

`dnsresolver.Resolver` owns an atomic, permission-filtered view of canonical
`*.hub.invalid` authorities. It resolves only while the profile is active and
drops its view on deactivation. `dnsresolver.Server` answers A/AAAA queries,
returns NXDOMAIN for unknown or inactive reserved names (never public
fallback), and sends non-Hub packets unchanged to its configured upstream.

Host resolver mutation is behind `dnsresolver.Installer`; install and removal
are coupled to server start and close. Production Linux installs route-only
`~hub.invalid` DNS on loopback through `resolvectl`, disables default routing,
and reverts partial setup and shutdown state.

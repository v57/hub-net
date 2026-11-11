# Hub Network agent platform matrix

This matrix defines the initial support boundary for the Go `hub-net` agent.
An adapter is supported only after its privilege probe, interface lifecycle,
scoped routes, split DNS, local IPC, rollback, and packaging tests pass.

| Platform | Initial status | WireGuard integration | Required privilege | Local service IPC | DNS integration |
| --- | --- | --- | --- | --- | --- |
| Linux | Supported target | Kernel WireGuard through netlink; userspace `wireguard-go` may be an explicit fallback | `CAP_NET_ADMIN` and `CAP_NET_RAW`, normally via a system service | Unix socket at `/run/hub-net/agent.sock`, mode `0660`, owner `root`, group `hub-net`; commands at `/run/hub-net/command.sock`, mode `0660`, group `hub-net` | `systemd-resolved` routing domain for `hub.invalid`; adapter must restore prior configuration |
| macOS 13+ | Supported target | Userspace WireGuard tunnel through a separately privileged system component | Root launch daemon for interface, route, and resolver changes | Unix socket at `/var/run/hub-net/agent.sock`, mode `0660`, restricted group | Scoped resolver file/configuration for `hub.invalid`; no default DNS capture |
| Windows 11 / Server 2022+ | Supported on Windows 11 arm64, the only Windows tested (see below) | WireGuardNT service adapter | Elevated Windows service (LocalSystem) | Named pipe `\\.\pipe\hub-net-agent` with an explicit service/user DACL; commands at `\\.\pipe\hub-net-command` | NRPT rule limited to `.hub.invalid`, resolver on `127.72.x.y:53` |
| Apple app profiles | Separate native target | Network Extension plus WireGuardKit; not the Go agent | Network Extension entitlement and user-approved VPN configuration | App-group IPC defined by Hub App | `NEDNSSettings` match domain |
| FreeBSD, Android, other Unix | Unsupported in v1 | No approved adapter | N/A | N/A | N/A |

## Safety requirements

- Startup probes every required capability before registering the profile as
  available. Missing privileges or unavailable WireGuard support is a hard,
  diagnosable failure.
- The agent installs only `100.96.0.0/11` and `fd48:5542:4e45::/48` routes. It
  must reject a conflicting existing route and must never install `0.0.0.0/0`
  or `::/0`.
- IPC accepts local clients only. Socket directory ownership, socket mode, peer
  credentials, nonce freshness, and service signatures are all checked; local
  filesystem access alone is not a service identity proof.
- Interface, routes, DNS rules, firewall state, and socket files are removed on
  clean shutdown. Failed startup uses the same rollback path.
- Windows support needed `channel-go`'s Windows poller and the WireGuardNT,
  named-pipe ACL, route, DNS, and rollback suites to pass. On Windows 11 arm64
  with wireguard-nt 0.10.1 they do: the `channel-go` WSAPoll poller and its
  client and server tests; the WireGuardNT adapter lifecycle
  (`HUBNET_WG_TEST=1`: two adapters handshake, the overlay route and a
  conflicting one refused, peers, MTU, Down removing the adapter and its
  route); the named-pipe ACL suite (protected DACL, first instance, remote
  clients rejected); split DNS through NRPT (resolution through the system
  resolver, removal on close, a crash's leftover rule replaced); and the WFP
  port-list lifecycle. Checked by hand on the same machine: the service
  installs, starts, stops and uninstalls; it joins a test Hub (approved by
  safety code), reaches a shared app on the Hub's machine and is reached at
  the port it shares while its other ports stay closed; stopping the service,
  leaving the Hub and killing the process remove the adapter, routes and WFP
  filters (stop and leave also remove the NRPT rule; after a crash the
  service restarts and replaces it), and the default route and ordinary DNS
  are untouched. Not checked: amd64 and Windows Server, and the IPv6
  rendezvous probe (Windows probes over IPv4 only).


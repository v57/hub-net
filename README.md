# hub-net

The Hub Network agent: the program on a device that puts it on a Hub's private network. It owns the device's
WireGuard interfaces, the overlay routes, split DNS for `*.hub.invalid`, the firewall rules that limit what other
devices may open, and the local sockets that apps and services use to talk to it. Devices find each other through a
rendezvous node ([hub-net-node](https://github.com/v57/hub-net-node)); traffic then goes directly between them and
never through the node.

The Go code lives in [`agent/`](agent/README.md). The wire protocol between the agent and the node is hub-net-node's
`PROTOCOL.md`; the Hub side (grants, `hub/net/*` APIs, devices) is section 10 of the Hub protocol
(`Docs/Devices/protocol.md` in the Hub workspace).

## What this repository ships

| Item | Purpose | Platforms / runtime | Install or import |
|---|---|---|---|
| [`hub-net`](docs/hub-net.md) | The agent daemon and its CLI (`join`, `local`, `list`, `leave`, `open`, `ports`, `vpn`, ...) | Linux (kernel WireGuard, nftables, systemd-resolved); other platforms fail its startup check | `make -C agent build`, from a Hub workspace checkout |
| Linux package | Tarball with the binary, a hardened systemd unit, sysusers/tmpfiles files and install, update and uninstall scripts | Linux with systemd | `make -C agent package VERSION=<release>`, see [`agent/packaging/linux`](agent/packaging/linux/README.md) |
| Container image | The agent in Debian with `wireguard-tools`, `nftables`, `iproute2`, `conntrack` | Linux, privileged container | `docker build -f Network/hub-net/agent/Dockerfile -t hub-net .` from the Hub workspace root |
| [Command socket](docs/ipc.md#command-socket) | JSON over HTTP on a Unix socket: what the CLI and the Hub app on Linux send to the daemon | Linux | `POST /v1/command` on `<state-dir>/command.sock` |
| [Service socket](docs/ipc.md#service-socket) | Local services prove a share's target is on this device and get a signed attestation | Linux | `/run/hub-net/agent.sock`, used by the hub-service SDKs |
| [Go packages](docs/hub-net.md#go-packages) | `github.com/v57/hub-net` (`hubnet.Agent`), `management` (command socket client), `wireguard`, `enforcement`, `dnsresolver`, `e2e` | Go 1.25 | Inside the Hub workspace only (see below) |
| `hubctl` | Test tool that plays the owner's app against a hub: sets the node, approves APIs, requests invitations | Go | `go run ./integration/hubctl` in `agent/` |

The Go module (`agent/go.mod`, module path `github.com/v57/hub-net`) replaces `channel-go`, `hub-service-go` and
`hub-net-node` with their checkouts next to it in the Hub workspace (`Channel/`, `HubService/`, `Network/`), so it
builds only from such a workspace. It isn't published for `go get` yet.

## Documentation

- [docs/hub-net.md](docs/hub-net.md): running the agent, joining a Hub, ports, split DNS, platforms, packaging,
  testing.
- [docs/ipc.md](docs/ipc.md): the command socket and the service socket.
- [agent/README.md](agent/README.md): package layout and design notes (device keys, key separation, gateway serving).
- [PLATFORMS.md](PLATFORMS.md): the platform matrix and safety requirements.
- [agent/packaging/linux/README.md](agent/packaging/linux/README.md): installing the Linux package, the hub host.
- [agent/docs/multi-hub-migration.md](agent/docs/multi-hub-migration.md): upgrading from single-Hub state, rollback.
- [integration/colima/README.md](integration/colima/README.md): the Linux acceptance run on colima.

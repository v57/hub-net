# hub-net agent

## Purpose

`hub-net` puts a device on the private network of one or more Hubs. Each Hub the device belongs to (a membership)
gets its own WireGuard interface (`hubnet0`, `hubnet1`, ...), overlay addresses from `100.96.0.0/11` and
`fd48:5542:4e45::/48`, a Hub connection, and names under `.hub.invalid`. The agent keeps the device present at the
Hub's rendezvous node, opens direct links to other devices when the Hub signs a grant for them, and installs firewall
rules so another device reaches only the ports both the Hub and this device allow.

It is not a relay and not the rendezvous node ([hub-net-node](https://github.com/v57/hub-net-node) is). It never
installs a default route (`0.0.0.0/0` or `::/0`). On macOS and iOS the Hub app runs its own Network Extension instead
of this agent.

One process (the daemon) runs every membership. The same binary is also the CLI: with a command it sends that command
to the daemon's [command socket](ipc.md#command-socket) and exits.

## Getting started

### Build

The module replaces `channel-go`, `hub-service-go` and `hub-net-node` with their checkouts in the Hub workspace, so
build inside one (`Channel/channel-go`, `HubService/hub-service-go` and `Network/hub-net-node` next to this repository):

```sh
cd agent
make build                  # build/hub-net, static, version "dev"
make build VERSION=1.0.0    # stamps the version shown by hub-net -version
make test                   # go test ./...
```

### Install on Linux

```sh
make package VERSION=1.0.0
tar -xzf build/hub-net-1.0.0-linux-amd64.tar.gz
sudo hub-net-1.0.0-linux-amd64/packaging/linux/install
sudo systemctl enable --now hub-net
```

The unit runs the agent as the `hub-net` user with only `CAP_NET_ADMIN` and `CAP_NET_RAW`, state in
`/var/lib/hub-net` (mode 0700) and runtime files in `/run/hub-net`. The agent checks those capabilities before it
creates an identity or talks to a Hub, and exits if they are missing. Details, update and uninstall:
[`agent/packaging/linux/README.md`](../agent/packaging/linux/README.md).

For a container, build `agent/Dockerfile` from the Hub workspace root. It needs `NET_ADMIN` and `NET_RAW` and keeps
its state in the `/var/lib/hub-net` volume.

### On the machine that runs the Hub

Make the agent the Hub's local agent once. hub-server proves the agent is on its machine over the service socket
(`/run/hub-net/agent.sock`), so the user running hub-server must be in the `hub-net` group, or hub-server must be
pointed at another socket with `HUB_NET_AGENT_SOCKET`.

```sh
sudo hub-net local                        # hub-server at ws://127.0.0.1:1997
sudo hub-net local ws://127.0.0.1:2000    # another address
sudo hub-net list
```

The owner then approves the agent's `net/*` APIs in the Hub app; like any service that isn't the owner's, they stay
pending until then. Only this agent issues invitations for the Hub.

### On another device

The owner creates an invitation in the Hub app (it calls the local agent's `net/invite`). On the device:

```sh
sudo hub-net join <invitation-code-or-hub://join/-URL>
```

It prints the Hub's local name, the Hub's host and this device's overlay address:

```
Joined home
Host: <hub host>
IP: 100.96.x.y
```

An invitation works once. `hub-net leave home` leaves that Hub; `hub-net removeAll` leaves every Hub.

## Commands

Run as root or as the agent's user: the command socket and the state directory belong to that user.

| Command | What it does |
|---|---|
| `hub-net` (no command) | Runs the daemon. |
| `hub-net join [--own] <code>` | Joins the Hub of an invitation. `--own` states the Hub is yours (see [Joining without a firewall](#joining-without-a-firewall)). |
| `hub-net local [hub-address]` | Serves the Hub on this machine as its local agent. Default `ws://127.0.0.1:1997`. One per machine. |
| `hub-net list` | One line per membership: local name, status (`starting`, `connected`, `disconnected`, `error`, `stopping`, `paused`) and the last error. |
| `hub-net leave <hub>` | Leaves a Hub: removes its interface, routes, DNS, firewall rules and membership state. |
| `hub-net removeAll` | Leaves every Hub. |
| `hub-net pause <hub>` / `resume <hub>` | Stops or restarts a membership's session. Keys, addresses and the membership stay. |
| `hub-net open <port> <hub>` / `close <port> <hub>` | Publishes or withdraws `127.0.0.1:<port>` (TCP and UDP) as shares `port-<port>-tcp` and `port-<port>-udp` to that Hub. |
| `hub-net vpn allow <hub>` / `vpn remove <hub>` | Lets that Hub's devices use this device as their internet gateway, or stops it. Off by default for every Hub. |
| `hub-net ports [list]` | Shows this device's own port list (below). |
| `hub-net ports allow tcp/8080` / `remove tcp/8080` | Adds or removes a port the user allows. `udp/<port>` works too. |
| `hub-net ports ssh on [port]` / `ssh off` | Allows SSH (port 22 unless given). |
| `hub-net -version` | Prints the build version. |

`<hub>` is the membership's local name, shown by `join` and `list`. It comes from the Hub's display name and is made
unique on this device.

### Daemon flags

The daemon reads flags only; there is no configuration file for the command.

| Flag | Default | Meaning |
|---|---|---|
| `-state-dir` | `/var/lib/hub-net` (Linux, macOS), `%ProgramData%\hub-net` (Windows) | Memberships, keys, the port list, the command socket. |
| `-socket` | `<state-dir>/command.sock` | The command socket. The CLI uses the same flag to find it. |
| `-socket-group` | none | Makes the command socket `0660` in this group, e.g. for the Hub app on Linux. |
| `-dns-listen` | `127.0.0.1:0` | Loopback UDP address of the `.hub.invalid` resolver. |
| `-bootstrap-listen` | `:0` | UDP address of the invitation bootstrap listener (only the Hub's local agent uses it). |
| `-advertise-address` | none | Address joiners use to reach the bootstrap listener and WireGuard port, for a host behind port forwarding. |
| `-device-key` | `$HUB_DEVICE_KEY`, else `/var/lib/hub/device.key` as root, else `~/.hub/device.key` | This device's key. Each membership's service key is certified by it, so the Hub knows the agent as `device:<id>`. |
| `-log-json` | `true` | JSON logs; `-log-json=false` for text. |

## How joining works

1. The Hub's local agent registers its presence at the Hub's rendezvous node. The node is whatever the Hub's owner set
   with `hub/net/node/set`; hub-server's default is `wss://v57.dev:1964`. The agent follows hub-server's `hub/net/node`
   setting and puts that node in its invitations.
2. The joiner decodes the invitation, opens a session at the node, and the node pairs it with the inviter. The node
   passes only addresses and typed coordination messages (hub-net-node's
   [`PROTOCOL.md`](https://github.com/v57/hub-net-node/blob/main/PROTOCOL.md), "Invitation bootstrap signaling").
3. The joiner sends a signed request straight to the inviter's bootstrap listener, gets a temporary WireGuard link to
   the Hub's machine, and binds to hub-server over it (`hub/net/bind`) with a fresh service key certified by the
   device key. The Hub assigns the overlay addresses.
4. The daemon adopts the membership. Keys are staged per invitation, so a retried join reuses them instead of
   enrolling twice.

After that the member keeps a WireGuard link to the Hub's machine and opens links to other devices when the Hub hands
it a peer link grant. The Hub side of this (grants, `hub/net/*`, revocation) is section 10 of the Hub protocol
(`Docs/Devices/protocol.md` in the Hub workspace).

## Ports and addresses

| What | Where | Notes |
|---|---|---|
| hub-server | `ws://<hub>:1997` | Reached over the overlay once joined. |
| Rendezvous node | The node URL (TCP, WebSocket on `/rendezvous`) and UDP on the same port | Default node `wss://v57.dev:1964`. The UDP probe goes to the URL's host and port. |
| WireGuard | UDP 51820 | Per interface. |
| Bootstrap listener | `-bootstrap-listen`, ephemeral by default | Hub's local agent only; joiners learn it through the node. |
| DNS resolver | `-dns-listen`, loopback | Only `.hub.invalid` queries are routed to it. |
| Command socket | `<state-dir>/command.sock` | [ipc.md](ipc.md#command-socket) |
| Service socket | `/run/hub-net/agent.sock` (Linux), `/var/run/hub-net/agent.sock` (macOS) | [ipc.md](ipc.md#service-socket) |

The agent installs routes only for `100.96.0.0/11` and `fd48:5542:4e45::/48` and refuses to start a membership when
another route already covers them. Every Hub assigns from the same ranges, so two Hubs can hand out overlapping
addresses. The `translation` package maps each Hub into its own range (`10.0.0.0/8` split into /11 slots, `fd80::/9`
into /48 slots) with policy routing and reversible NAT, and keeps the ranges across restarts; a daemon built with
`hubnet.NewDaemonWithTranslation` uses it. The `hub-net` command builds its daemon with `hubnet.NewDaemon`, which
doesn't translate.

## What other devices may open

A Hub-signed grant names ports. The device opens only those that are also on its own list, `device-ports.json` in
the state directory, shared by all its Hubs. So a Hub can narrow what's reachable on the device, never widen it. The
list holds:

- the shares this device publishes (`hub-net open`);
- ports local services attested through the service socket, for 31 days after the last attestation;
- ports the user allowed (`hub-net ports allow`);
- the Hub's own port, on the Hub's machine;
- SSH, only after `hub-net ports ssh on`.

`hub-net ports` edits the file directly, so nothing reaches it over the network. A running agent picks up a change
within seconds and ends the flows of a port that left the list.

Enforcement is the Linux nftables backend. The first link rule set turns the firewall on, also on a member with no
links, so every overlay port is closed until something opens it. A revoked device's peers, rules and flows are removed
and don't come back.

### Joining without a firewall

Without the nftables backend (Linux without `nft`; other platforms), nothing would stop a Hub's devices from reaching
every port the device listens on. There `hub-net join` refuses a Hub this device doesn't own. Before it binds, the
join asks the Hub through the temporary link whether this device is one of its owners; a Hub that says no or can't
answer counts as someone else's. `hub-net join --own` says the Hub is yours anyway. Joining your own Hub without a
firewall goes through with a warning that the device's ports aren't limited. `hub-net local` is always your own Hub.

## Split DNS

Each membership's names live under its local name: a name the Hub publishes as `printer.hub.invalid` resolves as
`printer.<hub>.hub.invalid` on this device. The resolver answers A and AAAA only while the membership is active,
returns NXDOMAIN for unknown `.hub.invalid` names (never a public fallback), and passes other queries to its upstream
unchanged.

On Linux the agent sets a route-only domain `~hub.invalid` on the membership's interface through `resolvectl`, turns
off default routing for that link, and reverts it on shutdown or a failed start. Without systemd-resolved the tunnel
still works, but `.hub.invalid` names don't resolve.

## Gateway serving

`hub-net vpn allow <hub>` lets that Hub's devices send their internet traffic through this device. The agent installs
forwarding, NAT and firewall rules for that Hub's interface only, then advertises the capability to the Hub.
`vpn remove` takes all of it down and ends tracked flows. The choice is stored per Hub; a restart restores only Hubs
where it was turned on. More in [`agent/README.md`](../agent/README.md#gateway-serving).

## Files

Under the state directory (all 0700 or 0600):

| Path | Contents |
|---|---|
| `memberships.json`, `memberships/<hash>/` | One directory per membership: `record.json`, `profile.identity` (service key), `wireguard.key`, `publications.json`, `service.sock` |
| `staged/`, `invitations/` | Joins in progress; an interrupted join resumes from here |
| `device-ports.json` | The device's port list |
| `command.sock` | The command socket |

The service key and the WireGuard key are separate files and rotate independently. Upgrading from a single-Hub
release: [`agent/docs/multi-hub-migration.md`](../agent/docs/multi-hub-migration.md).

## Platforms

The full matrix and safety rules are in [`PLATFORMS.md`](../PLATFORMS.md). Today:

| Platform | Status |
|---|---|
| Linux | Supported: kernel WireGuard over netlink, nftables, systemd-resolved, systemd packaging. Tested on Ubuntu amd64 and in the colima acceptance run. |
| macOS | The Go agent builds, but its startup check fails: there's no Go tunnel adapter. Macs use the Hub app's Network Extension. |
| iOS, iPadOS | Not this agent: the Hub app's Network Extension. |
| Windows | Planned. Builds; startup check fails. Not supported until WireGuardNT, named-pipe ACLs, routes, DNS (NRPT) and rollback pass. |
| Android, FreeBSD | Not supported. |

On every platform without a backend, operations fail closed (`ErrPlatformUnsupported`) instead of running without
enforcement.

## Go packages

The packages are written to be embedded and tested without privileges, but the module builds only inside the Hub
workspace (see [Build](#build)).

| Package | Use |
|---|---|
| `github.com/v57/hub-net` (`hubnet`) | `hubnet.New(hubnet.Options)` and `Agent.Run(ctx)`: one membership's session. `hubnet.NewDaemon` runs several. |
| `management` | The command socket: `NewClient(socketPath)`, `Client.Execute(ctx, Request)`, `ParseCommand(args)`. |
| `config` | `config.Defaults()`, `Config.Resolve()`: the session settings and their defaults. |
| `wireguard` | `Adapter` interface, `NewPlatformAdapter(name)`, `NewFakeAdapter()` for tests. |
| `enforcement` | Firewall backends; `MemoryBackend` for tests. |
| `dnsresolver` | The `.hub.invalid` resolver, server and host installer. |
| `deviceports` | The device's port list and the `hub-net ports` command. |
| `e2e` | Two agents in one test process: real IPC attestation, Hub-signed grants, fake WireGuard and firewall. |

A Go program on the same machine can drive the daemon like the CLI does:

```go
package main

import (
	"context"
	"fmt"

	"github.com/v57/hub-net/management"
)

func main() {
	client := management.NewClient("/var/lib/hub-net/command.sock")
	response, err := client.Execute(context.Background(), management.Request{
		Version: management.Version,
		Command: "list",
	})
	if err != nil {
		panic(err)
	}
	for _, item := range response.Items {
		fmt.Println(item.Alias, item.Status, item.OverlayIPv4)
	}
}
```

The wire models and identities come from hub-net-node's `models`, `identity` and `protocol` packages.

## Testing

```sh
cd agent
go test -race ./...         # what runs on any platform
go vet ./...
```

`enforcement`, `wireguard` and parts of `dnsresolver` build only on Linux. From a Mac, run the whole suite in a
Linux container with the whole Hub workspace mounted, since the module's `replace` directives point into it (the
colima profile from the acceptance run, or any Docker). From `agent/`:

```sh
docker run --rm -v "$(cd ../../.. && pwd)":/hub -w /hub/Network/hub-net/agent golang:1.26-bookworm go test ./...
```

Privileged checks run on a disposable Linux host as root:

| Command | Checks |
|---|---|
| `sudo make integration-multi-hub-linux` | Several Hubs with overlapping overlays: translation, DNS and node isolation, restart, leave, `removeAll`. |
| `sudo make integration-linux-package` | Package build, file modes, systemd hardening, upgrade, downgrade, uninstall without key loss. |
| `sudo make integration-machine-restart-prepare`, reboot, `...-verify` | Identity and keys survive a reboot. |

The end-to-end run with a real hub-server, node and three agents in containers is
[`integration/colima`](../integration/colima/README.md) (`./up.sh`). `agent/e2e` and `wireguard.NewFakeAdapter`,
`enforcement.MemoryBackend` let tests run agents without root.

## See also

- [ipc.md](ipc.md): the command socket and the service socket.
- [`agent/README.md`](../agent/README.md): layout, device keys, key separation.
- hub-net-node: [README](https://github.com/v57/hub-net-node#readme), [running a node](https://github.com/v57/hub-net-node/blob/main/docs/node.md),
  [`PROTOCOL.md`](https://github.com/v57/hub-net-node/blob/main/PROTOCOL.md).

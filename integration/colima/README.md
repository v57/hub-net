# Linux acceptance on colima

`up.sh` runs the Linux Hub Network acceptance against real kernel WireGuard on
the colima `hubnet` profile. It replaces the August harness that needed the
`v57u` Ubuntu host.

| Container | Role |
|---|---|
| `hn-node` | `hub-net-node` on the VM's own network, `<vm address>:1964` TCP + UDP |
| `hn-owner` | hub-pro + `hub-net local`: the hub host, issues invitations |
| `hn-joiner` | `hub-net join <invite>` |
| `hn-other` | second member; also checks that an invitation is single-use |

Hosts share the Docker network `hubnet-lan` (`172.30.0.0/24`). Binaries are
cross-compiled on the Mac (`bin/`) from `Network/hub-net` and
`Network/hub-net-node`, and `~/Developer/Hub` is mounted at `/hub` for hub-pro
(`Core/hub-pro`, whose `node_modules/channel` links to `Channel/channel`), so a
code change only needs another `./up.sh`. Logs land in `state/<host>/`.

## Setup (once)

```sh
colima start hubnet --vm-type vz --cpu 2 --memory 2 --network-address --port-forwarder grpc
docker context use desktop-linux   # colima start switches the global context
```

`--port-forwarder grpc` matters: the default ssh forwarder drops UDP.
`--network-address` gives the VM an address on a Mac vmnet (`192.168.64.x` or `192.168.65.x`,
it can change on restart; `up.sh` reads it from `colima list`) like the UTM
VMs; the Mac is `.1` on that subnet.

## Run

```sh
./up.sh          # build, start, join, then the checks below; exit 1 on any FAIL
./up.sh down     # remove the containers
```

Checks: traffic both ways and hub-pro (`:1997`) over the overlay; single-use
invitation; port grants (closed by default, global open/close, per-user grant
not shared with another member); members cannot reach each other; restart of
the joiner daemon, the owner daemon and hub-pro; revoke; leave.

`hubctl` (`agent/integration/hubctl`) plays the owner's app: it sets the
node endpoint, approves the agent's APIs (`hub/host/pending`), requests
invitations and calls the agent (`hubctl agent post net/ports/update '{...}'`).

## Mac joiner

A packet tunnel provider's own sockets are scoped to the physical interface
(`en0`), so the Mac extension cannot reach the colima VM network. `HUBNET_LAN=1`
publishes the node (`1964` tcp/udp) and the owner's WireGuard (`51820/udp`) and
bootstrap (`1965/udp`) ports on the Mac's LAN address, and the owner advertises
it (`hub-net -bootstrap-listen :1965 -advertise-address <lan ip>`):

```sh
HUBNET_LAN=1 ./up.sh                    # Linux scenarios still run (21 checks)
./mac-join.sh path/to/Debug/Hub.app     # join, ping/TCP/RPC to hub-pro, leave
```

The Mac needs the "Hub Network" VPN profile approved once, by a build signed
with the team's Apple Development identity (ad-hoc builds invalidate it).

## Linux-only Go tests

`enforcement`, `wireguard` and parts of `dnsresolver` only build on Linux:

channel-go, hub-service-go and hub-net-node come from their `~/Developer/Hub`
clones, so mount the whole Hub folder:

```sh
docker --context colima-hubnet run --rm -v ~/Developer/Hub:/hub -v hubnet-gomod:/go/pkg/mod \
  -w /hub/Network/hub-net/agent golang:1.26-bookworm go test ./...
```

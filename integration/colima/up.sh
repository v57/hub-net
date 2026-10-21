#!/usr/bin/env bash
# Linux owner -> Linux joiner acceptance on the colima `hubnet` profile.
#
#   hn-node    hub-net-node on the VM's own network (<vm address>:1964 tcp+udp)
#   hn-owner   hub-server + `hub-net local`: the hub host, issues the invitation
#   hn-joiner  `hub-net join <invite>`
#   hn-other   a second joiner, used to check that an invitation is single-use
#
# Both hosts sit on the docker network hubnet-lan (172.30.0.0/24) and run
# kernel WireGuard. Logs and state land in integration/colima/state/.
#
# Usage: up.sh          build, start everything and run the join
#        up.sh down     remove the containers
#
# HUBNET_OWNER_NETWORK=host puts hn-owner on the VM's own network
# (the VM address) instead of a Docker bridge address.
#
# HUBNET_LAN=1 publishes the node and the owner's WireGuard (51820/udp) and
# bootstrap (1965/udp) ports on the Mac's LAN address and has the owner
# advertise it. A Mac joiner needs this: a packet tunnel provider's own sockets
# are scoped to the physical interface, so it cannot reach the VM network.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# ~/Developer/Hub: hub-net, hub-net-node and hub-server are built from its clones.
hub=$(cd "$here/../../../.." && pwd)
context=${HUBNET_CONTEXT:-colima-hubnet}
# The VM's address on the Mac's vmnet (--network-address); it can change when
# the VM restarts.
node_ip=${HUBNET_NODE_IP:-$(colima list -p "${context#colima-}" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')}
lan_ip=""
if [[ -n ${HUBNET_LAN:-} ]]; then
  lan_ip=$(ipconfig getifaddr en0)
  node_ip=$lan_ip
fi
bin=$here/bin
state=$here/state
D() { docker --context "$context" "$@"; }
say() { echo "[hubnet] $*"; }

down() {
  D rm -f hn-node hn-owner hn-joiner hn-other >/dev/null 2>&1 || true
  # A host-network owner leaves its interface and firewall in the VM itself.
  colima ssh -p "${context#colima-}" -- sh -c \
    'sudo ip link del hubnet0 2>/dev/null; sudo nft delete table inet hub_net 2>/dev/null; true' >/dev/null 2>&1 || true
}

if [[ ${1:-} == down ]]; then
  down
  exit 0
fi

say "building linux/arm64 binaries"
mkdir -p "$bin"
(cd "$hub/Network/hub-net/agent" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$bin/hub-net" ./cmd/hub-net \
  && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$bin/hubctl" ./integration/hubctl)
(cd "$hub/Network/hub-net-node" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$bin/hub-net-node" ./cmd/hub-net-node)
D build -q -t hubnet-dev "$here" >/dev/null

down
rm -rf "$state"
mkdir -p "$state/node" "$state/owner/hub-server" "$state/joiner" "$state/other"
D network inspect hubnet-lan >/dev/null 2>&1 || D network create --subnet 172.30.0.0/24 hubnet-lan >/dev/null

say "starting hub-net-node on $node_ip:1964"
node_network=(--network host)
if [[ -n $lan_ip ]]; then
  node_network=(--network hubnet-lan -p 1964:1964/tcp -p 1964:1964/udp)
fi
D run -d --name hn-node "${node_network[@]}" -v "$bin:/opt/bin:ro" -v "$state/node:/state" hubnet-dev \
  /opt/bin/hub-net-node -listen 0.0.0.0:1964 -state-dir /state -log-json=false >/dev/null

host() {
  local network=(--network hubnet-lan --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.disable_ipv6=0)
  if [[ $1 == hn-owner && ${HUBNET_OWNER_NETWORK:-} == host ]]; then network=(--network host); fi
  if [[ $1 == hn-owner && -n $lan_ip ]]; then network+=(-p 51820:51820/udp -p 1965:1965/udp); fi
  D run -d --name "$1" --hostname "${1#hn-}" "${network[@]}" \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$hub:/hub" -v "$bin:/opt/bin:ro" -v "$state/${1#hn-}:/state" \
    -e PATH="/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" hubnet-dev sleep infinity >/dev/null
}
host hn-owner
host hn-joiner
host hn-other

wait_for() {
  local what=$1; shift
  for _ in $(seq 1 60); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  say "FAIL: $what"
  exit 1
}

owner_key=$(D exec hn-owner hubctl -identity /state/owner.identity key)
say "starting hub-server on hn-owner (owner ${owner_key:0:24}...)"
D exec -d -w /state/hub-server -e HUBOWNER="$owner_key" -e HUBLISTEN=0.0.0.0:1997 hn-owner \
  sh -c 'bun /hub/Core/hub-server/index.ts > /state/hub-server.log 2>&1'
wait_for "hub-server :1997" D exec hn-owner nc -z 127.0.0.1 1997
D exec hn-owner hubctl -identity /state/owner.identity node-set "ws://$node_ip:1964"

start_daemon() {
  local flags=""
  if [[ $1 == hn-owner && -n $lan_ip ]]; then flags="-bootstrap-listen :1965 -advertise-address $lan_ip"; fi
  D exec -d "$1" sh -c "hub-net -state-dir /var/lib/hub-net -log-json=false $flags >> /state/hub-net.log 2>&1"
  wait_for "$1 hub-net daemon" D exec "$1" test -S /var/lib/hub-net/command.sock
}
for name in hn-owner hn-joiner hn-other; do start_daemon "$name"; done

say "hn-owner: hub-net local"
D exec hn-owner hub-net -state-dir /var/lib/hub-net local
say "owner approves the agent's APIs (hub/host/pending), as in Hub App"
D exec hn-owner hubctl -identity /state/owner.identity approve
say "hn-owner: requesting an invitation"
invite=$(D exec hn-owner hubctl -identity /state/owner.identity invite)
say "invite: ${invite:0:48}..."

say "hn-joiner: hub-net join"
D exec hn-joiner hub-net -state-dir /var/lib/hub-net join "$invite"
D exec hn-joiner hub-net -state-dir /var/lib/hub-net list

owner_ip=$(D exec hn-owner sh -c "ip -4 -br addr show dev hubnet0" | awk '{print $3}' | cut -d/ -f1)
joiner_ip=$(D exec hn-joiner sh -c "ip -4 -br addr show dev hubnet0" | tr ' ' '\n' | grep '^100\.9[6-9]\|^100\.1[01][0-9]\|^100\.12[0-6]' | cut -d/ -f1 | head -1)
say "overlay: owner $owner_ip, joiner $joiner_ip"
check() {
  local label=$1; shift
  if D exec "$@" >/dev/null 2>&1; then say "PASS $label"; else say "FAIL $label"; failed=1; fi
}
# check_eventually retries for up to 20 s (reconnects, stream updates).
check_eventually() {
  local label=$1; shift
  for _ in $(seq 1 20); do
    if D exec "$@" >/dev/null 2>&1; then say "PASS $label"; return; fi
    sleep 1
  done
  say "FAIL $label"; failed=1
}
refute() {
  local label=$1; shift
  if D exec "$@" >/dev/null 2>&1; then say "FAIL $label"; failed=1; else say "PASS $label"; fi
}
agent() { D exec hn-owner hubctl -identity /state/owner.identity agent "$@"; }
failed=0
check_eventually "joiner -> owner ping" hn-joiner ping -c2 -W2 "$owner_ip"
check_eventually "owner -> joiner ping" hn-owner ping -c2 -W2 "$joiner_ip"
check_eventually "joiner -> hub-server :1997" hn-joiner nc -z -w3 "$owner_ip" 1997

say "--- single-use invitation"
refute "second joiner with the same invitation is rejected" hn-other hub-net -state-dir /var/lib/hub-net join "$invite"

say "--- ports"
D exec -d hn-owner sh -c 'while true; do echo hello | nc -l -N 8080 >/dev/null 2>&1; done'
sleep 1
refute "port 8080 closed by default" hn-joiner nc -z -w3 "$owner_ip" 8080
retired=$(agent post net/ports/update '{"update":[{"port":8080,"udp":false}]}' 2>&1 || true)
if printf '%s' "$retired" | grep -q "port grants are retired"; then say "PASS net/ports/update is refused"; else say "FAIL net/ports/update: $retired"; failed=1; fi
refute "the retired port grant opens nothing" hn-joiner nc -z -w3 "$owner_ip" 8080
users=$(agent stream net/users || true)
say "net/users: $users"
joiner_key=$(printf '%s' "$users" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])' 2>/dev/null || true)
if [[ -z $joiner_key ]]; then
  say "FAIL net/users did not list the joiner"; failed=1
fi

say "--- second member"
second_invite=$(D exec hn-owner hubctl -identity /state/owner.identity invite)
D exec hn-other hub-net -state-dir /var/lib/hub-net join "$second_invite" >/dev/null
other_ip=$(D exec hn-other sh -c "ip -4 -br addr show dev hubnet0" | tr ' ' '\n' | grep '^100\.9[6-9]' | cut -d/ -f1 | head -1)
say "second member $other_ip"
check_eventually "second member reaches hub-server" hn-other nc -z -w3 "$owner_ip" 1997
refute "port 8080 stays closed for the second member" hn-other nc -z -w3 "$owner_ip" 8080
refute "members cannot reach each other directly" hn-other ping -c1 -W2 "$joiner_ip"

say "--- restarts"
restart_daemon() {
  D exec "$1" pkill -x hub-net || true
  sleep 1
  start_daemon "$1"
}
restart_daemon hn-joiner
check_eventually "joiner daemon restart: hub-server reachable again" hn-joiner nc -z -w3 "$owner_ip" 1997
restart_daemon hn-owner
check_eventually "owner daemon restart: joiner reaches hub-server" hn-joiner nc -z -w3 "$owner_ip" 1997
check_eventually "owner daemon restart: owner reaches joiner" hn-owner ping -c1 -W2 "$joiner_ip"
D exec hn-owner pkill -x bun || true
D exec -d -w /state/hub-server -e HUBOWNER="$owner_key" -e HUBLISTEN=0.0.0.0:1997 hn-owner \
  sh -c 'bun /hub/Core/hub-server/index.ts >> /state/hub-server.log 2>&1'
check_eventually "hub-server restart: joiner reconnects" hn-joiner sh -c "hub-net -state-dir /var/lib/hub-net list | grep -q connected && nc -z -w3 $owner_ip 1997"
check_eventually "hub-server restart: owner reaches joiner" hn-owner ping -c1 -W2 "$joiner_ip"
check_eventually "after restarts: second member reaches hub-server" hn-other nc -z -w3 "$owner_ip" 1997

say "--- revoke and leave"
if [[ -n $joiner_key ]]; then
  agent post net/revoke "\"$joiner_key\"" >/dev/null || true
  check_eventually "revoked member loses access" hn-joiner sh -c "! nc -z -w3 $owner_ip 1997"
  check_eventually "other member keeps access" hn-other nc -z -w3 "$owner_ip" 1997
fi
hubctl_owner() { D exec hn-owner hubctl -identity /state/owner.identity "$@"; }
devices=$(hubctl_owner stream hub/devices || true)
other_device=$(printf '%s' "$devices" | python3 -c 'import json,sys; print(next(d["id"] for d in json.load(sys.stdin) if d.get("name") == "other"))' 2>/dev/null || true)
if [[ -n $other_device ]]; then
  say "PASS the second member is device ${other_device:0:12}..."
  hubctl_owner post hub/device/revoke "{\"id\":\"$other_device\"}" >/dev/null || true
  check_eventually "device revoke: the hub host drops its peer" hn-other sh -c "! nc -z -w3 $owner_ip 1997"
  check "device revoke: the owner no longer reaches it" hn-owner sh -c "! ping -c1 -W2 $other_ip"
else
  say "FAIL hub/devices did not list the second member: $devices"; failed=1
fi
D exec hn-other hub-net -state-dir /var/lib/hub-net leave owner >/dev/null || true
refute "leaving removes the interface" hn-other ip link show hubnet0
check "leaving clears the membership" hn-other sh -c "test -z \"\$(hub-net -state-dir /var/lib/hub-net list)\""

say "logs in $state"
exit $failed

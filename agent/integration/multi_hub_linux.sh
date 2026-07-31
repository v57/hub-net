#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo "SKIP: Linux required"
  exit 0
fi
if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: root required"
  exit 0
fi

for command in go ip nft conntrack sysctl curl ping python3; do
  command -v "$command" >/dev/null || {
    echo "SKIP: missing required command: $command"
    exit 0
  }
done

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root_dir"

# One bounded gate joins component acceptance that otherwise runs in separate
# packages. Race-enabled tests exercise persisted restart/recovery, isolated
# node/session state, alias-qualified DNS, serialized leave/removeAll, and
# crash-resumed cleanup. Privileged translation test then proves overlapping
# canonical IPv4/IPv6 traffic through real namespaces, policy routing, nftables,
# conntrack marks, deterministic reinstall, scoped leave, and final teardown.
go test -race ./supervisor -run 'Test(SessionsAreIndependentAndFailureIsolated|MembershipIsolationAndIdempotency)'
go test -race ./dnsresolver -run 'TestViewSet(IsolatesDuplicateSharesAndTranslatesAnswers|ReplacementAndRemovalStayScoped)'
go test -race ./membership -run 'Test(StoreCommitRestartAndCorruptionIsolation|LoadFinishesInterruptedRemoval)'
go test -race ./management -run 'Test(CommandsSerializeAndLeaveIsIdempotent|RemoveAllDeletesEveryLiveAndPersistedMembership)'

# Host may itself use Tailscale's 100.64.0.0/10 routes and anti-spoof rules.
# Run data-plane acceptance in a clean parent namespace so host VPN/firewall
# policy cannot capture hub-net's canonical 100.96.0.0/11 test traffic.
acceptance_namespace=hn837-root
cleanup_namespace() {
  ip netns delete "$acceptance_namespace" >/dev/null 2>&1 || true
}
trap cleanup_namespace EXIT
cleanup_namespace
ip netns add "$acceptance_namespace"
ip netns exec "$acceptance_namespace" ip link set lo up
ip netns exec "$acceptance_namespace" env \
  HUB_NET_PRIVILEGED=1 \
  go test ./translation -run '^TestLinuxPrivilegedOverlappingHubLifecycle$' -count=1
cleanup_namespace
trap - EXIT

# Gateway acceptance uses its own clean parent namespace so host forwarding,
# nftables, Tailscale routes, and local services cannot affect containment.
gateway_namespace=hn843-root
cleanup_gateway_namespace() {
  ip netns delete "$gateway_namespace" >/dev/null 2>&1 || true
}
trap cleanup_gateway_namespace EXIT
cleanup_gateway_namespace
ip netns add "$gateway_namespace"
ip netns exec "$gateway_namespace" ip link set lo up
ip netns exec "$gateway_namespace" env \
  HUB_NET_PRIVILEGED=1 \
  go test ./gateway -run '^TestLinuxPrivilegedGatewayContainmentAndRevocation$' -count=1
cleanup_gateway_namespace
trap - EXIT

echo "PASS: HN-837 multi-Hub isolation and HN-843 IPv4/IPv6 gateway containment"

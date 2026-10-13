#!/usr/bin/env bash
# Mac joins the Linux hub on colima: the Hub App's joiner acceptance hook joins
# with a fresh invitation, checks ping/TCP/RPC to the hub over the overlay,
# then leaves. Needs the "Hub Network" VPN profile approved once on this Mac.
#
#   HUBNET_OWNER_NETWORK=host ./up.sh    # owner reachable at the VM address
#   ./mac-join.sh [path/to/Hub.app]
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
app=${1:-${HUB_APP:-}}
if [[ -z $app ]]; then
  echo "usage: mac-join.sh path/to/Hub.app (a signed Debug build)" >&2
  exit 2
fi
context=${HUBNET_CONTEXT:-colima-hubnet}
log=$here/state/mac-join.log

invite=$(docker --context "$context" exec hn-owner hubctl -identity /state/owner.identity invite)
echo "[mac-join] invite ${invite:0:48}..."
# The acceptance runs in the app's window. A killed run can leave saved state
# that restores no window, so ignore it.
HUB_HN9XX_JOINER_ACCEPTANCE=1 HUB_HN9XX_INVITATION="$invite" \
  "$app/Contents/MacOS/Hub" -ApplePersistenceIgnoreState YES > "$log" 2>&1 &
pid=$!
for _ in $(seq 1 200); do
  if grep -q '\[HN9XX\] result-json' "$log"; then break; fi
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 1
done
kill "$pid" 2>/dev/null || true
grep '\[HN9XX\] progress\|\[HN9XX\] joiner' "$log" | tail -20 || true
result=$(grep -o '\[HN9XX\] result-json [A-Za-z0-9+/=]*' "$log" | tail -1 | cut -d' ' -f3)
if [[ -z $result ]]; then
  echo "[mac-join] FAIL: no result (log: $log)"
  exit 1
fi
echo "$result" | base64 -d | python3 -m json.tool
echo "$result" | base64 -d | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("joined") else 1)'

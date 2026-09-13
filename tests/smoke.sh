#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/shadowdns"
cd "$ROOT"

if [[ ! -x $BIN ]]; then
  make -C "$ROOT" >/dev/null
fi

PORT_DNS=18553
PORT_HTTP=18089
TOKEN="smoke-test-token-$$"
rm -f /tmp/shadowdns-smoke.jsonl
"$BIN" --bind 127.0.0.1 --dns-port "$PORT_DNS" --http-port "$PORT_HTTP" --quiet --no-ebpf \
  --token "$TOKEN" \
  --jsonl /tmp/shadowdns-smoke.jsonl \
  --policy config/policy.sd &
PID=$!
cleanup() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; return 0; }
trap cleanup EXIT

for i in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:${PORT_HTTP}/api/health" >/dev/null; then
    break
  fi
  sleep 0.1
done

# health is public
curl -sf "http://127.0.0.1:${PORT_HTTP}/api/health" | grep -q '"ok":true'
# stats require token
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT_HTTP}/api/stats")
[[ "$code" == "401" ]]
curl -sf -H "X-ShadowDNS-Token: $TOKEN" "http://127.0.0.1:${PORT_HTTP}/api/stats" | grep -q '"queries"'

dig @127.0.0.1 -p "$PORT_DNS" example.com +time=2 +tries=1 >/dev/null
dig @127.0.0.1 -p "$PORT_DNS" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tunnel.test" +time=2 +tries=1 >/dev/null || true
dig @127.0.0.1 -p "$PORT_DNS" api.segment.io +time=2 +tries=1 >/dev/null || true
dig @127.0.0.1 -p "$PORT_DNS" malware.example +time=2 +tries=1 >/dev/null || true

curl -sf -X POST -H "X-ShadowDNS-Token: $TOKEN" -H 'content-type: application/json' \
  "http://127.0.0.1:${PORT_HTTP}/api/fluxtap" \
  -d '{"sni":"cdn.other.test","process":"curl","ja3":"deadbeef"}' | grep -q ok

# unauth mutate must fail
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
  "http://127.0.0.1:${PORT_HTTP}/api/block" -d '{"domain":"evil.test"}')
[[ "$code" == "401" ]]

sleep 0.4
EVENTS="$(curl -sf -H "X-ShadowDNS-Token: $TOKEN" "http://127.0.0.1:${PORT_HTTP}/api/events")"
echo "$EVENTS" | grep -q example.com
echo "$EVENTS" | grep -q tunnel
curl -sf -H "X-ShadowDNS-Token: $TOKEN" "http://127.0.0.1:${PORT_HTTP}/metrics" | grep -q shadowdns_queries_total
curl -sf -H "X-ShadowDNS-Token: $TOKEN" "http://127.0.0.1:${PORT_HTTP}/api/sarif" | grep -q '"runs"'
curl -sf -H "X-ShadowDNS-Token: $TOKEN" "http://127.0.0.1:${PORT_HTTP}/api/stories" >/dev/null
curl -sf -H "X-ShadowDNS-Token: $TOKEN" "http://127.0.0.1:${PORT_HTTP}/api/policy" | grep -q policy
test -s /tmp/shadowdns-smoke.jsonl
# jsonl should be owner-only
perm=$(stat -c '%a' /tmp/shadowdns-smoke.jsonl)
[[ "$perm" == "600" || "$perm" == "0600" ]]
echo "smoke ok"

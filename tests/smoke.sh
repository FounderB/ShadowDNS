#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/shadowdns"
cd "$ROOT"

if [[ ! -x $BIN ]]; then
  make -C "$ROOT" >/dev/null
fi

PORT_DNS=18553
PORT_HTTP=18088
rm -f /tmp/shadowdns-smoke.jsonl
"$BIN" --dns-port "$PORT_DNS" --http-port "$PORT_HTTP" --quiet --no-ebpf \
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

curl -sf "http://127.0.0.1:${PORT_HTTP}/api/health" | grep -q '"ok":true'
dig @127.0.0.1 -p "$PORT_DNS" example.com +time=2 +tries=1 >/dev/null
dig @127.0.0.1 -p "$PORT_DNS" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tunnel.test" +time=2 +tries=1 >/dev/null || true
dig @127.0.0.1 -p "$PORT_DNS" api.segment.io +time=2 +tries=1 >/dev/null || true
dig @127.0.0.1 -p "$PORT_DNS" malware.example +time=2 +tries=1 >/dev/null || true

# FluxTap bridge ingest
curl -sf -X POST "http://127.0.0.1:${PORT_HTTP}/api/fluxtap" \
  -H 'content-type: application/json' \
  -d '{"sni":"cdn.other.test","process":"curl","ja3":"deadbeef"}' | grep -q ok

sleep 0.5
EVENTS="$(curl -sf "http://127.0.0.1:${PORT_HTTP}/api/events")"
echo "$EVENTS" | grep -q example.com
echo "$EVENTS" | grep -q tunnel
STATS="$(curl -sf "http://127.0.0.1:${PORT_HTTP}/api/stats")"
echo "$STATS" | grep -q '"queries"'
curl -sf "http://127.0.0.1:${PORT_HTTP}/metrics" | grep -q shadowdns_queries_total
curl -sf "http://127.0.0.1:${PORT_HTTP}/api/sarif" | grep -q '"runs"'
curl -sf "http://127.0.0.1:${PORT_HTTP}/api/stories" >/dev/null
curl -sf "http://127.0.0.1:${PORT_HTTP}/api/policy" | grep -q policy
test -s /tmp/shadowdns-smoke.jsonl
echo "smoke ok"

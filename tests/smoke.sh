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
"$BIN" --dns-port "$PORT_DNS" --http-port "$PORT_HTTP" --quiet &
PID=$!
cleanup() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }
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

sleep 0.4
EVENTS="$(curl -sf "http://127.0.0.1:${PORT_HTTP}/api/events")"
echo "$EVENTS" | grep -q example.com
echo "$EVENTS" | grep -q tunnel
STATS="$(curl -sf "http://127.0.0.1:${PORT_HTTP}/api/stats")"
echo "$STATS" | grep -q '"queries"'
echo "smoke ok"

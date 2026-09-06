#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-/usr/local}"

echo "[*] building ShadowDNS"
make -C "$ROOT" clean all

echo "[*] installing to $PREFIX (needs write access / sudo)"
install -d "$PREFIX/bin"
install -d "$PREFIX/share/shadowdns/web"
install -d "$PREFIX/share/shadowdns/config"
install -m 755 "$ROOT/shadowdns" "$PREFIX/bin/shadowdns"
cp -a "$ROOT/web/." "$PREFIX/share/shadowdns/web/"
cp -a "$ROOT/config/." "$PREFIX/share/shadowdns/config/"

if [[ -d /etc/systemd/system ]]; then
  install -m 644 "$ROOT/deploy/shadowdns.service" /etc/systemd/system/shadowdns.service
  systemctl daemon-reload || true
  echo "[*] systemd unit installed: systemctl enable --now shadowdns"
fi

echo
echo "Installed. Safe lab mode (no root DNS):"
echo "  shadowdns --dns-port 5353 --http-port 8088"
echo
echo "Production resolver (port 53) — review networking first:"
echo "  sudo shadowdns --dns-port 53 --http-port 8088 --upstream doh:cloudflare-dns.com"
echo
echo "Dashboard: http://127.0.0.1:8088"

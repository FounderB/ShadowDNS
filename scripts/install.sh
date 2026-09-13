#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-/usr/local}"

echo "[*] building ShadowDNS"
make -C "$ROOT" clean all

echo "[*] installing to $PREFIX"
install -d "$PREFIX/bin"
install -d "$PREFIX/share/shadowdns/web"
install -d "$PREFIX/share/shadowdns/config"
install -d /var/log/shadowdns
install -d /etc/shadowdns
install -m 755 "$ROOT/shadowdns" "$PREFIX/bin/shadowdns"
cp -a "$ROOT/web/." "$PREFIX/share/shadowdns/web/"
cp -a "$ROOT/config/." "$PREFIX/share/shadowdns/config/"

if [[ ! -f /etc/shadowdns/env ]]; then
  install -m 600 "$ROOT/deploy/env.example" /etc/shadowdns/env
  TOKEN="$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | xxd -p)"
  sed -i "s/change-me-to-a-long-random-token/${TOKEN}/" /etc/shadowdns/env
  echo "[*] wrote /etc/shadowdns/env (mode 600) with random SD_API_TOKEN"
fi

if ! id shadowdns >/dev/null 2>&1; then
  useradd --system --home /nonexistent --shell /usr/sbin/nologin shadowdns || true
fi
chown -R shadowdns:shadowdns /var/log/shadowdns || true

if [[ -d /etc/systemd/system ]]; then
  install -m 644 "$ROOT/deploy/shadowdns.service" /etc/systemd/system/shadowdns.service
  systemctl daemon-reload || true
  echo "[*] systemd unit installed"
  echo "    sudo systemctl enable --now shadowdns"
fi

TOKEN_HINT="$(grep -E '^SD_API_TOKEN=' /etc/shadowdns/env 2>/dev/null | cut -d= -f2- || true)"
echo
echo "Lab mode (no install):"
echo "  export SD_API_TOKEN=\$(openssl rand -hex 16)"
echo "  ./shadowdns --token \"\$SD_API_TOKEN\""
echo "  open http://127.0.0.1:8089/?token=\$SD_API_TOKEN"
echo
if [[ -n "${TOKEN_HINT}" ]]; then
  echo "Installed dashboard: http://127.0.0.1:8089/?token=${TOKEN_HINT}"
fi
echo "Security notes: see SECURITY.md"

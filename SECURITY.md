# Security

ShadowDNS **v0.2.1** ships with secure defaults after a full audit hotfix.

## Defaults

| Setting | Default | Why |
|---------|---------|-----|
| Bind | `127.0.0.1` | No open recursive DNS / open dashboard |
| HTTP port | `8089` | Avoid collision with other local labs on 8088 |
| TLS verify | on (DoH/DoT/webhook) | Prevent MITM DNS hijack |
| API auth | optional `--token` / `SD_API_TOKEN` | Required when exposed |
| DNS clients | loopback only | Use `--allow-client CIDR` or `--open-resolver` |

## Hardening checklist

```bash
export SD_API_TOKEN="$(openssl rand -hex 16)"
./shadowdns --token "$SD_API_TOKEN" --dns-port 5353 --http-port 8089
# LAN expose (explicit):
./shadowdns --listen-all --token "$SD_API_TOKEN" --allow-client 192.168.0.0/16
```

- Prefer `SD_TELEGRAM_TOKEN` + `--telegram-chat` over `--telegram TOKEN:CHAT` (argv leak).
- JSONL is created mode `0600`.
- Mutating APIs (`/api/block`, `/api/fluxtap`) and intel APIs require token when set.
- CORS `*` removed; CSP + security headers enabled.
- HTTP concurrency capped; SSE auto-closes after 5 minutes.
- Webhook SSRF: private/link-local destinations blocked; HTTPS required unless `--insecure-tls`.

## Fixed in 0.2.1

- Unauthenticated remote policy mutation / intel dump (when bound openly)
- Missing TLS peer verification on DoH/DoT/webhooks
- `snprintf` length used as `memcpy` size (over-read)
- Unbounded unique-name table growth
- DNS labels > 63 accepted
- Static file symlink / size footguns
- Open recursive DNS by default

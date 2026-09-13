# Changelog

## 0.2.2 — 2026-09-13

### Security / ops
- Cap concurrent HTTP worker threads at **64** (atomic counter; excess → `429`)
- Confirm mutating POSTs (`/api/block`, `/api/fluxtap`) require `X-ShadowDNS-Token` / `?token=` when `--token` / `SD_API_TOKEN` is set; without a token, localhost-only bind remains the safe default

## 0.2.1 — 2026-09-13

Security hardening release — safe to leave running for lab use.

### Security
- Default bind `127.0.0.1` (no open recursive DNS / open dashboard)
- Default HTTP port `8089`
- Optional API token (`--token` / `SD_API_TOKEN`) on intel + mutating APIs
- TLS peer verification for DoH / DoT / HTTPS webhooks (`--insecure-tls` to opt out)
- Clamp `snprintf` lengths before `memcpy` / `write`
- DNS client ACL (loopback-only unless `--allow-client` / `--open-resolver`)
- Cap unique-name table; RFC DNS label length ≤ 63
- Static file jail (`realpath` + `O_NOFOLLOW` + size cap)
- HTTP connection cap + SSE max lifetime
- Webhook SSRF hardening (block private / link-local)
- JSONL created as `0600`
- Prefer telegram token file / env over argv
- Removed CORS `*`; added CSP + security headers

### Ops
- Graceful stop via signal flag (no eBPF join from signal handler)
- GitHub Actions CI (build + unit + fuzz + smoke)
- systemd unit + install script updated for secure defaults

## 0.2.0 — 2026-09-06

eBPF process truth, policy DSL, DoH/DoT upstreams, attack stories, FluxTap bridge, TUI, SARIF/JSONL/metrics.

## 0.1.0 — 2026-09-06

Initial DNS proxy + live dashboard + tunnel/telemetry detectors.

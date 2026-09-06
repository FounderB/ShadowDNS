<p align="center">
  <img src="assets/logo.svg" alt="ShadowDNS" width="120" height="120"/>
</p>

<h1 align="center">ShadowDNS</h1>

<p align="center">
  <strong>DNS leak &amp; C2 radar</strong> — see who phones home before it vanishes in the noise.
</p>

<p align="center">
  <img alt="C11" src="https://img.shields.io/badge/C-11-38bdf8?style=flat-square"/>
  <img alt="Linux" src="https://img.shields.io/badge/platform-Linux-0c1a24?style=flat-square"/>
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-5eead4?style=flat-square"/></a>
  <img alt="version" src="https://img.shields.io/badge/version-0.1.0-0d1520?style=flat-square&labelColor=5eead4&color=0d1520"/>
</p>

<p align="center">
  <a href="https://github.com/FounderB/FluxTap">FluxTap</a> ·
  <a href="https://github.com/FounderB/Tracefuse">Tracefuse</a> ·
  <a href="https://github.com/FounderB/Timeforge">Timeforge</a> ·
  <b>ShadowDNS</b>
</p>

---

## Why

Browsers, package managers, SDKs, malware, and “helpful” telemetry all speak DNS first.  
Wireshark shows packets. ShadowDNS shows **intent**:

| You see | You get |
|---------|---------|
| `api.segment.io` | telemetry tag + alert |
| 40-char hex subdomain | tunnel heuristic (CRIT) |
| `malware.example` | blocklist → NXDOMAIN |
| local dig / resolver | process attribution via `/proc` |

Live SSE dashboard. One binary. No cloud. No agents to babysit.

---

## Features

- **UDP DNS proxy** with upstream forward (Cloudflare / Google / custom)
- **Live radar UI** — severity, action, process, reason, one-click block
- **Tunnel heuristics** — long labels, entropy, hex-dense subdomains, TXT/NULL
- **Telemetry map** — phone-home domains from config + builtins
- **Block / alert / allow** lists with enforce or alert-only mode
- **Process attribution** on Linux (`/proc/net/udp` → pid/comm)
- **JSON + SSE API** for SOCs, scripts, and FluxTap-style pipelines

---

## Quick start

```bash
git clone https://github.com/FounderB/ShadowDNS.git
cd ShadowDNS
make
./shadowdns --dns-port 5353 --http-port 8088
```

Open **http://127.0.0.1:8088**

Probe it:

```bash
dig @127.0.0.1 -p 5353 example.com
dig @127.0.0.1 -p 5353 api.segment.io
dig @127.0.0.1 -p 5353 $(python3 -c 'print("a"*48)').tunnel.test
```

### Use as system resolver (careful)

```bash
sudo ./shadowdns --dns-port 53 --http-port 8088
# then point NetworkManager / resolv.conf at 127.0.0.1
```

Prefer a VM or temporary resolv.conf change while evaluating.

---

## CLI

```text
./shadowdns [options]

  --dns-port PORT       UDP listen port (default 5353)
  --http-port PORT      dashboard + API (default 8088)
  --bind HOST           bind address (default 0.0.0.0)
  --upstream IP         upstream resolver (repeatable)
  --blocklist FILE      domain blocklist
  --telemetry FILE      telemetry domains
  --allowlist FILE      never-block list
  --alert-only          detect, never NXDOMAIN-block
  --no-proc             skip process attribution
  --quiet               less stdout
```

---

## API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | liveness |
| `GET /api/stats` | counters |
| `GET /api/events?after=ID` | ring buffer snapshot |
| `GET /api/stream` | Server-Sent Events live feed |
| `GET /api/rules` | loaded rules |
| `POST /api/block` | `{"domain":"evil.com"}` runtime block |

---

## Detection sketch

```
query in
  ├─ allowlist?          → allow
  ├─ blocklist?          → BLOCK (NXDOMAIN if enforce)
  ├─ telemetry list?     → ALERT
  ├─ entropy / length?   → tunnel CRIT/HIGH
  ├─ TXT/NULL / risky TLD→ soft alert
  └─ else                → forward upstream + log
```

---

## Layout

```text
ShadowDNS/
├── src/           C11 core (dns, detect, proxy, http)
├── include/       public headers
├── web/           live dashboard
├── config/        block / telemetry / allow lists
├── assets/        brand
└── tests/         smoke test
```

---

## Security notes

ShadowDNS is a **local radar / policy point**, not a silver bullet.  
Tunnel heuristics can false-positive on CDN edge names — tune lists.  
Binding `:53` needs privileges; prefer non-root `5353` while developing.  
Process attribution is best-effort and may be empty for short-lived clients.

---

## License

MIT © FounderB

<p align="center">
  <img src="assets/logo.svg" alt="ShadowDNS" width="120" height="120"/>
</p>

<h1 align="center">ShadowDNS</h1>

<p align="center">
  <strong>DNS leak &amp; C2 radar</strong> — eBPF process truth, policy DSL, DoH/DoT upstreams, attack stories.
</p>

<p align="center">
  <img alt="C11" src="https://img.shields.io/badge/C-11-38bdf8?style=flat-square"/>
  <img alt="eBPF" src="https://img.shields.io/badge/eBPF-CO--RE-5eead4?style=flat-square"/>
  <img alt="Linux" src="https://img.shields.io/badge/platform-Linux-0c1a24?style=flat-square"/>
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-5eead4?style=flat-square"/></a>
  <img alt="version" src="https://img.shields.io/badge/version-0.2.1-0d1520?style=flat-square&labelColor=5eead4&color=0d1520"/>
  <img alt="secure" src="https://img.shields.io/badge/defaults-localhost%20%2B%20TLS%20verify-5eead4?style=flat-square"/>
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
ShadowDNS shows **who** phoned home, **why it looks bad**, and can **block** it.

| Signal | What you get |
|--------|----------------|
| eBPF sport→pid | process / cgroup / container id |
| tunnel / DGA / fast-flux | severity + tags |
| DoH/DoT bypass | CRIT when apps skip your resolver |
| policy DSL | `process=npm action=alert` |
| Attack Story | telemetry → tunnel → block, one timeline |
| FluxTap bridge | DNS name vs TLS SNI mismatch |

---

## Features (v0.2)

- **UDP DNS proxy** with **UDP / DoT / DoH** upstreams + **split horizon**
- **eBPF process truth** (`udp_sendmsg` map + DoH/DoT bypass ringbuf)
- **Policy DSL** (`config/policy.sd`)
- **Detectors**: tunnel, telemetry, DGA, newly-seen, NX spikes, fast-flux, risky TLDs
- **Attack stories** + live SSE dashboard
- **JSONL** append, **SARIF** export, **Prometheus** `/metrics`
- **Telegram / webhook** on HIGH/CRIT
- **TUI** (`--tui`), **systemd** unit, install script
- **Unit + fuzz** tests for DNS parsers / detect

---

## Quick start

```bash
git clone https://github.com/FounderB/ShadowDNS.git
cd ShadowDNS
make
export SD_API_TOKEN="$(openssl rand -hex 16)"
./shadowdns --token "$SD_API_TOKEN" --dns-port 5353 --http-port 8089
```

Dashboard: **http://127.0.0.1:8089/?token=$SD_API_TOKEN**

Secure defaults (v0.2.1): bind `127.0.0.1`, TLS verify on DoH/DoT, optional API token, DNS clients loopback-only.
See [SECURITY.md](SECURITY.md).

```bash
dig @127.0.0.1 -p 5353 example.com
dig @127.0.0.1 -p 5353 api.segment.io
```

### Real resolver modes

```bash
# DoT upstream (cert verified)
./shadowdns --upstream dot:1.1.1.1:853 --token "$SD_API_TOKEN"

# LAN expose (explicit)
./shadowdns --listen-all --token "$SD_API_TOKEN" --allow-client 192.168.0.0/16
```

eBPF needs privileges (`CAP_BPF` / root). Without them, ShadowDNS still runs with `/proc` attribution (`--no-ebpf`).

---

## Policy DSL

`config/policy.sd`:

```text
tag=tunnel action=block
process=npm action=alert
qname=*.onion action=block
tag=doh-bypass action=alert
severity=crit action=alert
```

## Split horizon

`config/split.conf`:

```text
*.corp.local = udp:10.0.0.53
*.sensitive.internal = dot:1.1.1.1:853
```

## FluxTap bridge

```bash
curl -X POST http://127.0.0.1:8088/api/fluxtap \
  -H 'content-type: application/json' \
  -d '{"sni":"evil.cdn","process":"curl","ja3":"..."}'
```

---

## API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | liveness |
| `GET /api/stats` | counters |
| `GET /api/events` | ring buffer |
| `GET /api/stories` | attack stories |
| `GET /api/stream` | SSE (`dns` + `story` events) |
| `GET /api/policy` | loaded DSL |
| `GET /api/sarif` | SARIF 2.1 export |
| `GET /metrics` | Prometheus |
| `POST /api/block` | runtime block |
| `POST /api/fluxtap` | SNI/JA3 ingest |

---

## CLI highlights

```text
--upstream udp:IP|dot:IP[:853]|doh:host[/path]
--policy FILE   --split FILE   --jsonl FILE
--webhook URL   --telegram TOKEN:CHAT
--tui           --no-ebpf      --alert-only
```

---

## Layout

```text
bpf/           CO-RE eBPF (process truth + bypass)
src/           C11 userspace
web/           live radar UI
config/        lists + policy + split
deploy/        systemd unit
scripts/       install + libbpf fetch
tests/         smoke / unit / fuzz
```

---

## License

MIT © FounderB

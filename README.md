# Accessyo (Go CLI)

**Stop guessing why your users can't connect - see it from their network.**

[![CI](https://github.com/tmszcncl/accessyo_go/actions/workflows/ci.yml/badge.svg)](https://github.com/tmszcncl/accessyo_go/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Work in progress.

🌐 [accessyo.com](https://accessyo.com)
📦 [GitHub repository](https://github.com/tmszcncl/accessyo_go)
📦 [npm CLI variant](https://www.npmjs.com/package/accessyo)
⬇️ [Download binaries (latest release)](https://github.com/tmszcncl/accessyo_go/releases/latest)

---

## What is Accessyo?

Accessyo is a network debugging CLI that shows *why* your users cannot connect - not just that something is down.

> "Your server is fine. Your users still fail."

Current monitoring tools see your servers. They do not see:

- ISP-level issues (Orange, Vodafone, Comcast)
- VPN / corporate proxy problems
- DNS resolution failures
- TLS handshake errors
- CDN edge routing issues
- Browser-level blocks (CORS, extensions)

Accessyo does.

---

## Status

The CLI is in active development. Currently supports:

- Network context (location/ISP/ASN + public IP; masked by default, full with `--debug`)
- DNS resolution (A, AAAA, CNAME records, TTL, resolver, split-horizon check vs 1.1.1.1)
- TCP connectivity check
- TLS handshake (protocol, cipher, certificate info + expiry, hostname match, HTTP/2 via ALPN)
- HTTP request (status, TTFB, redirects, IPv4/IPv6, browser UA comparison, CDN detection, WAF blocking, www/non-www canonical check, HSTS validation)
- Timings summary (per-check + total)
- Root cause diagnosis with actionable suggestions
- Batch mode - check multiple domains at once with per-domain warnings (HSTS, cert expiry, IPv6, split-horizon DNS, slow response)

Single domain (full detailed output):

```bash
go run ./cmd/accessyo example.com
```

Multiple domains (compact summary by default):

```bash
go run ./cmd/accessyo example.com api.example.com cdn.example.com
```

Download prebuilt binaries from GitHub Releases:

- https://github.com/tmszcncl/accessyo_go/releases
- https://github.com/tmszcncl/accessyo_go/releases/latest

Options:

```bash
--timeout <ms>   per-check timeout in milliseconds (default: 5000)
--json           output results as JSON
--debug          show full diagnostic details
```

```bash
go run ./cmd/accessyo example.com --json
go run ./cmd/accessyo example.com --debug
go run ./cmd/accessyo example.com --timeout 3000
```

## How diagnosis works

Accessyo runs checks in order:

1. DNS
2. TCP (port 443)
3. TLS handshake
4. HTTP request

Each step depends on the previous one. Example: if DNS fails, TCP/TLS/HTTP are skipped for that host.

At the end, Accessyo builds a summary with:

- overall status (`ok`)
- likely root cause (`problem`, `likelyCause`)
- actionable hints (`whatYouCanDo`)

## How to read output

- `✓ WORKING`: site is reachable
- `⚠ DEGRADED`: reachable, but quality/connectivity is degraded
- `✗ FAIL`: critical check failed (DNS/TCP/TLS/HTTP)
- `Warnings`: non-fatal issues (for example IPv6 failure, slow response, HSTS info)

## Default vs debug output

- Default output is safe to share:
  - public IP is masked
  - DNS resolver and full DNS record lists are hidden
  - HTTP headers are minimized (only `server`, when present)
- `--debug` shows full details:
  - full public IP
  - full DNS details (resolver, A/AAAA, resolver comparison, TTL)
  - TLS internals (protocol/cipher/ALPN/cert details)
  - full HTTP headers

Multi-domain behavior:

- default: compact table + totals
- `--debug`: full per-domain output (no compact table)

## JSON output (CI / integrations)

`--json` returns machine-readable output with no spinner/table formatting.

Single host:

```bash
go run ./cmd/accessyo example.com --json
```

Batch (multiple hosts):

```bash
go run ./cmd/accessyo example.com api.example.com cdn.example.com --json
```

Single output shape:

```json
{
  "host": "example.com",
  "timestamp": "2026-04-11T10:00:00Z",
  "checks": {
    "dns": { "ok": true, "durationMs": 12 },
    "tcp": { "ok": true, "durationMs": 30 },
    "tls": { "ok": true, "durationMs": 80 },
    "http": { "ok": true, "durationMs": 150, "statusCode": 200 }
  },
  "summary": {
    "ok": true,
    "problem": null,
    "likelyCause": null,
    "whatYouCanDo": [],
    "totalMs": 272
  }
}
```

Batch output is an array of the same objects.

Important fields:

- `checks.dns` / `checks.tcp` / `checks.tls` / `checks.http`: raw check data
- `summary.ok`: final pass/fail boolean for automation
- `summary.problem`: short root-cause label when failed
- `summary.likelyCause`: human-readable likely cause
- `summary.whatYouCanDo`: suggested next actions
- `summary.totalMs`: summed runtime across checks

CI examples:

```bash
# Fail pipeline when any host is not OK
go run ./cmd/accessyo example.com api.example.com --json | jq -e 'all(.[]; .summary.ok == true)'

# Print failing hosts only
go run ./cmd/accessyo example.com api.example.com --json | jq -r '.[] | select(.summary.ok != true) | .host'

# Fail only when TLS fails
go run ./cmd/accessyo example.com api.example.com --json | jq -e 'all(.[]; .checks.tls == null or .checks.tls.ok == true)'
```

Exit codes:

- `0` when all checked hosts are OK
- `1` when any checked host fails (single or batch, including `--json` mode)

Alternative command form (`diagnose`):

```bash
go run ./cmd/accessyo diagnose example.com
```

## Known limitations

- Some CDNs may rate-limit quick consecutive probes; IPv4/IPv6 quick checks can show timeout warnings.
- DNS comparison for split-horizon currently uses system resolver vs `1.1.1.1`.
- Results depend on your local network path (ISP, VPN, corporate proxy, firewall).

---

## Open source

Accessyo CLI is open source (MIT). The backend, dashboard, alerting, and root cause engine are proprietary.

This is an [open-core](https://en.wikipedia.org/wiki/Open-core_model) model.

---

## License

[MIT](LICENSE)

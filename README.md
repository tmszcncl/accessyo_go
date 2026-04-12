# Accessyo (Go CLI)

**Stop guessing why your users can't connect - see it from their network.**

[![CI](https://github.com/tmszcncl/accessyo_go/actions/workflows/ci.yml/badge.svg)](https://github.com/tmszcncl/accessyo_go/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Work in progress.

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

- Network context (public IP, country, DNS resolver)
- DNS resolution (A, AAAA, CNAME records, TTL, resolver)
- TCP connectivity check
- TLS handshake (protocol, cipher, certificate info + expiry, hostname match, HTTP/2 via ALPN)
- HTTP request (status, TTFB, redirects, IPv4/IPv6, browser UA comparison, CDN detection, WAF blocking, www/non-www canonical check, HSTS validation)
- Timings summary (per-check + total)
- Root cause diagnosis with actionable suggestions
- Batch mode - check multiple domains at once with per-domain warnings (HSTS, cert expiry, IPv6, slow response)

Single domain (full detailed output):

```bash
go run ./cmd/accessyo example.com
```

Multiple domains (compact summary + auto-details for failures):

```bash
go run ./cmd/accessyo example.com api.example.com cdn.example.com
```

Options:

```bash
--timeout <ms>   per-check timeout in milliseconds (default: 5000)
--json           output results as JSON
```

```bash
go run ./cmd/accessyo example.com --json
go run ./cmd/accessyo example.com --timeout 3000
```

Alternative command form (`diagnose`):

```bash
go run ./cmd/accessyo diagnose example.com
```

---

## Open source

Accessyo CLI is open source (MIT). The backend, dashboard, alerting, and root cause engine are proprietary.

This is an [open-core](https://en.wikipedia.org/wiki/Open-core_model) model.

---

## License

[MIT](LICENSE)

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

- DNS resolution (A + AAAA records, TTL placeholder, resolver info, CDN detection)
- TCP connectivity check
- TLS handshake (protocol, cipher, certificate info)
- HTTP request (status, redirects, key headers, basic block detection)

Run locally:

```bash
go run ./cmd/accessyo example.com
```

Alternative command form:

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

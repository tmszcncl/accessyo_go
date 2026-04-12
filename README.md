# Accessyo (Go CLI)

**Stop guessing why your users can't connect - see it from their network.**

[![CI](https://github.com/tmszcncl/accessyo_go/actions/workflows/ci.yml/badge.svg)](https://github.com/tmszcncl/accessyo_go/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Work in progress. First scaffold commit.

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

This repository is in early development. Current scope is project scaffold only:

- Go module + CLI entrypoint
- GitHub Actions CI
- Tag-based binary release workflow
- Project structure for upcoming network checks

Functional diagnostics are being built in the next commits.

---

## Open source

Accessyo CLI is open source (MIT). The backend, dashboard, alerting, and root cause engine are proprietary.

This is an [open-core](https://en.wikipedia.org/wiki/Open-core_model) model.

---

## License

[MIT](LICENSE)

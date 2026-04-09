# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust backend for the Keylime Monitoring Dashboard -- a web-based security operations platform providing centralized monitoring, management, and compliance capabilities for [Keylime](https://keylime.dev/) remote attestation infrastructure. It consumes Keylime's existing Verifier and Registrar REST APIs (v2 pull-mode and v3 push-mode) via mTLS without modifying Keylime components.

The full SRS (69 FRs, 23 NFRs, 29 SRs with Gherkin acceptance criteria) lives in the sibling repo at `../keylime-webtool-doc/spec/SRS-Keylime-Monitoring-Tool.md`.

## Tech Stack

- **Language:** Rust with `#![forbid(unsafe_code)]` (SR-023)
- **Framework:** Axum (async HTTP/WebSocket)
- **Runtime:** Tokio
- **Database:** TimescaleDB (time-series attestation history/metrics)
- **Cache:** Redis with tiered TTLs (agent list 10s, detail 30s, policies 60s, certs 300s)
- **Keylime comms:** mTLS via rustls, private keys in HSM/Vault (never cleartext on disk)
- **Auth:** OIDC/SAML + short-lived JWT (15 min) with refresh rotation
- **Frontend:** React.js + TypeScript SPA (separate repo: `keylime-webtool-frontend`)

## Build Commands

```bash
cargo build              # dev build
cargo build --release    # release build
cargo test               # run all unit tests
cargo test <test_name>   # run a single test
cargo clippy -- -D warnings   # lint (treat warnings as errors)
cargo fmt                # format code
cargo fmt -- --check     # check formatting without modifying
cargo run                # run dev server
```

## Mockoon Integration Tests

Integration tests use [Mockoon](https://mockoon.com/) to simulate Keylime Verifier (port 3000) and Registrar (port 3001) APIs. Mock data is in `test-data/`.

```bash
# Automated: starts mocks, runs tests, cleans up
bash tests/mockoon_tests.sh

# Manual: start mocks, then run tests with the mockoon feature flag
mockoon-cli start --data test-data/verifier.json --port 3000 &
mockoon-cli start --data test-data/registrar.json --port 3001 &
MOCKOON_VERIFIER=1 MOCKOON_REGISTRAR=1 cargo test --features mockoon test_mockoon -- --nocapture
pkill -f mockoon-cli
```

The mock fleet has 3 agents: healthy (GET_QUOTE), failed (FAILED), and push-mode (PROVIDE_V). Tests are gated behind `#[cfg(feature = "mockoon")]` and env vars `MOCKOON_VERIFIER`/`MOCKOON_REGISTRAR`.

Alternatively, open `test-data/verifier.json` and `test-data/registrar.json` in the Mockoon desktop app, start both environments, then run the tests from a terminal. The GUI shows live request logs for debugging.

## Architecture

### System Layers

```
Browser (React SPA) --TLS 1.3--> Backend (this repo) --mTLS--> Keylime Verifier/Registrar APIs
                                      |          |
                                      v          v
                                  TimescaleDB   Redis
```

### Backend Responsibilities

1. **Fleet Monitoring** -- KPI computation (active/failed agents, success rate, latency), real-time WebSocket push with HTTP polling fallback
2. **Agent Management** -- sortable/filterable fleet list, agent detail with 6 tabs (Timeline, PCR Values, IMA Log, Boot Log, Certificates, Raw Data), bulk operations
3. **Attestation Analytics** -- failure categorization by type/severity, cross-agent correlation, root cause suggestions, policy rollback
4. **Policy Management** -- IMA and measured boot policy CRUD with versioning, impact analysis, two-person approval (drafter != approver)
5. **Certificate Management** -- unified view (EK, AK, IAK, IDevID, mTLS, server certs), tiered expiry alerts (30-day window)
6. **Security Audit** -- tamper-evident hash-chained audit logging with RFC 3161 anchoring, RBAC enforcement
7. **Integrations** -- SIEM (Syslog CEF/LEEF, Splunk HEC, Elastic Common Schema), Prometheus metrics, OpenTelemetry traces

### RBAC Model (Three-tier)

| Role | Capabilities |
|------|-------------|
| Viewer | Read-only across all modules |
| Operator | Read + write (agents, policies as draft) |
| Admin | Full access + policy approval + config + MFA required |

### Key Performance Requirements

- 10K concurrent WebSocket connections, <100ms p99 latency (NFR-005)
- KPI refresh within 30 seconds (NFR-001)
- Event-driven ingestion primary, polling fallback for ~1K agents (NFR-006/007)
- Max 5 parallel concurrent log fetches to Verifier API (NFR-023)
- Circuit breaker on Verifier API latency (NFR-017)
- Active/Passive HA with <30s RTO, 0 RPO (NFR-010)

### Security Constraints

- `#![forbid(unsafe_code)]` on the crate (SR-023)
- Never cache/store/log raw TPM quotes, IMA logs, boot logs, PoP tokens (SR-013/014)
- mTLS private keys never stored on disk in cleartext -- use HSM or Vault (SR-005/006)
- TLS 1.3 minimum for browser connections, TLS 1.2+ for Keylime API (SR-008/009)
- Signed cache entries with TTLs to mitigate cache poisoning (SR-024)
- SSRF protection on webhook URLs -- allowlist, block RFC 1918 (SR-016)
- Audit log retention >= 1 year (SR-026)

## License

Apache-2.0

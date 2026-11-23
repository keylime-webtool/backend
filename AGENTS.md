# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

Rust backend for the Keylime Monitoring Dashboard — a security operations platform for [Keylime](https://keylime.dev/) remote attestation infrastructure. It consumes Keylime Verifier and Registrar REST APIs (v2 pull-mode, v3 push-mode) via mTLS without modifying Keylime components.

- The full SRS lives in the sibling repo `../keylime-webtool-doc/spec/SRS-Keylime-Monitoring-Tool.md`.
- Implementation status and remaining stubs are tracked in [PENDING.md](PENDING.md) — consult it before starting work.
- [CLAUDE.md](CLAUDE.md) contains extended architecture context (RBAC model, performance/security requirements).

## Commands

```bash
cargo build                    # dev build
cargo test                     # unit tests
cargo test <test_name>         # single test
cargo clippy -- -D warnings    # lint (warnings are errors)
cargo fmt                      # format code
cargo fmt -- --check           # check formatting only
cargo run                      # run dev server (listens on :8080)
```

### Full verification (mirrors CI)

```bash
bash scripts/pre-commit.sh            # fmt + clippy + strict build + tests + audit + machete + shellcheck
bash scripts/pre-commit.sh --quick    # skip slow checks (audit, machete, coverage)
bash scripts/verify.sh                # pre-commit checks + coverage + signed-commit check
```

Prefer running `bash scripts/pre-commit.sh --quick` before declaring work done; run the full suite before commits.

### Integration tests (Mockoon)

```bash
bash tests/mockoon_tests.sh           # automated: starts mocks, runs tests, cleans up
```

Manual: start Mockoon mocks (verifier on :3000, registrar on :3001), then:

```bash
MOCKOON_VERIFIER=1 MOCKOON_REGISTRAR=1 cargo test --features mockoon test_mockoon -- --nocapture
```

End-to-end curl tests: `bash tests/curl_integration_test.sh` (requires mockoon-cli and jq).

## Architecture

```
Browser (React SPA, separate repo) --TLS--> Backend (this repo) --mTLS--> Keylime Verifier/Registrar
                                                |            |
                                                v            v
                                          TimescaleDB     Redis
```

### Source layout

- `src/api/` — Axum routes, handlers, middleware, WebSocket (`ws.rs`), response envelope
- `src/keylime/` — Keylime API client, v2/v3 models, X.509 cert parser
- `src/models/` — domain types (agents, alerts, policies, attestations, certificates, KPIs)
- `src/repository/` — repository traits + SQLite implementations (`repository_tests.rs` holds shared trait tests)
- `src/storage/` — DB pool and Redis cache (not yet wired into `AppState`)
- `src/auth/` — OIDC, JWT, sessions, RBAC (three-tier: Viewer / Operator / Admin)
- `src/audit/` — hash-chained tamper-evident audit logger
- `src/tasks/` — background tasks (observations)
- `src/state.rs` — `AppState` composition
- `tests/` — Mockoon integration tests and shell-based e2e tests
- `test-data/` — Mockoon mock environments (verifier :3000, registrar :3001) defining a 7-agent mock fleet
- `scripts/` — pre-commit, verify, and signed-commit check scripts

### Key behaviors

- Dev/test database is SQLite via `DATABASE_URL` (`sqlite::memory:` or `sqlite://./file.db`); unset means in-memory repositories. Schema auto-creates on startup. See [docs/TESTING_WITH_SQLITE.md](docs/TESTING_WITH_SQLITE.md).
- Keylime endpoints come from `KEYLIME_VERIFIER_URL` / `KEYLIME_REGISTRAR_URL` (defaults `http://localhost:3000` / `http://localhost:3001`).
- Policies come from Keylime `GET /v2/allowlists/` (IMA) and `GET /v2/mbpolicies/` (measured boot).

## Coding Conventions

- `#![forbid(unsafe_code)]` is crate-wide (SR-023) — never introduce `unsafe`.
- CI compiles with `RUSTFLAGS="-D warnings"` and strict clippy (`--all-features --all-targets`); code must be warning-free.
- Keep `Cargo.toml`'s `[package.metadata.cargo-machete]` ignored-dependency list in sync: remove entries as scaffolded modules get implemented.
- Follow Clean Code / SOLID principles; use repository traits to keep storage swappable (SQLite now, TimescaleDB later).
- Error handling uses `thiserror` in `src/error.rs`; avoid `unwrap()`/`expect()` in production code paths.
- Tests are gated behind `#[cfg(feature = "mockoon")]` plus `MOCKOON_VERIFIER`/`MOCKOON_REGISTRAR` env vars.

## Security Constraints (do not violate)

- Never cache, store, or log raw TPM quotes, IMA logs, boot logs, or PoP tokens (SR-013/014).
- mTLS private keys never on disk in cleartext — HSM or Vault only (SR-005/006).
- SSRF protection on webhook URLs: allowlist, block RFC 1918 (SR-016).
- Signed cache entries with TTLs to mitigate cache poisoning (SR-024).

## Commits

- Sign every commit (`git commit -s`); the `commit-msg` hook and CI enforce `Signed-off-by:`.
- Use kebab-case branch names; avoid prefixes "up", "or", "ma" (e.g. use "modify" not "update").
- Do not include issue or PR numbers in commit messages — GitHub appends them on merge.
- Never push unless explicitly asked.
- Install local hooks once per clone: `git config core.hooksPath .githooks`.

## Documentation

- Update `README.md` when commands, endpoints, or setup change.
- Update `PENDING.md` when implementing a stub or wiring infrastructure.

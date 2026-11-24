## Pending Implementation -- Keylime Webtool Backend

### Current Status: ~73% of route handlers fully implemented (57/78)

Of the 78 HTTP route handlers registered in `src/api/routes.rs`:

- **57 fully implemented**
- **17 stubs** returning `500 not implemented` (auth, policy CRUD, incidents, alert notifications/thresholds, compliance export)
- **4 placeholders** returning valid JSON with `"status": "not_configured"` (see section 6)
- **1 WebSocket handler** that is an echo-only skeleton (section 7)

Infrastructure wiring is done: repository traits (#79), SQLite persistence (#80),
Redis cache, the background observation loop (#87), and the audit recording
service are all live in `AppState` (`src/state.rs:24-35`) and `main.rs`
(`src/main.rs:69-121`). The remaining work is auth enforcement,
repository-layer stubs, and the feature handlers that depend on them.

Last refreshed: 2026-11-24 (at PR #158; previous refresh was PR #22).

---

### 0. Shipped since the last refresh (for context, no action needed)

- **Repository abstraction + SQLite backend** (#79, #80) — traits in `src/repository/`,
  SQLite implementations in `src/repository/sqlite/`, selected via `DATABASE_URL`,
  in-memory fallback when unset; schema auto-creates on startup; alert seeding (#93)
- **Redis cache wired** — via `REDIS_URL` with in-memory fallback (`src/main.rs:90-102`)
- **Background observation loop** (FR-087, #87) — records attestation observations every
  tick plus a 10-tick fleet reconciliation sweep (`src/tasks/observations.rs`)
- **mTLS client** (#34) — reqwest client built with client identity + CA cert
  (`src/keylime/client.rs:96-138`); rejects `pkcs11://`/`vault://` key URIs (SR-005/006 caveat below)
- **Settings API + TOML persistence** (#36) — runtime Verifier/Registrar URLs and mTLS
  config via `/api/settings/*`, persisted to a TOML config file (`src/api/handlers/settings.rs`)
- **SSH reachability probe** (FR-086, #69) — `/api/integrations/ssh-check/{service_name}`
- **X.509 certificate parsing** (#73) — subject/issuer/validity/SAN parsing plus
  PEM/DER download routes (`src/keylime/cert_parser.rs`, `src/api/handlers/certificates.rs`)
- **Policy impact analysis** (FR-038) — implemented at `src/api/handlers/policies.rs:186`,
  unlike the CRUD handlers around it
- **Audit Log API** (FR-042/043/061) — the 3 audit handlers are wired to the
  existing `AuditRepository` (`src/api/handlers/audit.rs`): filterable/paginated
  event list, hash-chain verification (409 + broken entry id on tamper), and
  CSV/JSON export with attachment headers. A new `AuditService`
  (`src/audit/service.rs`) owns the chain tip, resumes it from the persisted
  SQLite tip on startup, and records entries from mutating handlers (settings
  updates → `config_change`, alert lifecycle actions → `alert_action`,
  SSH probes → `integration_check`; actor is `"system"` until SR-001 auth lands).
  Known frontend delta (SDD is the contract): `keylime-webtool-frontend` calls
  `GET /audit-log/verify-chain`, `POST /audit-log/export`, and uses
  `from_date`/`to_date`/`per_page` — the backend serves `GET /verify`,
  `GET /export`, `start`/`end`, `page_size` per SDD section 3.4; the frontend
  needs a follow-up alignment
- Circuit-breaker state on the Verifier client, push-mode/Timeout agent states,
  unified performance summary endpoint (#94)

---

### 1. Authentication & Authorization (4 stub handlers + enforcement gap)

| Handler | File | Requirement |
|---|---|---|
| `login()` | `src/api/handlers/auth.rs:10` | SR-001 -- OIDC login flow |
| `callback()` | `src/api/handlers/auth.rs:30` | SR-001/010 -- Auth code -> JWT |
| `refresh_token()` | `src/api/handlers/auth.rs:42` | SR-010 -- JWT refresh rotation |
| `logout()` | `src/api/handlers/auth.rs:48` | SR-011 -- Session revocation |

Plus 3 TODOs in `src/auth/oidc.rs:19-21` (authorization URL, code exchange, userinfo/role mapping).

**Enforcement gap (SR-001/010/011):** `require_auth`/`require_admin` middleware exists in
`src/api/middleware.rs` but is never applied to any route group. The only guarded route is
`/api/integrations/ssh-check/{service_name}` via `require_write`
(`src/api/routes.rs:211-214`). All other endpoints — including mutating ones like policy
updates and alert actions — are currently unauthenticated.

Related blockers:

- JWT secret is hardcoded to `b"placeholder"` (`src/api/middleware.rs:19-20`, TODO: get secret from app state)
- `SessionStore` (`src/auth/session.rs`) is fully implemented but wired nowhere —
  `src/api/middleware.rs:23` still has the TODO for session revocation checking

---

### 2. Alert Management (2 stub handlers + missing automatic generation)

Alert lifecycle (list/get/acknowledge/investigate/resolve/dismiss/escalate) is implemented
against `AlertRepository` (SQLite with `seed_if_empty`, or in-memory). Remaining work:

| Handler | File | Requirement |
|---|---|---|
| `list_notifications()` | `src/api/handlers/alerts.rs:155` | FR-009 -- in-app notification bell with badge count |
| `update_thresholds()` | `src/api/handlers/alerts.rs:171` | FR-011 -- configurable alert thresholds (Admin only) |

#### Pending: Automatic alert generation for down systems

No alerts are currently raised automatically. `ServiceDown` exists only as an enum variant
(`src/models/alert.rs:33`) — no code path constructs or raises it. The background
observation loop (`src/tasks/observations.rs`) records attestation observations but never
creates alerts. Required scenarios:

| Alert Condition | Alert Type | Severity | Requirement |
|---|---|---|---|
| **Verifier unreachable** -- backend cannot connect to Keylime Verifier API | `service_down` | CRITICAL | FR-046 |
| **Registrar unreachable** -- backend cannot connect to Keylime Registrar API | `service_down` | CRITICAL | FR-046 |
| **Backend unreachable** -- frontend cannot reach the backend API (frontend-side detection needed, not backend) | N/A (frontend) | CRITICAL | FR-046 |
| **All revocation channels unavailable** -- webhook, ZeroMQ, and REST notification channels all failing | `service_down` | CRITICAL | FR-046 |
| **Webhook delivery failure** -- revocation notification webhook returns error / times out | `service_down` | WARNING | FR-046 |

Implementation approach:

- Extend the existing background observation loop (or the Verifier circuit breaker) to
  detect Verifier/Registrar unreachability and insert/resolve `service_down` alerts in
  `AlertRepository` (FR-049 auto-resolve on recovery)
- For **backend unreachable**, detection must happen in the frontend (axios interceptor or
  WebSocket disconnect handler) since the backend cannot observe its own downtime

#### Pending: Alert generation from attestation failures

Alerts should be created automatically when agents fail attestation:

| Alert Condition | Alert Type | Severity | Requirement |
|---|---|---|---|
| Agent attestation quote invalid | `attestation_failure` | CRITICAL | FR-025/047 |
| Agent IMA policy violation | `policy_violation` | CRITICAL | FR-025/047 |
| Agent consecutive failures exceed threshold | `attestation_failure` | WARNING | FR-011/047 |
| Certificate approaching expiry (≤30 days) | `cert_expiry` | WARNING | FR-051 |
| Certificate critical expiry (≤7 days) | `cert_expiry` | CRITICAL | FR-051 |
| PCR value change detected | `pcr_change` | INFO | FR-021/022 |

#### Persistence caveat

When `DATABASE_URL` is unset the in-memory `AlertRepository` is used and all alerts are
lost on restart. With `DATABASE_URL=sqlite:...` alerts persist. The alert thresholds
themselves have no persistence (blocked by `update_thresholds` stub above).

---

### 3. Policy Management (7 stub handlers + repository-layer stubs)

| Handler | File | Requirement |
|---|---|---|
| `create_policy()` | `src/api/handlers/policies.rs:147` | FR-034 |
| `update_policy()` | `src/api/handlers/policies.rs:160` | FR-034/039 |
| `delete_policy()` | `src/api/handlers/policies.rs:165` | Admin only |
| `list_versions()` | `src/api/handlers/policies.rs:170` | FR-035 -- version history |
| `diff_versions()` | `src/api/handlers/policies.rs:175` | FR-035 -- version diff |
| `rollback_policy()` | `src/api/handlers/policies.rs:182` | FR-035 -- rollback |
| `approve_change()` | `src/api/handlers/policies.rs:243` | FR-039 -- two-person approval |

Implemented and working: `list_policies`, `get_policy`, `assignment_matrix` (FR-037),
and `impact_analysis` (FR-038, `policies.rs:186`).

**Blocked by repository-layer stubs** — versioning is not implemented in either backend:

| Repository method | In-memory | SQLite |
|---|---|---|
| `list_versions()` | `src/repository/policy.rs:97` | `src/repository/sqlite/policy.rs:178` |
| `diff()` | `src/repository/policy.rs:101` | `src/repository/sqlite/policy.rs:182` |
| `rollback()` | `src/repository/policy.rs:105` | `src/repository/sqlite/policy.rs:186` |

Note: these handlers also need to write through to Keylime (`POST/PUT/DELETE` on
`/v2/allowlists/` and `/v2/mbpolicies/`), not just the local repository, to have real effect.

---

### 4. Attestation Incidents & Pipeline (3 stub handlers + repository-layer stubs)

| Handler | File | Requirement |
|---|---|---|
| `list_incidents()` | `src/api/handlers/attestations.rs:299` | FR-026/027 -- correlated incidents |
| `get_incident()` | `src/api/handlers/attestations.rs:306` | FR-027 -- root cause detail |
| `rollback_from_incident()` | `src/api/handlers/attestations.rs:311` | FR-028 -- one-click rollback |

Repository-layer state (blocks the handlers above):

- **In-memory** (`src/repository/attestation.rs`): `get_pipeline` (:206),
  `correlate_incidents` (:223), and `get_incident` (:227) are all stubs
- **SQLite** (`src/repository/sqlite/attestation.rs`): `get_pipeline` (:141) is a stub;
  `correlate_incidents` (:161) and `get_incident` (:169) read from the
  `correlated_incidents` table — but nothing ever writes to that table, since no
  correlation engine exists yet

---

### 5. Compliance Export (1 stub handler)

| Handler | File | Requirement |
|---|---|---|
| `export_report()` | `src/api/handlers/compliance.rs:126` | FR-060 -- PDF/CSV export |

---

### 6. Placeholder Handlers (return `not_configured`, not errors)

These return valid JSON with placeholder data:

- `database_metrics()` -- `src/api/handlers/performance.rs:89-98` (FR-065 -- DB pool
  monitoring; reports zeroed metrics until a real pool is observed)
- `durable_backends()` -- `src/api/handlers/integrations.rs:166-177` (FR-058). Note the
  response content is stale: it reports Redis as "integration pending" although the Redis
  cache is wired via `REDIS_URL`
- `revocation_channels()` -- `src/api/handlers/integrations.rs:180-194` (FR-046)
- `siem_status()` -- `src/api/handlers/integrations.rs:197-203` (FR-063)

---

### 7. WebSocket (echo skeleton only)

`src/api/ws.rs:20-27` has 4 TODOs:

- Authentication on connect
- Event channel subscriptions (KPI, agents, alerts, policies)
- Heartbeat/ping-pong
- Subscription message parsing

Currently every text message is echoed back. Required for NFR-005 (10K concurrent
connections, <100ms p99) and NFR-021 (real-time UI updates).

---

### 8. Routes & Infrastructure TODOs

- **Prometheus `/metrics` endpoint** -- TODO at `src/api/routes.rs:17` (FR-063)
- **CORS / tracing / rate-limiting layers** -- TODO at `src/api/routes.rs:18`
- **TimescaleDB** (FR-058 durable attestation backend) — SQLite has effectively replaced
  TimescaleDB as the persistence backend (#80). What remains true: `src/storage/db.rs`
  (PgPool wrapper) is now dead code — referenced nowhere outside `src/storage/` — and the
  migrations TODO at `src/storage/db.rs:36` is still open. Decide whether to keep
  TimescaleDB as the durable backend or remove the module
- **mTLS HSM/Vault keys** (SR-005/006) — `src/keylime/client.rs:97-101` rejects
  `pkcs11://` and `vault://` key URIs; only file-based PEM identities are supported
- **Dead code cleanup** — `src/models/alert_store.rs` (the pre-repository in-memory
  `AlertStore`) is unused since #79/#80 and can be removed

---

### Suggested Implementation Order

1. **AuthN/AuthZ enforcement** — real JWT secret + apply `require_auth`/RBAC middleware
   to route groups (SR-001/010/011). Every mutating endpoint is currently unguarded;
   this gates all write-path features below
2. **OIDC login flow** — implement `src/auth/oidc.rs` + the 4 auth handlers, wire
   `SessionStore` for revocation (SR-011)
3. **Policy repository versioning** — `list_versions`/`diff`/`rollback` in both repo
   backends, then the 7 policy handlers with Keylime write-through (FR-034/035/039)
4. **Automatic alert generation** — extend the observation loop to raise/resolve
   `service_down` and attestation-failure alerts in `AlertRepository` (FR-046/047/049)
5. **Alert notifications & thresholds** — `list_notifications` + `update_thresholds`
   handlers with threshold persistence (FR-009/011)
6. **Incident correlation** — repository `correlate_incidents`/`get_incident`/`get_pipeline`,
   a writer for the `correlated_incidents` table, then the 3 incident handlers
   (FR-026/027/028)
7. **WebSocket event streaming** — auth, subscriptions, heartbeat; includes alert push
   (NFR-005/021)
8. **Remaining stubs & placeholders** — compliance export (FR-060), `database_metrics`
   (FR-065), durable backends / revocation channels / SIEM status (FR-058/046/063)
9. **Routes & infra polish** — `/metrics`, CORS/tracing/rate limiting, TimescaleDB
   decision, HSM/Vault key support

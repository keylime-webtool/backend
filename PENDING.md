## Pending Implementation -- Keylime Webtool Backend

### Current Status: ~77% of backend functions implemented (53/71 handlers)

---

### 1. Infrastructure Wiring (foundational -- blocks many features)

These are not yet connected in `AppState` or `main.rs`, even though modules exist:

- **Database (TimescaleDB)** -- `src/storage/db.rs` has connection pool setup but no migrations directory, and DB is not wired into `AppState`
- **Redis Cache** -- `src/storage/cache.rs` is fully implemented but not wired into `AppState`
- **Session Store** -- `src/auth/session.rs` is implemented but not wired
- **Audit Logger** -- `src/audit/logger.rs` is implemented (hash chain, tamper detection) but not wired
- **Middleware** -- `src/api/middleware.rs` has TODOs for JWT secret retrieval and session revocation checking
- **CORS / Tracing / Rate Limiting** -- noted as TODO in `src/api/routes.rs:14-15` (needs `tower-http`)
- **Prometheus `/metrics` endpoint** -- TODO in `src/api/routes.rs:14`
- **mTLS client** -- `src/keylime/client.rs:98` has a TODO for building the mTLS reqwest client when `config.mtls` is set

---

### 2. Authentication (4 stub handlers + 3 OIDC TODOs)

| Handler | File | Requirement |
|---|---|---|
| `login()` | `auth.rs:8` | SR-001 -- OIDC login flow |
| `callback()` | `auth.rs:25` | SR-001/010 -- Auth code -> JWT |
| `refresh_token()` | `auth.rs:38` | SR-010 -- JWT refresh rotation |
| `logout()` | `auth.rs:43` | SR-011 -- Session revocation |

Plus 3 TODOs in `src/auth/oidc.rs:19-21` (authorization URL, code exchange, userinfo/role mapping).

---

### 3. Alert Management (7 stub handlers -- entirely unimplemented)

| Handler | File | Requirement |
|---|---|---|
| `list_alerts()` | `alerts.rs:11` | FR-047 |
| `acknowledge_alert()` | `alerts.rs:16` | FR-047 |
| `investigate_alert()` | `alerts.rs:21` | FR-047 |
| `resolve_alert()` | `alerts.rs:31` | FR-047 |
| `dismiss_alert()` | `alerts.rs:39` | FR-047 |
| `list_notifications()` | `alerts.rs:44` | FR-009 |
| `update_thresholds()` | `alerts.rs:57` | FR-011 |

---

### 4. Policy Management (6 stub handlers)

| Handler | File | Requirement |
|---|---|---|
| `create_policy()` | `policies.rs:112` | FR-034 |
| `update_policy()` | `policies.rs:124` | FR-034/039 |
| `delete_policy()` | `policies.rs:132` | Admin only |
| `list_versions()` | `policies.rs:137` | FR-035 -- version history |
| `diff_versions()` | `policies.rs:142` | FR-035 -- version diff |
| `rollback_policy()` | `policies.rs:147` | FR-035 -- rollback |
| `approve_change()` | `policies.rs:192` | FR-039 -- two-person approval |

---

### 5. Audit Log API (3 stub handlers)

| Handler | File | Requirement |
|---|---|---|
| `list_audit_events()` | `audit.rs:22` | FR-042/043 |
| `verify_chain()` | `audit.rs:29` | FR-061 |
| `export_audit_log()` | `audit.rs:34` | FR-042 |

Note: the underlying `AuditLogger` with hash chain is already implemented -- these handlers just need to call it.

---

### 6. Attestation Incidents (3 stub handlers)

| Handler | File | Requirement |
|---|---|---|
| `list_incidents()` | `attestations.rs:133` | FR-026/027 -- correlated incidents |
| `get_incident()` | `attestations.rs:138` | FR-027 -- root cause detail |
| `rollback_from_incident()` | `attestations.rs:145` | FR-028 -- one-click rollback |

---

### 7. Remaining Stubs (3 handlers across different areas)

| Handler | File | Requirement |
|---|---|---|
| `renew_certificate()` | `certificates.rs:136` | FR-053 -- cert renewal |
| `export_report()` | `compliance.rs:112` | FR-060 -- PDF/CSV export |
| `database_metrics()` | `performance.rs:31` | FR-065 -- DB pool monitoring |

---

### 8. WebSocket (skeleton only)

`src/api/ws.rs:18-25` has 4 TODOs:
- Authentication on connect
- Event channel subscriptions
- Heartbeat/ping-pong
- Subscription message parsing

Required for NFR-005 (10K concurrent connections) and NFR-021 (real-time UI updates).

---

### 9. Integration Stubs (returning `not_configured`)

These handlers exist and return valid JSON, but with placeholder data:
- `durable_backends()` -- `integrations.rs:59` (FR-058)
- `revocation_channels()` -- `integrations.rs:73` (FR-046)
- `siem_status()` -- `integrations.rs:90` (FR-063)

---

### Suggested Implementation Order

1. **Infrastructure wiring** -- DB + cache + session + audit in `AppState` + middleware
2. **Authentication** -- OIDC flow + JWT middleware (unblocks RBAC enforcement)
3. **Policy CRUD** -- create/update/delete/versioning (needs DB)
4. **Alert management** -- full lifecycle (needs DB)
5. **Audit log API** -- wire existing logger to handlers (needs DB)
6. **Attestation incidents** -- correlation + root cause (needs DB for history)
7. **WebSocket** -- real-time event streaming
8. **Remaining stubs** -- cert renewal, compliance export, DB metrics

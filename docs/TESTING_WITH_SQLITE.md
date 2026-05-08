# Testing with SQLite

The backend supports SQLite as a lightweight database for development and testing.
No configuration files or flags are needed -- the presence of `DATABASE_URL` is the only signal.

## Quick start

### In-memory (ephemeral, fastest)

```bash
DATABASE_URL=sqlite::memory: cargo run
```

Data lives only while the process is running. Each restart starts fresh.

### File-based (persists across restarts)

```bash
DATABASE_URL=sqlite://./keylime-dev.db cargo run
```

The database file is created automatically on first run. Data survives restarts.

### Default (no database)

```bash
cargo run
```

Uses in-memory repositories with no database at all. This is the default and matches
the behavior before SQLite support was added.

## Running tests against SQLite

All SQLite repository tests use `sqlite::memory:` internally -- no env var needed:

```bash
cargo test
```

The SQLite tests are integrated into the standard test suite alongside the
in-memory repository tests.

## Schema

Tables are auto-created on startup (`CREATE TABLE IF NOT EXISTS`). No migration
tool is needed.

| Table | Purpose |
|-------|---------|
| `alerts` | Alert lifecycle and state machine |
| `policies` | IMA and measured boot policies |
| `policy_changes` | Two-person approval workflow (SR-018) |
| `audit_entries` | Tamper-evident hash-chained audit log |
| `attestation_results` | Attestation outcome records |
| `correlated_incidents` | Cross-agent failure correlation |

## Inspecting a file-based database

```bash
sqlite3 keylime-dev.db
```

```sql
.tables                          -- list all tables
.schema alerts                   -- show CREATE TABLE for alerts
SELECT count(*) FROM alerts;     -- count alert rows
SELECT id, severity, state FROM alerts;
```

## Type conventions

| Rust type | SQLite storage | Notes |
|-----------|---------------|-------|
| `Uuid` | `TEXT` | Hyphenated lowercase (`550e8400-...`) |
| `DateTime<Utc>` | `TEXT` | RFC 3339 (`2024-01-15T10:30:00+00:00`) |
| Enums | `TEXT` | serde_json lowercase (`"critical"`, `"new"`) |
| `Vec<T>` | `TEXT` | JSON array (`["agent-1","agent-2"]`) |
| `bool` | `INTEGER` | 0 = false, 1 = true |

## Limitations vs production Postgres

- No TimescaleDB hypertables or continuous aggregates
- No `JSONB` -- JSON stored as plain `TEXT` (no indexed queries on JSON fields)
- No native UUID type -- stored as `TEXT`
- Single-writer concurrency (WAL mode enabled for concurrent reads)
- Timeline aggregation uses `strftime()` instead of `date_trunc()`
- No connection pooling benefits at SQLite scale
- `list_versions()`, `diff()`, `rollback()` are not implemented (return error)

## Environment variable reference

| Variable | Effect |
|----------|--------|
| (unset) | In-memory repositories, no database |
| `DATABASE_URL=sqlite::memory:` | SQLite in-memory database |
| `DATABASE_URL=sqlite://./path.db` | SQLite file-based database |
| `DATABASE_URL=postgres://...` | Not yet implemented, falls back to in-memory |
| `REDIS_URL=redis://...` | Redis cache (independent of database choice) |

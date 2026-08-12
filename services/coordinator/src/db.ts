/**
 * §40 — operational state.
 *
 * DEVIATION FROM SPEC, STATED PLAINLY: the spec calls for PostgreSQL + Neo4j.
 * This prototype uses node:sqlite (built into Node 22) so `pnpm dev` runs the
 * whole demo with no Docker and no external services. The schema below is the
 * spec's schema table-for-table and column-for-column, and the graph is still a
 * PROJECTION built from the outbox (§42) rather than written on the inference
 * path — so moving to Postgres + Neo4j replaces two adapters and no logic.
 */
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DB_PATH = process.env.CTN_DB_PATH ?? join(root, ".data", "coordinator.sqlite");
mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA journal_mode = WAL");
db.exec("PRAGMA foreign_keys = ON");

export function migrate(): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS contributors (
      id            TEXT PRIMARY KEY,
      display_name  TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'ACTIVE',
      created_at    TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS credentials (
      id                              TEXT PRIMARY KEY,
      contributor_id                  TEXT NOT NULL REFERENCES contributors(id),
      provider                        TEXT NOT NULL,
      label                           TEXT NOT NULL,
      -- vault ciphertext only; raw credential material is never stored (§13)
      encrypted_blob                  TEXT NOT NULL,
      capability_json                 TEXT NOT NULL,
      capability_signature            TEXT NOT NULL,
      key_fingerprint                 TEXT NOT NULL,
      status                          TEXT NOT NULL DEFAULT 'ACTIVE',
      weight                          INTEGER NOT NULL DEFAULT 1,
      created_at                      TEXT NOT NULL,
      last_used_at                    TEXT,
      requests_today                  INTEGER NOT NULL DEFAULT 0,
      estimated_cost_today_usd        REAL NOT NULL DEFAULT 0,
      usage_day                       TEXT,
      failure_count                   INTEGER NOT NULL DEFAULT 0,
      cooldown_until                  TEXT,
      operational_daily_usd_limit     REAL,
      operational_daily_request_limit INTEGER
    );

    CREATE TABLE IF NOT EXISTS requests (
      id                     TEXT PRIMARY KEY,
      request_commitment     TEXT,
      policy_id              TEXT,
      policy_result          TEXT,
      selected_credential_id TEXT,
      provider               TEXT,
      model                  TEXT,
      status                 TEXT NOT NULL,
      privacy_mode           TEXT NOT NULL,
      trust_status           TEXT,
      proof_status           TEXT NOT NULL DEFAULT 'NOT_REQUIRED',
      error_code             TEXT,
      created_at             TEXT NOT NULL,
      completed_at           TEXT,
      policy_ms              INTEGER,
      proof_ms               INTEGER,
      provider_ms            INTEGER,
      total_ms               INTEGER,
      input_tokens           INTEGER,
      output_tokens          INTEGER
    );

    CREATE TABLE IF NOT EXISTS provider_attempts (
      id             TEXT PRIMARY KEY,
      request_id     TEXT NOT NULL REFERENCES requests(id),
      credential_id  TEXT NOT NULL,
      contributor_id TEXT NOT NULL,
      attempt_number INTEGER NOT NULL,
      status         TEXT NOT NULL,
      http_status    INTEGER,
      classification TEXT,
      latency_ms     INTEGER,
      created_at     TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS proofs (
      id              TEXT PRIMARY KEY,
      request_id      TEXT NOT NULL REFERENCES requests(id),
      proof_system    TEXT NOT NULL,
      guest_image_id  TEXT NOT NULL,
      receipt_blob    TEXT,
      receipt_digest  TEXT,
      -- Rule 8: the enclave-signed statement binding this proof to the receipt.
      binding_json    TEXT,
      verified        INTEGER NOT NULL DEFAULT 0,
      status          TEXT NOT NULL,
      error           TEXT,
      simulated_cost_ms INTEGER,
      proof_ms        INTEGER,
      created_at      TEXT NOT NULL,
      completed_at    TEXT
    );

    CREATE TABLE IF NOT EXISTS compute_receipts (
      id           TEXT PRIMARY KEY,
      request_id   TEXT NOT NULL REFERENCES requests(id),
      receipt_json TEXT NOT NULL,
      signature    TEXT NOT NULL,
      created_at   TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS usage (
      id                 TEXT PRIMARY KEY,
      request_id         TEXT NOT NULL REFERENCES requests(id),
      credential_id      TEXT NOT NULL,
      contributor_id     TEXT NOT NULL,
      input_tokens       INTEGER NOT NULL DEFAULT 0,
      output_tokens      INTEGER NOT NULL DEFAULT 0,
      estimated_cost_usd REAL NOT NULL DEFAULT 0,
      created_at         TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS outbox_events (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type   TEXT NOT NULL,
      aggregate_id TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      created_at   TEXT NOT NULL,
      processed_at TEXT
    );

    -- Neo4j stand-in. Same node/link model as §43/§44; projected from the outbox.
    CREATE TABLE IF NOT EXISTS graph_nodes (
      id         TEXT PRIMARY KEY,
      type       TEXT NOT NULL,
      label      TEXT NOT NULL,
      status     TEXT,
      meta_json  TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS graph_links (
      id         TEXT PRIMARY KEY,
      source     TEXT NOT NULL,
      target     TEXT NOT NULL,
      type       TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_outbox_unprocessed ON outbox_events(processed_at, id);
    CREATE INDEX IF NOT EXISTS idx_attempts_request ON provider_attempts(request_id);
    CREATE INDEX IF NOT EXISTS idx_usage_contributor ON usage(contributor_id);
    CREATE INDEX IF NOT EXISTS idx_credentials_contributor ON credentials(contributor_id);
    CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(created_at DESC);
  `);
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function today(): string {
  return new Date().toISOString().slice(0, 10);
}

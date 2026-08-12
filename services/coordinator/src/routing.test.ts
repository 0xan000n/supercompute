import { test, after } from "node:test";
import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

/**
 * §5.1 — an outcome we could not classify is not a free request.
 *
 * The DB module opens its file at import time, so the path has to be set before
 * the module graph is evaluated: hence the dynamic imports below rather than
 * static ones. Everything after this point runs against a throwaway database.
 */
const DB_FILE = join(tmpdir(), `ctn-routing-test-${randomUUID()}.sqlite`);
process.env.CTN_DB_PATH = DB_FILE;

const { db, migrate, nowIso } = await import("./db.js");
const { recordAssumedUsage } = await import("./routing.js");

migrate();

after(() => {
  db.close();
  for (const suffix of ["", "-wal", "-shm"]) rmSync(`${DB_FILE}${suffix}`, { force: true });
});

function seedCredential(id: string, contributorId: string): void {
  db.prepare(`INSERT INTO contributors (id, display_name, created_at) VALUES (?, ?, ?)`).run(
    contributorId,
    "Test Contributor",
    nowIso()
  );
  db.prepare(
    `INSERT INTO credentials (id, contributor_id, provider, label, encrypted_blob, capability_json,
                              capability_signature, key_fingerprint, created_at, usage_day)
     VALUES (?, ?, 'mock', 'test key', 'vault:ciphertext', '{}', 'sig', 'fp', ?, ?)`
  ).run(id, contributorId, nowIso(), new Date().toISOString().slice(0, 10));
}

function seedRequest(id: string): void {
  db.prepare(
    `INSERT INTO requests (id, status, privacy_mode, created_at) VALUES (?, 'RECEIVED', 'secure', ?)`
  ).run(id, nowIso());
}

interface Counters {
  estimated_cost_today_usd: number;
  requests_today: number;
}
function counters(credentialId: string): Counters {
  return db
    .prepare(`SELECT estimated_cost_today_usd, requests_today FROM credentials WHERE id = ?`)
    .get(credentialId) as unknown as Counters;
}

test("assumed usage enforces the cap exactly like real usage", () => {
  seedCredential("cred_test", "contrib_t");
  seedRequest("req_t");

  const before = counters("cred_test");
  recordAssumedUsage({
    requestId: "req_t",
    credentialId: "cred_test",
    contributorId: "contrib_t",
    assumedSpendMicroUsd: 2_500,
  });
  const after = counters("cred_test");

  assert.ok(after.estimated_cost_today_usd > before.estimated_cost_today_usd, "cost counter must move");
  assert.equal(after.requests_today, before.requests_today + 1, "request slot consumed");

  const usage = db.prepare(`SELECT * FROM usage WHERE request_id = ?`).get("req_t") as unknown as {
    estimated_cost_usd: number;
    input_tokens: number;
    output_tokens: number;
    credential_id: string;
  };
  assert.equal(usage.input_tokens, 0);
  assert.equal(usage.output_tokens, 0);
  assert.equal(usage.credential_id, "cred_test");
  assert.ok(Math.abs(usage.estimated_cost_usd - 0.0025) < 1e-9);
});

/**
 * The ledger row and the cap counters are one fact stated twice. If they can
 * come apart, a wedged provider gets a free request every time the write half
 * fails — so the failure path is tested, not assumed.
 */
test("a rejected assumed-usage write leaves the cap counters untouched", () => {
  seedCredential("cred_atomic", "contrib_atomic");
  seedRequest("req_atomic");

  const args = {
    requestId: "req_atomic",
    credentialId: "cred_atomic",
    contributorId: "contrib_atomic",
    assumedSpendMicroUsd: 1_000,
  };
  recordAssumedUsage(args);
  const after = counters("cred_atomic");

  // Same request id -> the usage insert violates the primary key mid-transaction.
  assert.throws(() => recordAssumedUsage(args));

  assert.deepEqual(counters("cred_atomic"), after, "a rolled-back write must not move the counters");
  const rows = db.prepare(`SELECT COUNT(*) AS n FROM usage WHERE request_id = ?`).get("req_atomic") as unknown as {
    n: number;
  };
  assert.equal(rows.n, 1);
});

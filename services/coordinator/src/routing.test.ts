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
const { applyAttemptOutcome, recordAssumedUsage } = await import("./routing.js");

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
 * come apart, a contributor is charged for a request with nothing on record to
 * explain it — so the failure path is tested, not assumed.
 *
 * This discriminates only because `recordAssumedUsage` bumps the counters BEFORE
 * the insert that can fail. Written the other way round the insert would throw
 * first, the counters would never move, and this test would pass with the
 * transaction deleted. Verified by deleting the BEGIN/COMMIT/ROLLBACK and
 * watching it fail: `requests_today` came back 2 instead of 1.
 */
test("a rejected assumed-usage write rolls back the cap counters", () => {
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

  // Same request id -> the usage insert violates its primary key, AFTER the
  // counters for this second booking have already been incremented.
  assert.throws(() => recordAssumedUsage(args));

  assert.deepEqual(counters("cred_atomic"), after, "the rolled-back bump must not survive");
  const rows = db.prepare(`SELECT COUNT(*) AS n FROM usage WHERE request_id = ?`).get("req_atomic") as unknown as {
    n: number;
  };
  assert.equal(rows.n, 1);
});

/**
 * An unknown outcome with no priceable bound still consumed a request slot.
 * Pins the `?? 0` at the call site: zero dollars is not zero requests.
 */
interface StatusRow {
  status: string;
  failure_count: number;
}
function credentialRow(id: string): StatusRow {
  return db
    .prepare(`SELECT status, failure_count FROM credentials WHERE id = ?`)
    .get(id) as unknown as StatusRow;
}

/**
 * §50 — revocation is terminal, including against our own failure handler.
 *
 * `auth_failed` disables the credential, and a dispatch already in flight when
 * the owner revokes lands here afterwards. A plain `SET status = 'DISABLED'`
 * would move a DELETED row into a status that PATCH is allowed to flip back to
 * ACTIVE — resurrecting, by way of a failure handler, exactly the key the owner
 * revoked. The e2e suite covers the API surface of that rule (case 66); this
 * covers the race, which no request sequence can schedule on purpose.
 */
test("an auth_failed outcome cannot resurrect a revoked credential", () => {
  seedCredential("cred_revoked", "contrib_revoked");
  db.prepare(`UPDATE credentials SET status = 'DELETED' WHERE id = ?`).run("cred_revoked");

  const action = applyAttemptOutcome("cred_revoked", "FAILED", "auth_failed");

  const row = credentialRow("cred_revoked");
  assert.equal(row.status, "DELETED", "a revoked credential must not come back as DISABLED");
  // The bookkeeping still has to happen: the guard is about the status column,
  // not about pretending the failed attempt did not occur.
  assert.equal(row.failure_count, 1, "the failure is still counted");
  assert.equal(action.action, "disabled", "the policy applied is still 'disable'");
});

/**
 * The other half of the same guard: it must not blunt a legitimate disable. A
 * CASE expression that got its condition backwards would pass the test above
 * and leave every auth-failing credential ACTIVE, retried on every request.
 */
test("an auth_failed outcome still disables a live credential", () => {
  seedCredential("cred_live", "contrib_live");
  assert.equal(credentialRow("cred_live").status, "ACTIVE");

  applyAttemptOutcome("cred_live", "FAILED", "auth_failed");

  const row = credentialRow("cred_live");
  assert.equal(row.status, "DISABLED", "a provider-rejected credential must leave the pool");
  assert.equal(row.failure_count, 1);
});

test("a zero-dollar assumed spend still consumes a request slot", () => {
  seedCredential("cred_zero", "contrib_zero");
  seedRequest("req_zero");

  const before = counters("cred_zero");
  recordAssumedUsage({
    requestId: "req_zero",
    credentialId: "cred_zero",
    contributorId: "contrib_zero",
    assumedSpendMicroUsd: 0,
  });
  const after = counters("cred_zero");

  assert.equal(after.requests_today, before.requests_today + 1, "request slot consumed");
  assert.equal(after.estimated_cost_today_usd, before.estimated_cost_today_usd, "no cost to book");
});

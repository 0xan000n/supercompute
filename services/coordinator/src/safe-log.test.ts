import { test } from "node:test";
import assert from "node:assert/strict";
import { redact } from "./safe-log.js";

/**
 * §57 — the prompt-privacy claim rests on this module refusing sensitive fields,
 * so the refusal is tested rather than assumed.
 */

const REDACTED = "[redacted-by-safeLog]";

test("redacts every forbidden top-level field", () => {
  const out = redact({
    request_id: "req_1",
    messages: [{ role: "user", content: "CANARY" }],
    prompt: "CANARY",
    authorization: "Bearer sk-live-123",
    api_key: "sk-live-123",
    ciphertext: "AAAA",
    encrypted_blob: "BBBB",
  }) as Record<string, unknown>;

  assert.equal(out.request_id, "req_1");
  for (const key of ["messages", "prompt", "authorization", "api_key", "ciphertext", "encrypted_blob"]) {
    assert.equal(out[key], REDACTED, `${key} must be redacted`);
  }
});

test("redacts forbidden fields nested inside objects", () => {
  const out = redact({
    envelope: { requestId: "req_1", ciphertext: "SECRET", aad: { model: "m" } },
  }) as { envelope: Record<string, unknown> };
  assert.equal(out.envelope.ciphertext, REDACTED);
  assert.equal(out.envelope.requestId, "req_1");
});

test("redacts forbidden fields nested inside arrays", () => {
  const out = redact({
    attempts: [{ credential_id: "c1", secret: "SECRET" }, { credential_id: "c2", key: "SECRET" }],
  }) as { attempts: Array<Record<string, unknown>> };
  assert.equal(out.attempts[0].secret, REDACTED);
  assert.equal(out.attempts[1].key, REDACTED);
  assert.equal(out.attempts[0].credential_id, "c1");
});

test("field matching is case-insensitive", () => {
  const out = redact({ Prompt: "CANARY", API_KEY: "x", CipherText: "y" }) as Record<string, unknown>;
  assert.equal(out.Prompt, REDACTED);
  assert.equal(out.API_KEY, REDACTED);
  assert.equal(out.CipherText, REDACTED);
});

test("a redacted value never contains the original", () => {
  const canary = "CANARY_PRIVATE_PROMPT_ABC123";
  const serialized = JSON.stringify(
    redact({ prompt: canary, messages: [{ content: canary }], response: { output: canary } })
  );
  assert.ok(!serialized.includes(canary), `canary leaked: ${serialized}`);
});

test("non-forbidden identifiers survive, so logs stay useful", () => {
  const out = redact({
    request_id: "req_1",
    credential_id: "cred_1",
    contributor_id: "contrib_1",
    commitment: "0xabc",
    policy_ms: 3,
    http_status: 429,
  }) as Record<string, unknown>;
  assert.deepEqual(out, {
    request_id: "req_1",
    credential_id: "cred_1",
    contributor_id: "contrib_1",
    commitment: "0xabc",
    policy_ms: 3,
    http_status: 429,
  });
});

test("deeply nested structures terminate instead of recursing forever", () => {
  // Build a chain deeper than the depth limit and confirm it is truncated, not thrown.
  let deep: Record<string, unknown> = { prompt: "CANARY" };
  for (let i = 0; i < 30; i++) deep = { nested: deep };
  const serialized = JSON.stringify(redact(deep));
  assert.ok(serialized.includes("[depth-limit]"));
  assert.ok(!serialized.includes("CANARY"));
});

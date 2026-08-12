import { test } from "node:test";
import assert from "node:assert/strict";
import { intentDigest, type CredentialIntentV1 } from "@ctn/protocol";
import { MODEL_CATALOG } from "./catalog.js";
import { parseIntent, deriveCapability, InvalidIntentError } from "./intent.js";

const intent: CredentialIntentV1 = {
  version: 1,
  credentialId: "cred_aaaaaaaaaaaa",
  secret: "sk-test-000000000000",
  provider: "anthropic",
  allowedModels: ["claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001"],
  allowedPolicies: ["safety-v1"],
  contributorId: "contrib_alice",
  intentNonce: "a".repeat(64),
};
const bytes = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));

test("a valid intent parses", () => {
  assert.deepEqual(parseIntent(bytes(intent), MODEL_CATALOG), intent);
});

test("strict schema: rejects unknown fields, bad version, malformed secret, bad ids", () => {
  for (const bad of [
    { ...intent, extraField: true },
    { ...intent, version: 2 },
    { ...intent, secret: "short" },
    { ...intent, secret: "has whitespace in it" },
    { ...intent, credentialId: "not-a-cred-id" },
    { ...intent, intentNonce: "zz" },
    { ...intent, contributorId: "" },
    { ...intent, contributorId: "x".repeat(65) },
  ]) {
    assert.throws(() => parseIntent(bytes(bad), MODEL_CATALOG), InvalidIntentError);
  }
});

test("strict catalog: provider membership, no cross-provider models, no dupes, caps", () => {
  for (const bad of [
    { ...intent, provider: "google" },
    { ...intent, allowedModels: [] },
    { ...intent, allowedModels: ["gpt-4o-2024-08-06"] },              // wrong provider
    { ...intent, allowedModels: ["claude-haiku-4-5"] },               // movable alias, not pinned
    { ...intent, allowedModels: ["claude-haiku-4-5-20251001", "claude-haiku-4-5-20251001"] }, // dupe
    { ...intent, allowedPolicies: ["invented-policy"] },
    { ...intent, allowedPolicies: [] },
  ]) {
    assert.throws(() => parseIntent(bytes(bad), MODEL_CATALOG), InvalidIntentError);
  }
});

test("non-JSON plaintext is rejected without echoing content", () => {
  assert.throws(() => parseIntent(new TextEncoder().encode("sk-live-notjson"), MODEL_CATALOG), (err: Error) => {
    assert.ok(!err.message.includes("sk-live"));
    return err instanceof InvalidIntentError;
  });
});

test("deriveCapability uses ONLY the intent — credentialId included — and binds its digest", () => {
  const cap = deriveCapability({
    intent, blobDigest: "0xabc",
    resolvePolicyId: (l) => (l === "safety-v1" ? "policy_123" : l), now: 1234,
  });
  assert.equal(cap.credentialId, "cred_aaaaaaaaaaaa");
  assert.equal(cap.provider, "anthropic");
  assert.deepEqual(cap.allowedModels, ["claude-haiku-4-5-20251001", "claude-sonnet-4-5-20250929"]); // sorted
  assert.deepEqual(cap.allowedPolicyIds, ["policy_123"]);
  assert.equal(cap.contributorId, "contrib_alice");
  assert.equal(cap.version, 1);
  assert.equal(cap.blobDigest, "0xabc");
  assert.equal(cap.intentDigest, intentDigest(intent));
});

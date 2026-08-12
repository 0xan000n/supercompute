# Phase 1: Intent-Bound Contribution + Real Providers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A contributor's API key travels in one HPKE envelope *together with their constraints* (provider, models, policies) and a client-chosen credential id, the enclave derives capabilities only from that sealed intent and rejects replays, capabilities become immutable, prompts proxy to real Anthropic/OpenAI APIs with **exactly one dispatch per request**, and cost accounting is honest about unknown upstream outcomes.

**Architecture:** Extends the existing five-package pnpm workspace in place. A new `CredentialIntentV1` protocol type replaces the split key/metadata contribution; a new pure `intent.ts` module in tee-sim derives capabilities against a pinned model catalog; the recapability endpoint is deleted; `providers.ts` gains an `AnthropicAdapter`, strict response validation, and a shared checked-in pricing table with digest; the routing loop becomes single-dispatch.

**Tech Stack:** TypeScript, Fastify, better-sqlite3, `@hpke/core` (already present), `node:test` via `tsx --test`. **No new dependencies in this phase.**

**Spec:** `docs/superpowers/specs/2026-08-11-supercompute-real-design.md` (§5.1, §7, §8, §10)

**Revision note (same day):** restructured after plan review — Tasks 1–3 merged into one atomic task (no broken intermediate commits); replay protection added; single-dispatch routing added; worst-case estimator switched to a UTF-8-byte upper bound; unknown-outcome classification broadened beyond AbortError; malformed-200 validation added; intent validation strictened with pinned snapshot model IDs; assumed spend now enforces caps atomically with a schema migration.

## Global Constraints

- Local demo only; no authentication; must not be network-exposed.
- Non-streaming only; `max_tokens` required.
- **Single dispatch:** authorization failures and other provably pre-dispatch failures may fall through to the next candidate credential, but once one upstream request has been dispatched, every response or uncertain transport outcome terminates routing for that request. No inference call is ever retried.
- All money is **integer micro-USD** (receipts are signed over canonical bytes; floats forbidden in signed structures). Operational SQLite columns may stay REAL.
- Egress allow-list is exactly `api.openai.com:443`, `api.anthropic.com:443`, plus `CTN_EGRESS_ALLOWLIST` env extras (used for the local mock). Google's endpoint is removed.
- Capabilities are **immutable**: editing = revoke + re-contribute. No re-signing endpoint may exist.
- **Model consent is pinned:** capabilities name dated snapshot model IDs (e.g. `claude-haiku-4-5-20251001`), never movable aliases.
- Honesty labelling: any UI/docs claim changed here must state limitations at equal weight (pricing is an estimate from a pinned table; timeout spend is unknown; replay protection is in-memory and resets with the enclave).
- Test runner everywhere: `tsx --test src/*.test.ts` with `node:test` + `node:assert/strict`.
- Full-repo gates that must stay green **after every task's commit**: `npx tsc --noEmit -p tsconfig.json` and `pnpm test`.
- The demo SQLite DB is disposable: schema changes land in `db.ts`'s `CREATE TABLE` statements **plus** a tolerant `ALTER TABLE` migration (wrapped in try/catch) so an existing `.data` dir keeps working; `pnpm reset` is the clean path.

---

### Task 1: Sealed intent end-to-end (protocol + client + enclave + coordinator, one atomic commit)

This task replaces the contribution wire format in all four places at once so every commit keeps `tsc` and `pnpm test` green. It is larger than the others by design — the intermediate states do not compile.

**Files:**
- Modify: `packages/protocol/src/types.ts` (add `CredentialIntentV1`; extend `CredentialCapability`; slim `CredentialSubmission`)
- Modify: `packages/protocol/src/crypto.ts` (add `intentDigest`)
- Modify: `packages/protocol/src/index.ts` (exports)
- Modify: `packages/client/src/index.ts:287-334` (`contributeCredential`)
- Create: `services/tee-sim/src/catalog.ts` (pinned provider→models catalog — Task 3/4/5/8 also consume this)
- Create: `services/tee-sim/src/intent.ts`
- Modify: `services/tee-sim/src/index.ts:139-205` (ingestion route + `IngestBody` + in-memory replay set)
- Modify: `services/coordinator/src/index.ts:138-233` (`POST /v1/credentials`)
- Modify: `services/coordinator/src/tee-client.ts` (`ingestCredential` payload type)
- Test: `packages/protocol/src/protocol.test.ts` (append), `services/tee-sim/src/intent.test.ts` (new), `scripts/test-e2e.mts` (replay test)

**Interfaces:**
- Produces (later tasks rely on these exact names):
  - `interface CredentialIntentV1 { version: 1; credentialId: string; secret: string; provider: Provider; allowedModels: string[]; allowedPolicies: string[]; contributorId: string; intentNonce: string }`
  - `function intentDigest(intent: CredentialIntentV1): string` — `"0x"`-hex, excludes `secret`, binds everything else including `credentialId` and `intentNonce`
  - `CredentialCapability.intentDigest: string` (new required field)
  - `MODEL_CATALOG: Record<"anthropic" | "openai" | "mock", readonly string[]>` in `catalog.ts` with **pinned snapshot IDs**:
    - anthropic: `["claude-haiku-4-5-20251001", "claude-sonnet-4-5-20250929"]`
    - openai: `["gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06"]`
    - mock: `["ctn/demo-model-a", "ctn/demo-model-b", "ctn/demo-model-fast"]`
  - `parseIntent(plaintext: Uint8Array, catalog: typeof MODEL_CATALOG): CredentialIntentV1` — throws `InvalidIntentError` (`.code = "CTN_INVALID_ENVELOPE"`)
  - `deriveCapability(input: { intent: CredentialIntentV1; blobDigest: string; resolvePolicyId: (label: string) => string; now: number }): CredentialCapability` — note: **no separate credentialId param**; it comes from the intent
  - Client POST body to `/v1/credentials`: `{ contributorId, label, weight, operationalLimits, credentialId, enclaveKeyId, enc, encryptedSecret }` — `credentialId` is **client-generated** (`"cred_" + randomHex(6)` → matches the existing `cred_` + 12-hex format) and also sealed inside the intent; no plaintext provider/models/policies anywhere

- [ ] **Step 1: Write the failing protocol tests** (append to `packages/protocol/src/protocol.test.ts`)

```ts
import { intentDigest, type CredentialIntentV1 } from "./crypto";
import { generateHpkeKeyPair, hpkeSeal, hpkeOpen } from "./hpke";
import { canonicalJson } from "./canonical";

const baseIntent: CredentialIntentV1 = {
  version: 1,
  credentialId: "cred_aaaaaaaaaaaa",
  secret: "sk-test-000000000000",
  provider: "anthropic",
  allowedModels: ["claude-haiku-4-5-20251001"],
  allowedPolicies: ["safety-v1"],
  contributorId: "contrib_alice",
  intentNonce: "a".repeat(64),
};

test("intentDigest is deterministic and 0x-prefixed", () => {
  assert.equal(intentDigest(baseIntent), intentDigest({ ...baseIntent }));
  assert.match(intentDigest(baseIntent), /^0x[0-9a-f]{64}$/);
});

test("intentDigest ignores the secret but binds every other field", () => {
  const base = intentDigest(baseIntent);
  assert.equal(intentDigest({ ...baseIntent, secret: "sk-test-999999999999" }), base);
  assert.notEqual(intentDigest({ ...baseIntent, credentialId: "cred_bbbbbbbbbbbb" }), base);
  assert.notEqual(intentDigest({ ...baseIntent, provider: "openai" }), base);
  assert.notEqual(intentDigest({ ...baseIntent, allowedModels: ["gpt-4o-2024-08-06"] }), base);
  assert.notEqual(intentDigest({ ...baseIntent, contributorId: "contrib_bob" }), base);
  assert.notEqual(intentDigest({ ...baseIntent, intentNonce: "b".repeat(64) }), base);
});

test("a sealed intent round-trips: key, constraints, and credentialId in ONE envelope", async () => {
  const enclave = await generateHpkeKeyPair();
  const sealed = await hpkeSeal(enclave.publicKeyB64, new TextEncoder().encode(canonicalJson(baseIntent)));
  const opened = JSON.parse(new TextDecoder().decode(await hpkeOpen(enclave.privateKeyB64, sealed))) as CredentialIntentV1;
  assert.deepEqual(opened, baseIntent);
});
```

(If `generateHpkeKeyPair`'s property names differ — check `packages/protocol/src/hpke.ts` — use the names it actually returns.)

- [ ] **Step 2: Write the failing intent unit tests** (`services/tee-sim/src/intent.test.ts`)

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalJson, intentDigest, type CredentialIntentV1 } from "@ctn/protocol";
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
```

- [ ] **Step 3: Run both to verify failure**

Run: `pnpm --filter @ctn/protocol test && pnpm --filter @ctn/tee-sim test`
Expected: FAIL — `intentDigest`, `./catalog.js`, `./intent.js` missing.

- [ ] **Step 4: Implement the protocol layer**

`packages/protocol/src/types.ts` — next to `CredentialSubmission`:

```ts
/**
 * The contributor's sealed intent — the ONLY authority on what a credential
 * may do. HPKE-sealed in the contributor's browser to the attested ingress
 * key; the enclave derives the signed capability exclusively from this.
 * The coordinator relays an opaque envelope: there is no plaintext metadata
 * left for it to alter, and the credentialId inside forecloses minting the
 * same envelope under a different id.
 */
export interface CredentialIntentV1 {
  version: 1;
  /** client-generated, "cred_" + 12 hex; the capability's id comes from HERE */
  credentialId: string;
  secret: string;
  provider: Provider;
  allowedModels: string[];
  allowedPolicies: string[];
  contributorId: string;
  /** 32-byte hex, fresh per contribution; the enclave rejects repeats */
  intentNonce: string;
}
```

Extend `CredentialCapability` (after `blobDigest`, matching its comment style):

```ts
  /**
   * SHA-256 over the canonical intent minus the secret. Ties this capability
   * to exactly what the contributor sealed — including the credentialId and
   * a fresh nonce, so a relayed envelope cannot be re-minted.
   */
  intentDigest: string;
```

Slim `CredentialSubmission`:

```ts
/** §13 — credential submission; the intent (key + constraints) is HPKE-sealed. */
export interface CredentialSubmission {
  enclaveKeyId: string;
  enc: string;
  encryptedSecret: string;
  contributorDisplayId: string;
}
```

`packages/protocol/src/crypto.ts` (below `requestCommitment`, same idiom):

```ts
const INTENT_DOMAIN = "CTN_INTENT_V1";

/** Digest of the canonical intent MINUS the secret, domain-separated. */
export function intentDigest(intent: CredentialIntentV1): string {
  const { secret: _secret, ...publicIntent } = intent;
  const canonical = utf8(canonicalJson(publicIntent));
  const domain = utf8(INTENT_DOMAIN);
  const buf = new Uint8Array(domain.length + canonical.length);
  buf.set(domain, 0);
  buf.set(canonical, domain.length);
  return "0x" + toHex(sha256(buf));
}
```

Export both from `index.ts`.

- [ ] **Step 5: Implement `services/tee-sim/src/catalog.ts`**

```ts
/**
 * §5.1 — the pinned model catalog. Capabilities name DATED SNAPSHOT IDs, not
 * movable aliases: consent to "claude-haiku-4-5" would be consent to whatever
 * that alias points at next month. A catalog change is a deliberate commit.
 */
export const MODEL_CATALOG = {
  anthropic: ["claude-haiku-4-5-20251001", "claude-sonnet-4-5-20250929"],
  openai: ["gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06"],
  mock: ["ctn/demo-model-a", "ctn/demo-model-b", "ctn/demo-model-fast"],
} as const satisfies Record<string, readonly string[]>;

export type CatalogProvider = keyof typeof MODEL_CATALOG;
```

- [ ] **Step 6: Implement `services/tee-sim/src/intent.ts`**

```ts
/**
 * §5.1 — the sealed intent is the ONLY authority on a credential's
 * capability. This module is pure: parse + derive, no I/O, so the
 * tamper-resistance property is unit-testable in isolation.
 */
import {
  intentDigest,
  type CredentialCapability,
  type CredentialIntentV1,
} from "@ctn/protocol";
import type { MODEL_CATALOG } from "./catalog.js";

export class InvalidIntentError extends Error {
  readonly code = "CTN_INVALID_ENVELOPE";
}

const INTENT_KEYS = [
  "version", "credentialId", "secret", "provider",
  "allowedModels", "allowedPolicies", "contributorId", "intentNonce",
].sort();
const SUPPORTED_POLICIES = ["safety-v1"];
const MAX_MODELS = 8;
const MAX_ID_LENGTH = 64;

export function parseIntent(
  plaintext: Uint8Array,
  catalog: typeof MODEL_CATALOG
): CredentialIntentV1 {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    // Never echo the plaintext: it may be a raw key pasted without sealing.
    throw new InvalidIntentError("sealed intent is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
    throw new InvalidIntentError("sealed intent must be an object");
  // Exact schema: unknown fields are rejected, not ignored — an ignored field
  // is a field somebody will eventually trust without the enclave checking it.
  const keys = Object.keys(parsed).sort();
  if (JSON.stringify(keys) !== JSON.stringify(INTENT_KEYS))
    throw new InvalidIntentError("sealed intent has missing or unexpected fields");

  const i = parsed as CredentialIntentV1;
  if (i.version !== 1) throw new InvalidIntentError("unsupported intent version");
  if (typeof i.credentialId !== "string" || !/^cred_[0-9a-f]{12}$/.test(i.credentialId))
    throw new InvalidIntentError("credentialId must be cred_ + 12 hex chars");
  if (typeof i.secret !== "string" || i.secret.trim().length < 8 || /\s/.test(i.secret.trim()))
    throw new InvalidIntentError("credential does not look like an API key");
  if (typeof i.provider !== "string" || !(i.provider in catalog))
    throw new InvalidIntentError("provider is not implemented");
  const models = catalog[i.provider as keyof typeof catalog] as readonly string[];
  if (
    !Array.isArray(i.allowedModels) ||
    i.allowedModels.length === 0 ||
    i.allowedModels.length > MAX_MODELS ||
    !i.allowedModels.every((m) => typeof m === "string" && models.includes(m)) ||
    new Set(i.allowedModels).size !== i.allowedModels.length
  )
    throw new InvalidIntentError("allowedModels must be unique pinned snapshot ids from this provider's catalog");
  if (
    !Array.isArray(i.allowedPolicies) ||
    i.allowedPolicies.length === 0 ||
    !i.allowedPolicies.every((p) => SUPPORTED_POLICIES.includes(p)) ||
    new Set(i.allowedPolicies).size !== i.allowedPolicies.length
  )
    throw new InvalidIntentError("allowedPolicies must be supported policy labels");
  if (typeof i.contributorId !== "string" || i.contributorId.length === 0 || i.contributorId.length > MAX_ID_LENGTH)
    throw new InvalidIntentError("contributorId must be 1-64 chars");
  if (typeof i.intentNonce !== "string" || !/^[0-9a-f]{64}$/.test(i.intentNonce))
    throw new InvalidIntentError("intentNonce must be 32 bytes of hex");
  return { ...i, secret: i.secret.trim() };
}

export function deriveCapability(input: {
  intent: CredentialIntentV1;
  blobDigest: string;
  resolvePolicyId: (label: string) => string;
  now: number;
}): CredentialCapability {
  const { intent } = input;
  return {
    credentialId: intent.credentialId,
    provider: intent.provider,
    allowedModels: [...intent.allowedModels].sort(),
    // Contributors opt into an exact policy version, not a mutable label (§24).
    allowedPolicyIds: intent.allowedPolicies.map(input.resolvePolicyId),
    contributorId: intent.contributorId,
    createdAt: input.now,
    version: 1,
    blobDigest: input.blobDigest,
    intentDigest: intentDigest(intent),
  };
}
```

- [ ] **Step 7: Rewire the enclave ingestion route** (`services/tee-sim/src/index.ts`)

```ts
interface IngestBody {
  enclaveKeyId: string;
  enc: string;
  encryptedSecret: string;
  credentialId: string;
}

/**
 * §5.1 replay guard. In-memory: a restarted enclave forgets — LABELLED as such
 * in VALIDATION.md. The client-generated credentialId sealed inside the intent
 * is the structural half of the defence (a replayed envelope can only ever
 * mint the SAME capability, never a second one under a new id).
 */
const consumedIntentDigests = new Set<string>();
```

```ts
app.post("/credentials/ingest", async (request, reply) => {
  const body = request.body as IngestBody;
  if (body.enclaveKeyId !== tee.enclaveKeyId) {
    return reply.code(400).send({ error: { code: "CTN_INVALID_ENVELOPE", message: "unknown enclave key id" } });
  }

  let intent;
  try {
    const opened = await tee.openIngress({ enc: body.enc, ciphertext: body.encryptedSecret });
    intent = parseIntent(opened, MODEL_CATALOG);
  } catch (err) {
    const message = err instanceof InvalidIntentError ? err.message : "credential ciphertext failed to decrypt";
    return reply.code(400).send({ error: { code: "CTN_INVALID_ENVELOPE", message } });
  }

  if (intent.credentialId !== body.credentialId) {
    return reply.code(400).send({
      error: { code: "CTN_INTENT_MISMATCH", message: "sealed intent names a different credential id" },
    });
  }
  const digest = intentDigest(intent);
  if (consumedIntentDigests.has(digest)) {
    return reply.code(409).send({
      error: { code: "CTN_INTENT_REPLAY", message: "this sealed intent has already been consumed" },
    });
  }

  // §13 — only ciphertext leaves the enclave; the DB never sees raw material.
  const encryptedBlob = vaultEncrypt(vaultKey, intent.secret);

  // §5.1 — derived from the DECRYPTED INTENT alone. Anything else in the HTTP
  // body is ignored by construction.
  const capability = deriveCapability({
    intent,
    blobDigest: "0x" + sha256Hex(encryptedBlob),
    resolvePolicyId: (p) => (p === "safety-v1" ? pkg.policyId : p),
    now: Date.now(),
  });
  consumedIntentDigests.add(digest);

  return {
    credentialId: intent.credentialId,
    encryptedBlob,
    capability,
    // §15 — enclave signs the capability so the coordinator cannot widen it.
    capabilitySignature: tee.signReceipt(capability),
    keyFingerprint: "0x" + tee.fingerprint(intent.credentialId, intent.secret),
    policyId: pkg.policyId,
  };
});
```

Import `parseIntent`, `deriveCapability`, `InvalidIntentError` from `./intent.js`, `MODEL_CATALOG` from `./catalog.js`, `intentDigest` from `@ctn/protocol`. Delete the now-unused inline secret validation.

- [ ] **Step 8: Rewire the client** (`packages/client/src/index.ts:287-334`)

Replace the sealing + POST section (keep the attestation check above it):

```ts
    // The key AND its constraints are sealed together, in the contributor's
    // own browser, to the attested key — including a client-chosen credential
    // id and a fresh nonce, so the envelope can neither be altered nor
    // re-minted by the relay (§5.1).
    const credentialId = `cred_${randomHex(6)}`;
    const intent: CredentialIntentV1 = {
      version: 1,
      credentialId,
      secret: input.apiKey,
      provider: input.provider as CredentialIntentV1["provider"],
      allowedModels: input.allowedModels,
      allowedPolicies: ["safety-v1"],
      contributorId: input.contributorId,
      intentNonce: randomHex(32),
    };
    const sealed = await hpkeSeal(
      attestation.bundle.ingressPublicKey,
      new TextEncoder().encode(canonicalJson(intent))
    );

    const res = await fetch(`${this.baseUrl}/v1/credentials`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contributorId: input.contributorId,
        label: input.label,
        weight: input.weight ?? 1,
        operationalLimits: input.operationalLimits,
        credentialId,
        enclaveKeyId: attestation.bundle.enclaveKeyId,
        enc: sealed.enc,
        encryptedSecret: sealed.ciphertext,
      }),
    });
```

Add `CredentialIntentV1`, `canonicalJson`, `randomHex` to the `@ctn/protocol` imports. (`randomHex(n)` — confirm whether the parameter is bytes or chars in `crypto.ts` and adjust so `credentialId` gets 12 hex chars and `intentNonce` 64.)

- [ ] **Step 9: Rewire the coordinator** (`services/coordinator/src/index.ts:138-233`, `tee-client.ts`)

- Route body type becomes `{ contributorId, label, weight?, operationalLimits?, credentialId, enclaveKeyId, enc, encryptedSecret }` — drop `provider`/`allowedModels`/`allowedPolicies`, add `credentialId`.
- Delete the coordinator's `randomUUID`-based `credentialId` generation; validate the client's: `if (!/^cred_[0-9a-f]{12}$/.test(body.credentialId)) → 400 CTN_INVALID_ENVELOPE`. Reject duplicates: `SELECT id FROM credentials WHERE id = ?` → `409 CTN_INTENT_REPLAY` (the enclave enforces the real invariant; this keeps coordinator state coherent).
- `teeClient.ingestCredential` payload becomes `{ enclaveKeyId, enc, encryptedSecret, credentialId }` (update the payload type in `tee-client.ts`; the `contributorId` and `capability` block are gone).
- After ingest, consistency check + provider column from the enclave's answer:

```ts
  if (ingested.capability.contributorId !== body.contributorId) {
    safeLog("warn", "credential.intent_mismatch", { credential_id: body.credentialId });
    return reply.code(400).send({
      error: { code: "CTN_INTENT_MISMATCH", message: "sealed intent names a different contributor" },
    });
  }
```

- In the `INSERT INTO credentials` call and `emitEvent("credential.created", ...)`, replace `body.provider` with `ingested.capability.provider`.
- Propagate the enclave's 409 (`CTN_INTENT_REPLAY`) to the caller as 409, alongside the existing `EnclaveRejectionError` 400 handling (extend `tee-client.ts`'s error mapping if it collapses status codes — read its `EnclaveRejectionError` construction and preserve the status).

- [ ] **Step 10: Write the failing replay e2e test** (append to `scripts/test-e2e.mts`, matching its `await test("NN", ...)` idiom — read two adjacent tests first and copy their helpers)

```ts
await test("59", "a sealed intent cannot be re-minted — not even under a fresh coordinator id", async () => {
  // Capture one contribution's raw envelope by contributing via the client,
  // then replay the same envelope directly against the coordinator.
  const { envelope, credentialId } = await contributeAndCaptureEnvelope(); // helper: wrap client.contributeCredential's fetch, or build the intent + hpkeSeal inline exactly as packages/client/src/index.ts does
  const replay = await fetch(`${COORD}/v1/credentials`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...envelope, credentialId }), // same id → coordinator dedupe or enclave replay guard
  });
  assert(replay.status === 409, `expected 409 on same-id replay, got ${replay.status}`);

  // A malicious coordinator submitting the SAME envelope under a DIFFERENT id
  // hits the enclave's intent/body mismatch — the id inside the envelope wins.
  const reminted = await fetch(`${COORD}/v1/credentials`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...envelope, credentialId: "cred_ffffffffffff" }),
  });
  const json = await reminted.json();
  assert(reminted.status === 400 || reminted.status === 409, `expected rejection, got ${reminted.status}`);
  assert(
    ["CTN_INTENT_MISMATCH", "CTN_INTENT_REPLAY"].includes(json.error?.code),
    `got ${json.error?.code}`
  );
});
```

- [ ] **Step 11: Full gates**

Run: `npx tsc --noEmit -p tsconfig.json` — clean.
Run: `pnpm test` — all green (protocol +3, tee-sim intent suite).
Run: `pnpm reset && pnpm dev` (one terminal), `pnpm seed` (another) — seed completes via the updated client (seed uses mock-provider models, which are in the catalog). Then `pnpm test:e2e` — all green including test 59.

- [ ] **Step 12: Commit (single atomic commit)**

```bash
git add packages/protocol/src packages/client/src services/tee-sim/src services/coordinator/src scripts/test-e2e.mts
git commit -m "contribution: sealed CredentialIntentV1 end-to-end with replay protection"
```

---

### Task 2: Remove recapability — capabilities are immutable

**Files:**
- Modify: `services/tee-sim/src/index.ts` (delete the `/credentials/recapability` route)
- Modify: `services/coordinator/src/tee-client.ts` (delete `recapability`)
- Modify: `services/coordinator/src/index.ts:288-340` (`PATCH /v1/credentials/:id`: delete the `allowedModels` branch; reject the field)
- Modify: `packages/client/src/index.ts` (delete `allowedModels` from the update method's input and body)
- Modify: `apps/web` — `grep -rn "allowedModels" apps/web/src`; remove any *edit* affordance; read-only displays stay.
- Test: `scripts/test-e2e.mts` (append)

**Interfaces:**
- Produces: `PATCH /v1/credentials/:id` accepts only `{ status?, weight?, operationalLimits? }`, returns `400 CTN_CAPABILITY_IMMUTABLE` if `allowedModels` present; `POST <tee>/credentials/recapability` → 404.

- [ ] **Step 1: Write the failing e2e test** (append, same idiom)

```ts
await test("60", "capability widening is structurally impossible", async () => {
  const direct = await fetch("http://127.0.0.1:4400/credentials/recapability", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ capability: { credentialId: "cred_x", allowedModels: ["anything"] } }),
  });
  assert(direct.status === 404, `expected 404 from removed enclave endpoint, got ${direct.status}`);

  const patch = await fetch(`${COORD}/v1/credentials/${anyCredentialId}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ allowedModels: ["ctn/demo-model-a", "ctn/demo-model-b"] }),
  });
  const json = await patch.json();
  assert(patch.status === 400, `expected 400, got ${patch.status}`);
  assert(json.error?.code === "CTN_CAPABILITY_IMMUTABLE", `got ${json.error?.code}`);
});
```

- [ ] **Step 2: Run to verify failure** — `pnpm test:e2e`: test 60 FAILS (recapability answers 200).

- [ ] **Step 3: Delete the paths**

- tee-sim: remove the whole `/credentials/recapability` route.
- tee-client: remove the `recapability` method.
- Coordinator PATCH — add at the top of the handler:

```ts
  if ((request.body as Record<string, unknown>).allowedModels !== undefined) {
    return reply.code(400).send({
      error: {
        code: "CTN_CAPABILITY_IMMUTABLE",
        message: "Capabilities are immutable. Revoke this credential and contribute a new one.",
      },
    });
  }
```

then remove the `if (body.allowedModels) {...}` recapability branch.
- Client: remove `allowedModels` from the update-credential input type and body.
- Web: remove any models-editing control found by the grep.

- [ ] **Step 4: Run gates** — `npx tsc --noEmit -p tsconfig.json` && `pnpm test` && `pnpm test:e2e`: green incl. test 60.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "capabilities are immutable: remove recapability everywhere"
```

---

### Task 3: Pricing module with pinned digest + defensible worst-case bound

**Files:**
- Create: `services/tee-sim/src/pricing.ts`
- Test: `services/tee-sim/src/pricing.test.ts`
- Modify: `services/tee-sim/src/providers.ts` (delete local `PRICING` + `estimateCostMicroUsd` at lines 77-90; import from `./pricing.js`; add `pricingTableDigest` to `ProviderResponse`)
- Modify: `packages/protocol/src/types.ts` (`ComputeReceipt.usage` gains optional `pricingTableDigest?: string`)
- Modify: `services/tee-sim/src/index.ts:454-457` (thread `pricingTableDigest` into the receipt's `usage`)

**Interfaces:**
- Consumes: `canonicalHash` from `@ctn/protocol`; `MODEL_CATALOG` keys (Task 1) — every catalog model MUST have a price entry (unit-tested).
- Produces:
  - `PRICING_TABLE: Record<string, { inMicroUsdPerMTok: number; outMicroUsdPerMTok: number }>`
  - `PRICING_TABLE_DIGEST: string`
  - `estimateCostMicroUsd(model: string, inTok: number, outTok: number): number` — throws `UnpricedModelError`
  - `estimateWorstCaseMicroUsd(model: string, messages: Array<{ content: string }>, maxTokens: number): number` (Task 7 consumes this — note the signature takes messages, not chars)
  - `ProviderResponse.pricingTableDigest: string`

- [ ] **Step 1: Write the failing tests** (`services/tee-sim/src/pricing.test.ts`)

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { MODEL_CATALOG } from "./catalog.js";
import {
  PRICING_TABLE, PRICING_TABLE_DIGEST,
  estimateCostMicroUsd, estimateWorstCaseMicroUsd, UnpricedModelError,
} from "./pricing.js";

test("every catalog model is priced — no silent default for real money", () => {
  for (const models of Object.values(MODEL_CATALOG))
    for (const m of models) assert.ok(PRICING_TABLE[m], `missing price for ${m}`);
  assert.match(PRICING_TABLE_DIGEST, /^0x[0-9a-f]{64}$/);
});

test("estimates are integer micro-USD", () => {
  const v = estimateCostMicroUsd("claude-haiku-4-5-20251001", 1234, 567);
  assert.equal(v, Math.trunc(v));
  // 1234 in at $1/MTok + 567 out at $5/MTok = 1234 + 2835 = 4069 µUSD
  assert.equal(v, 4069);
});

test("unknown model refuses rather than guessing", () => {
  assert.throws(() => estimateCostMicroUsd("gpt-99", 1, 1), UnpricedModelError);
});

test("worst case is a UTF-8 byte UPPER bound — multibyte text cannot underestimate", () => {
  const ascii = estimateWorstCaseMicroUsd("claude-haiku-4-5-20251001", [{ content: "a".repeat(1000) }], 100);
  const cjk = estimateWorstCaseMicroUsd("claude-haiku-4-5-20251001", [{ content: "語".repeat(1000) }], 100);
  assert.ok(cjk > ascii, "CJK must bound higher than same-length ASCII");
  // 1000 CJK chars = 3000 UTF-8 bytes ≥ any BPE token count for that string.
  const bytes = Buffer.byteLength("語".repeat(1000), "utf8");
  const boundTok = bytes + 16 * 1 + 16;
  assert.equal(cjk, Math.ceil((boundTok * 1_000_000 + 100 * 5_000_000) / 1_000_000));
});
```

- [ ] **Step 2: Run to verify failure** — `pnpm --filter @ctn/tee-sim test`: `./pricing.js` missing.

- [ ] **Step 3: Implement `services/tee-sim/src/pricing.ts`**

```ts
/**
 * §5.1 — the pinned price table. Costs in receipts are ESTIMATES derived from
 * provider-reported token counts and THIS table; the table's digest travels in
 * the receipt so a verifier knows which prices produced the number. Integer
 * micro-USD per million tokens — no floats anywhere near signed bytes.
 */
import { canonicalHash } from "@ctn/protocol";

export class UnpricedModelError extends Error {
  constructor(model: string) {
    super(`UNPRICED_MODEL: ${model} has no entry in the pinned pricing table`);
  }
}

export interface ModelPrice {
  inMicroUsdPerMTok: number;
  outMicroUsdPerMTok: number;
}

export const PRICING_TABLE: Record<string, ModelPrice> = {
  // Anthropic (2026-08 list prices)
  "claude-haiku-4-5-20251001": { inMicroUsdPerMTok: 1_000_000, outMicroUsdPerMTok: 5_000_000 },
  "claude-sonnet-4-5-20250929": { inMicroUsdPerMTok: 3_000_000, outMicroUsdPerMTok: 15_000_000 },
  // OpenAI
  "gpt-4o-mini-2024-07-18": { inMicroUsdPerMTok: 150_000, outMicroUsdPerMTok: 600_000 },
  "gpt-4o-2024-08-06": { inMicroUsdPerMTok: 2_500_000, outMicroUsdPerMTok: 10_000_000 },
  // Local mock (demo values so seeded dashboards stay meaningful)
  "ctn/demo-model-a": { inMicroUsdPerMTok: 150_000, outMicroUsdPerMTok: 600_000 },
  "ctn/demo-model-b": { inMicroUsdPerMTok: 2_500_000, outMicroUsdPerMTok: 10_000_000 },
  "ctn/demo-model-fast": { inMicroUsdPerMTok: 50_000, outMicroUsdPerMTok: 200_000 },
};

export const PRICING_TABLE_DIGEST = "0x" + canonicalHash(PRICING_TABLE);

function price(model: string): ModelPrice {
  const p = PRICING_TABLE[model];
  if (!p) throw new UnpricedModelError(model);
  return p;
}

export function estimateCostMicroUsd(model: string, inTok: number, outTok: number): number {
  const p = price(model);
  return Math.ceil((inTok * p.inMicroUsdPerMTok + outTok * p.outMicroUsdPerMTok) / 1_000_000);
}

/**
 * Pre-call UPPER bound on spend, used when the upstream outcome is unknown.
 * Token-count bound: BPE tokenizers over UTF-8 emit at least one byte per
 * token, so tokens(text) <= utf8Bytes(text). Add 16 tokens per message for
 * role/format framing and 16 for the wrapper — generous, and cheapness is
 * not the goal here; NOT undercounting is.
 */
export function estimateWorstCaseMicroUsd(
  model: string,
  messages: Array<{ content: string }>,
  maxTokens: number
): number {
  const p = price(model);
  const byteBound = messages.reduce((n, m) => n + Buffer.byteLength(m.content, "utf8"), 0);
  const promptTokBound = byteBound + 16 * messages.length + 16;
  return Math.ceil((promptTokBound * p.inMicroUsdPerMTok + maxTokens * p.outMicroUsdPerMTok) / 1_000_000);
}
```

- [ ] **Step 4: Rewire `providers.ts` and the receipt**

- Delete the local `PRICING` constant and `estimateCostMicroUsd` (providers.ts:77-90); import the estimators + `PRICING_TABLE_DIGEST` from `./pricing.js`.
- Add `pricingTableDigest: string;` to `ProviderResponse`; set it in the success arm of `OpenAICompatibleAdapter.complete()`.
- `services/tee-sim/src/index.ts` receipt `usage` gains `pricingTableDigest: outcome.response.pricingTableDigest`.
- `types.ts` `ComputeReceipt.usage` gains `pricingTableDigest?: string;`

- [ ] **Step 5: Run gates** — `npx tsc --noEmit -p tsconfig.json` && `pnpm test`: green.

- [ ] **Step 6: Commit**

```bash
git add services/tee-sim/src packages/protocol/src/types.ts
git commit -m "pricing: pinned table with digest; UTF-8-byte worst-case bound"
```

---

### Task 4: `AnthropicAdapter` + strict response validation for both adapters

**Files:**
- Modify: `services/tee-sim/src/providers.ts` (new class; shared `validateUsage` helper; rename `OPENAI_TIMEOUT_MS` → function `providerTimeoutMs()` reading `CTN_PROVIDER_TIMEOUT_MS` per call)
- Test: `services/tee-sim/src/providers.test.ts` (new)

**Interfaces:**
- Consumes: `assertEgressAllowed`, `ProviderOutcome`, `ProviderResponse`, pricing (Task 3), `canonicalHash`.
- Produces:
  - `class AnthropicAdapter implements ProviderAdapter`, constructor `(name: string, baseUrl: string, models: string[])`
  - `ProviderOutcome` failure arm gains `classification: ... | "malformed_response"` and the fields `upstreamOutcomeUnknown?: true; assumedSpendMicroUsd?: number` (Task 6/7 consume these — defined HERE so both adapters validate consistently)
  - Rule: a 200 whose body fails validation is **not** a success and **not** a known-zero-spend failure — it returns `classification: "malformed_response"` with `upstreamOutcomeUnknown: true` and worst-case assumed spend.

- [ ] **Step 1: Write the failing tests** (`services/tee-sim/src/providers.test.ts`)

```ts
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { AnthropicAdapter, OpenAICompatibleAdapter } from "./providers.js";

// The §69 gate blocks direct construction of authorized values; adapter unit
// tests only need the structural fields complete() reads.
function fakeAuthorized(model: string, messages: Array<{ role: string; content: string }>) {
  const request = { request: { model, messages, temperature_millis: 0, max_tokens: 64 } } as never;
  const credential = { secret: "sk-ant-test-000000000000" } as never;
  return { request, credential };
}

let server: Server | undefined;
let lastReq: { url?: string; headers: Record<string, string | string[] | undefined>; body: string };

function start(status: number, payload: unknown): Promise<number> {
  return new Promise((resolve) => {
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        lastReq = { url: req.url, headers: req.headers, body };
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(payload));
      });
    });
    server.listen(0, "127.0.0.1", () => resolve((server!.address() as { port: number }).port));
  });
}
after(() => server?.close());

test("anthropic adapter: wire shape, headers, parsing", async () => {
  const port = await start(200, {
    content: [{ type: "text", text: "hello from claude" }],
    usage: { input_tokens: 10, output_tokens: 5 },
  });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [
    { role: "system", content: "be brief" },
    { role: "user", content: "hi" },
  ]);
  const outcome = await adapter.complete(request, credential);

  assert.ok(outcome.ok, "expected success");
  assert.equal(outcome.response.content, "hello from claude");
  assert.equal(outcome.response.inputTokens, 10);
  assert.equal(outcome.response.outputTokens, 5);
  assert.equal(lastReq.url, "/v1/messages");
  assert.equal(lastReq.headers["x-api-key"], "sk-ant-test-000000000000");
  assert.equal(lastReq.headers["anthropic-version"], "2023-06-01");
  assert.equal(lastReq.headers["authorization"], undefined, "no bearer header on anthropic");
  const sent = JSON.parse(lastReq.body);
  assert.equal(sent.system, "be brief", "system messages lift to top-level system");
  assert.deepEqual(sent.messages, [{ role: "user", content: "hi" }]);
  assert.equal(sent.max_tokens, 64);
});

test("anthropic adapter: 401 classifies auth_failed and reads no body", async () => {
  const port = await start(401, { error: { message: "sk-ant-echo-attempt" } });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [{ role: "user", content: "hi" }]);
  const outcome = await adapter.complete(request, credential);
  assert.ok(!outcome.ok);
  assert.equal(outcome.classification, "auth_failed");
  assert.notEqual(outcome.upstreamOutcomeUnknown, true, "a definitive 401 is a KNOWN outcome");
});

test("a malformed 200 is NEVER a zero-cost success — both adapters", async () => {
  for (const make of [
    (port: number) => new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]),
    (port: number) => new OpenAICompatibleAdapter("openai", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]),
  ]) {
    const port = await start(200, { totally: "unexpected" });
    process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
    const adapter = make(port);
    const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [{ role: "user", content: "hi" }]);
    const outcome = await adapter.complete(request, credential);
    assert.ok(!outcome.ok, `${adapter.name}: malformed 200 must not be ok`);
    assert.equal(outcome.classification, "malformed_response");
    assert.equal(outcome.upstreamOutcomeUnknown, true, "the provider DID process it — spend unknown");
    assert.ok((outcome.assumedSpendMicroUsd ?? 0) > 0);
    server!.close();
  }
});

test("negative or non-integer usage counts are malformed", async () => {
  const port = await start(200, {
    content: [{ type: "text", text: "x" }],
    usage: { input_tokens: -5, output_tokens: 2.5 },
  });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [{ role: "user", content: "hi" }]);
  const outcome = await adapter.complete(request, credential);
  assert.ok(!outcome.ok);
  assert.equal(outcome.classification, "malformed_response");
});
```

- [ ] **Step 2: Run to verify failure** — `AnthropicAdapter` not exported; new fields missing (TS errors count as the failure).

- [ ] **Step 3: Implement**

Extend the failure arm of `ProviderOutcome`:

```ts
      classification:
        | "auth_failed" | "rate_limited" | "server_error" | "timeout"
        | "egress_denied" | "malformed_response";
      /**
       * §5.1 — the request was dispatched and no definitive answer exists
       * (timeout, transport failure, or a 200 we could not parse). The
       * provider may have processed AND billed it: cap accounting must
       * assume the conservative estimate.
       */
      upstreamOutcomeUnknown?: true;
      assumedSpendMicroUsd?: number;
```

Shared validation helper (in `providers.ts`):

```ts
function validUsage(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}
```

`AnthropicAdapter` — mirror `OpenAICompatibleAdapter`'s structure exactly (egress check → `egress_denied` with NO unknown flag, since nothing was dispatched; manual redirect; no error-body reads; abort timer), with these differences:

```ts
export class AnthropicAdapter implements ProviderAdapter {
  constructor(
    readonly name: string,
    private readonly baseUrl: string,
    private readonly models: string[]
  ) {}

  supportsModel(model: string): boolean {
    return this.models.includes(model);
  }

  async complete(
    request: AuthorizedRequest,
    credential: AuthorizedCredential
  ): Promise<ProviderOutcome> {
    const url = `${this.baseUrl}/v1/messages`;
    const started = performance.now();
    try {
      assertEgressAllowed(url);
    } catch {
      return { ok: false, httpStatus: 0, latencyMs: Math.round(performance.now() - started), classification: "egress_denied" };
    }

    const system = request.request.messages
      .filter((m) => m.role === "system")
      .map((m) => m.content)
      .join("\n");
    const body = {
      model: request.request.model,
      max_tokens: request.request.max_tokens,
      ...(system ? { system } : {}),
      messages: request.request.messages
        .filter((m) => m.role !== "system")
        .map((m) => ({ role: m.role, content: m.content })),
      temperature: request.request.temperature_millis / 1000,
    };
    const upstreamRequestHash = "0x" + canonicalHash(body);
    const unknownOutcome = (latencyMs: number, classification: "timeout" | "server_error" | "malformed_response") =>
      ({
        ok: false as const, httpStatus: 0, latencyMs, classification,
        upstreamOutcomeUnknown: true as const,
        assumedSpendMicroUsd: estimateWorstCaseMicroUsd(
          request.request.model, request.request.messages, request.request.max_tokens
        ),
      });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), providerTimeoutMs());
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          // The only place the contributed secret is ever used.
          "x-api-key": credential.secret,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify(body),
        signal: controller.signal,
        redirect: "manual",
      });
      const latencyMs = Math.round(performance.now() - started);

      if (res.status >= 300 && res.status < 400) {
        return { ok: false, httpStatus: res.status, latencyMs, classification: "egress_denied" };
      }
      if (!res.ok) {
        // A definitive HTTP error is a KNOWN outcome. Do not read the body (§58).
        const classification =
          res.status === 401 || res.status === 403
            ? ("auth_failed" as const)
            : res.status === 429
              ? ("rate_limited" as const)
              : ("server_error" as const);
        return { ok: false, httpStatus: res.status, latencyMs, classification };
      }

      let json: {
        content?: Array<{ type?: string; text?: string }>;
        usage?: { input_tokens?: unknown; output_tokens?: unknown };
      };
      try {
        json = (await res.json()) as typeof json;
      } catch {
        return unknownOutcome(Math.round(performance.now() - started), "malformed_response");
      }
      const inputTokens = json.usage?.input_tokens;
      const outputTokens = json.usage?.output_tokens;
      const blocks = json.content;
      if (!validUsage(inputTokens) || !validUsage(outputTokens) || !Array.isArray(blocks)) {
        // The provider processed the request; a response we cannot account for
        // must never become a zero-spend success.
        return unknownOutcome(latencyMs, "malformed_response");
      }
      const content = blocks.filter((b) => b.type === "text").map((b) => b.text ?? "").join("");

      return {
        ok: true,
        response: {
          content,
          inputTokens,
          outputTokens,
          estimatedCostMicroUsd: estimateCostMicroUsd(request.request.model, inputTokens, outputTokens),
          pricingTableDigest: PRICING_TABLE_DIGEST,
          upstreamRequestHash,
          upstreamResponseHash: "0x" + canonicalHash({ content, inputTokens, outputTokens }),
          httpStatus: res.status,
          latencyMs,
        },
      };
    } catch (err) {
      const latencyMs = Math.round(performance.now() - started);
      // ANY exception after dispatch — abort, reset, DNS mid-flight — is an
      // unknown upstream outcome. Only pre-dispatch failures are known.
      const aborted = err instanceof Error && err.name === "AbortError";
      return unknownOutcome(latencyMs, aborted ? "timeout" : "server_error");
    } finally {
      clearTimeout(timer);
    }
  }
}
```

Apply the same three changes to `OpenAICompatibleAdapter`: (a) validate `choices[0].message.content` present and usage via `validUsage` → else `unknownOutcome(..., "malformed_response")` (add the same helper usage there); (b) catch-block returns `unknownOutcome` for post-dispatch exceptions; (c) `providerTimeoutMs()` function replaces the module-scope constant:

```ts
function providerTimeoutMs(): number {
  return Number(process.env.CTN_PROVIDER_TIMEOUT_MS ?? 20_000);
}
```

- [ ] **Step 4: Run tests** — `pnpm --filter @ctn/tee-sim test`: PASS.
Confirm the canonical-request field names (`temperature_millis`, `max_tokens`, `messages[].role/content`) against `toCanonicalRequest` in `packages/protocol`; adjust the adapter (not the protocol) if they differ.

- [ ] **Step 5: Commit**

```bash
git add services/tee-sim/src/providers.ts services/tee-sim/src/providers.test.ts
git commit -m "providers: AnthropicAdapter; malformed 200s and post-dispatch failures are unknown outcomes"
```

---

### Task 5: Registry from the catalog + egress narrowing

**Files:**
- Modify: `services/tee-sim/src/providers.ts` (allowlist at :20-31; `buildRegistry` at :215-222)
- Test: `services/tee-sim/src/providers.test.ts` (append)

**Interfaces:**
- Consumes: `AnthropicAdapter` (Task 4), `MODEL_CATALOG` (Task 1).
- Produces: registry entries `"mock" | "openai" | "anthropic"` built FROM the catalog (single source of truth); allowlist without Google. Task 8's endpoint reads `buildRegistry()`; make `models` readable: add `readonly models: readonly string[]` to the `ProviderAdapter` interface and both classes.

- [ ] **Step 1: Write the failing tests** (append)

```ts
import { assertEgressAllowed, EgressDeniedError, buildRegistry } from "./providers.js";
import { MODEL_CATALOG } from "./catalog.js";

test("egress allowlist is exactly the implemented providers", () => {
  delete process.env.CTN_EGRESS_ALLOWLIST;
  assertEgressAllowed("https://api.anthropic.com/v1/messages");
  assertEgressAllowed("https://api.openai.com/v1/chat/completions");
  assert.throws(() => assertEgressAllowed("https://generativelanguage.googleapis.com/v1"), EgressDeniedError);
});

test("registry models come from the catalog — one source of truth", () => {
  const r = buildRegistry();
  for (const [provider, models] of Object.entries(MODEL_CATALOG)) {
    assert.deepEqual([...r.get(provider)!.models], [...models], provider);
  }
});
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement**

- `allowlist()`: delete `"generativelanguage.googleapis.com:443"`.
- `ProviderAdapter` gains `readonly models: readonly string[]`; both classes change `private readonly models` → `readonly models`.
- `buildRegistry()`:

```ts
export function buildRegistry(): Map<string, ProviderAdapter> {
  const registry = new Map<string, ProviderAdapter>();
  const mockUrl = process.env.MOCK_PROVIDER_URL ?? "http://127.0.0.1:4300";
  registry.set("mock", new OpenAICompatibleAdapter("mock", mockUrl, [...MODEL_CATALOG.mock]));
  registry.set("openai", new OpenAICompatibleAdapter("openai", "https://api.openai.com", [...MODEL_CATALOG.openai]));
  registry.set("anthropic", new AnthropicAdapter("anthropic", "https://api.anthropic.com", [...MODEL_CATALOG.anthropic]));
  return registry;
}
```

- [ ] **Step 4: Run gates** — package tests, then `pnpm test` + `npx tsc --noEmit -p tsconfig.json`.

- [ ] **Step 5: Commit**

```bash
git add services/tee-sim/src/providers.ts services/tee-sim/src/providers.test.ts
git commit -m "registry: catalog-driven models; drop google from egress"
```

---

### Task 6: Single-dispatch routing

The spec's "no retries" invariant vs. the existing §18 loop (`services/tee-sim/src/index.ts:349`), which falls through to the next credential after ANY provider failure. New rule: pre-dispatch failures (`authorizationFailures`, `egress_denied`) may continue the candidate loop; once one upstream request has been dispatched, the loop terminates on any outcome.

**Files:**
- Modify: `services/tee-sim/src/index.ts:349-395` (the candidate loop)
- Modify: `scripts/test-e2e.mts` (the existing rate-limit-fallback test — find it via `grep -n '"-RATE"' scripts/test-e2e.mts` and the `-RATE` prompt helper — its expectations change)
- Test: `scripts/test-e2e.mts` (append single-dispatch test)

**Interfaces:**
- Consumes: `ProviderOutcome.classification` (Task 4's union).
- Produces: at most one attempt with a dispatched outcome per request. Failure code selection (`CTN_PROVIDER_*`) is unchanged. The old fallback story survives at *request* granularity: a 429 cools the credential down, so the **next** request routes elsewhere — update the e2e test to assert exactly that.

- [ ] **Step 1: Update the rate-limit e2e test + add the single-dispatch test**

Rewrite the existing `-RATE` fallback test's assertions: the rate-limited request now FAILS with `CTN_PROVIDER_RATE_LIMITED` and exactly one provider attempt; a follow-up request (same contributor pool) succeeds via a different credential because the 429'd one is cooling down. Then append:

```ts
await test("63", "single dispatch: a dispatched failure never falls through to a second credential", async () => {
  // Preconditions: at least two eligible credentials for the model (seeded).
  const res = await submitPrompt("hello -RATE"); // helper reused from the neighbouring tests
  assert(res.status === "FAILED", `expected FAILED, got ${res.status}`);
  const dispatched = res.attempts.filter((a: { classification?: string }) => a.classification !== "egress_denied");
  assert(dispatched.length === 1, `expected exactly 1 dispatched attempt, got ${dispatched.length}`);
});
```

- [ ] **Step 2: Run to verify failure** — the current loop makes a second attempt; test 63 FAILS.

- [ ] **Step 3: Implement** — replace the loop's failure tail:

```ts
    lastFailure = outcome;
    // §5.1 single dispatch — the prompt has now been sent upstream once.
    // Sending it again (to another credential, another provider) would double
    // both the spend risk and the exposure surface. Only provably
    // pre-dispatch failures may try the next candidate.
    if (outcome.classification !== "egress_denied") break;
```

(The `authorizationFailures` `continue`s above the dispatch point are untouched — they are pre-dispatch by construction.)

- [ ] **Step 4: Run gates** — full `pnpm test`, restart stack, `pnpm test:e2e` (updated -RATE test + test 63 green; expect the seeded-graph denial visuals to be unaffected — seeded traffic doesn't trigger provider failures).

- [ ] **Step 5: Commit**

```bash
git add services/tee-sim/src/index.ts scripts/test-e2e.mts
git commit -m "routing: single dispatch — dispatched failures terminate the candidate loop"
```

---

### Task 7: Assumed-spend cap enforcement (atomic) + attempt schema migration

**Files:**
- Modify: `services/coordinator/src/db.ts` (schema: `provider_attempts` gains `upstream_outcome_unknown INTEGER NOT NULL DEFAULT 0` and `assumed_spend_micro_usd INTEGER`; tolerant `ALTER TABLE` migration for existing DBs)
- Modify: `services/coordinator/src/routing.ts` (new `recordAssumedUsage`; attempt persistence writes the new columns)
- Modify: `services/tee-sim/src/index.ts` (attempt records forwarded to the coordinator carry `upstreamOutcomeUnknown` + `assumedSpendMicroUsd` from the outcome — extend the `attempts.push({...})` at :369-377 and the `AttemptRecord` type it satisfies)
- Modify: `services/mock-provider/src/index.ts` (add `-HANG` trigger next to the existing `-RATE` trigger: `await new Promise((r) => setTimeout(r, 25_000))` before responding)
- Test: coordinator unit test `services/coordinator/src/routing.test.ts` (append or create per coordinator conventions); `scripts/test-e2e.mts` (append slow test)

**Interfaces:**
- Consumes: Task 4's outcome fields.
- Produces:

```ts
export function recordAssumedUsage(args: {
  requestId: string;
  credentialId: string;
  contributorId: string;
  assumedSpendMicroUsd: number;
}): void
```

— in ONE transaction: inserts a `usage` row (tokens 0, `estimated_cost_usd` = micro/1e6) **and** increments the same per-credential daily counters `recordUsage` increments (`estimated_cost_today_usd` — copy the exact `UPDATE credentials SET ...` statement from `recordUsage` at `routing.ts:194` and reuse it), **including `requests_today`** — an unknown outcome consumes a request slot; under-counting either number would let a wedged provider drain a cap unbounded.

- [ ] **Step 1: Write the failing coordinator unit test**

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { db } from "./db.js";              // match the module's actual export
import { recordAssumedUsage } from "./routing.js";

test("assumed usage enforces the cap exactly like real usage", () => {
  // Insert a minimal credential row (copy the INSERT used by neighbouring
  // coordinator tests — they seed rows directly).
  const before = db.prepare(`SELECT estimated_cost_today_usd, requests_today FROM credentials WHERE id = ?`).get("cred_test") as { estimated_cost_today_usd: number; requests_today: number };
  recordAssumedUsage({ requestId: "req_t", credentialId: "cred_test", contributorId: "contrib_t", assumedSpendMicroUsd: 2_500 });
  const after = db.prepare(`SELECT estimated_cost_today_usd, requests_today FROM credentials WHERE id = ?`).get("cred_test") as { estimated_cost_today_usd: number; requests_today: number };
  assert.ok(after.estimated_cost_today_usd > before.estimated_cost_today_usd, "cost counter must move");
  assert.equal(after.requests_today, before.requests_today + 1, "request slot consumed");
  const usage = db.prepare(`SELECT * FROM usage WHERE request_id = ?`).get("req_t") as { estimated_cost_usd: number; input_tokens: number };
  assert.equal(usage.input_tokens, 0);
  assert.ok(Math.abs(usage.estimated_cost_usd - 0.0025) < 1e-9);
});
```

(Read the daily-counter column names from `db.ts` / `recordUsage` first — use whatever `recordUsage` actually increments, verbatim; if `requests_today` has a different name, follow the schema.)

- [ ] **Step 2: Run to verify failure** — `recordAssumedUsage` doesn't exist.

- [ ] **Step 3: Implement**

- `db.ts`: add the two columns to the `provider_attempts` CREATE TABLE; below the schema exec, add tolerant migrations:

```ts
for (const ddl of [
  `ALTER TABLE provider_attempts ADD COLUMN upstream_outcome_unknown INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE provider_attempts ADD COLUMN assumed_spend_micro_usd INTEGER`,
]) {
  try { db.exec(ddl); } catch { /* column already exists */ }
}
```

- `routing.ts`: implement `recordAssumedUsage` wrapped in `db.transaction(...)`, reusing `recordUsage`'s INSERT and UPDATE statements with tokens 0 / cost `assumedSpendMicroUsd / 1_000_000`, plus the `requests_today` increment.
- Attempt persistence (wherever `provider_attempts` rows are inserted — grep `INSERT INTO provider_attempts`): write the two new columns from the attempt record.
- Call site: where the coordinator processes a completed/failed request's attempts (same place `recordUsage` is invoked for successes — follow `recordUsage`'s callers), invoke `recordAssumedUsage` for every attempt with `upstreamOutcomeUnknown && assumedSpendMicroUsd`.
- tee-sim: extend the `attempts.push({...})` record and `AttemptRecord` type with the two optional fields copied from the outcome.
- mock-provider: add the `-HANG` trigger.

- [ ] **Step 4: Slow e2e test** (append)

```ts
await test("64", "unknown outcome books conservative spend against the cap (slow: ~21s)", async () => {
  const before = await credentialUsage(credentialId);   // helper mirroring the dashboard usage fetch in neighbouring tests
  const res = await submitPrompt("summarize this please -HANG");
  assert(res.status === "FAILED", `expected FAILED, got ${res.status}`);
  const attempt = res.attempts.find((a: { upstreamOutcomeUnknown?: boolean }) => a.upstreamOutcomeUnknown);
  assert(attempt, "attempt must be flagged unknown");
  const after = await credentialUsage(credentialId);
  assert(after.cost > before.cost, "assumed spend must appear in cap accounting");
  assert(after.requests > before.requests, "request slot consumed");
});
```

- [ ] **Step 5: Run gates** — coordinator + tee-sim tests, `npx tsc --noEmit -p tsconfig.json`, restart stack, `pnpm test:e2e` (~21s slower).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "assumed spend: atomic cap enforcement + attempt schema migration"
```

---

### Task 8: Provider catalog endpoint + UI wiring

**Files:**
- Modify: `services/tee-sim/src/index.ts` (add `GET /providers`)
- Modify: `services/coordinator/src/index.ts` (add `GET /v1/providers`) and `services/coordinator/src/tee-client.ts` (add `providers()`)
- Modify: `apps/web/src/app/contribute/page.tsx` (provider picker + models from catalog)
- Modify: `apps/web/src/app/playground/page.tsx` (model picker from catalog)
- Test: `scripts/test-e2e.mts` (append)

**Interfaces:**
- Consumes: `buildRegistry()` with `readonly models` (Task 5).
- Produces: `GET /v1/providers` → `{ providers: [{ provider: string, models: string[] }] }`, alphabetical.

- [ ] **Step 1: Failing e2e test**

```ts
await test("65", "provider catalog serves implemented providers with pinned model ids", async () => {
  const res = await fetch(`${COORD}/v1/providers`);
  const json = await res.json() as { providers: Array<{ provider: string; models: string[] }> };
  const names = json.providers.map((p) => p.provider);
  assert(JSON.stringify(names) === JSON.stringify(["anthropic", "mock", "openai"]), `got ${names}`);
  const anthropic = json.providers.find((p) => p.provider === "anthropic")!;
  assert(anthropic.models.includes("claude-haiku-4-5-20251001"), "pinned snapshot ids listed");
});
```

- [ ] **Step 2: Run to verify failure** — 404.

- [ ] **Step 3: Implement**

tee-sim:

```ts
app.get("/providers", async () => ({
  providers: [...registry.entries()]
    .map(([provider, adapter]) => ({ provider, models: [...adapter.models] }))
    .sort((a, b) => a.provider.localeCompare(b.provider)),
}));
```

Coordinator: `tee-client.ts` gains `providers()` following the existing method style; `index.ts`:

```ts
app.get("/v1/providers", async () => teeClient.providers());
```

- [ ] **Step 4: Wire the web UI** — `grep -n "ctn/demo-model" apps/web/src` to find hardcoded model constants; replace with a fetch of `/v1/providers` using each page's existing data-fetch idiom. Contribute page: provider `<select>` from the catalog; models multiselect filtered by chosen provider. Playground: model select grouped by provider. Keep all existing styling; change data sources only.

- [ ] **Step 5: Run gates** — `pnpm test:e2e` (test 65), `pnpm --filter @ctn/web build` clean.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "provider catalog endpoint; contribute/playground driven by registry"
```

---

### Task 9: Redaction hardening for real key material

**Files:**
- Modify: `services/coordinator/src/safe-log.ts` (FORBIDDEN_KEYS + SECRET_VALUE_PATTERNS)
- Modify: `services/tee-sim/src/enclave-log.ts` (SECRET_VALUE_PATTERNS)
- Test: `services/coordinator/src/safe-log.test.ts`; `services/tee-sim/src/enclave-log.test.ts` (create or append per each package's conventions)

- [ ] **Step 1: Write the failing tests**

Coordinator (`safe-log.test.ts`):

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { redact } from "./safe-log.js";

test("real provider auth headers are redacted by key", () => {
  const out = redact({
    "x-api-key": "sk-ant-real-key-123456789",
    Authorization: "Bearer sk-real-key-123456789",
    "anthropic-version": "2023-06-01",
  }) as Record<string, string>;
  assert.equal(out["x-api-key"], "[redacted-by-safeLog]");
  assert.equal(out["Authorization"], "[redacted-by-safeLog]");
  assert.equal(out["anthropic-version"], "2023-06-01");
});

test("key-shaped VALUES are redacted even under innocent keys", () => {
  const out = redact({ note: "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA" }) as Record<string, string>;
  assert.equal(out.note, "[redacted-by-safeLog]");
});
```

tee-sim (`enclave-log.test.ts`): the same two cases against `enclave-log.ts`'s exported redaction function (read lines 1-30 for its export name; marker is `"[redacted-by-enclaveSafe]"`).

- [ ] **Step 2: Run** — keep whichever assertions fail as the work list (`sk-ant-…` value patterns are new at minimum).

- [ ] **Step 3: Implement**

- `FORBIDDEN_KEYS` (coordinator): ensure `x-api-key`, `xapikey`, `authorization` match after `normalizeKey` (read it — it likely lowercases/strips separators).
- `SECRET_VALUE_PATTERNS` (both): add `/sk-[A-Za-z0-9_-]{16,}/` (covers `sk-ant-…` and OpenAI `sk-…`; 16-char floor avoids redacting literal "sk-test").

- [ ] **Step 4: Run gates** — package tests + `pnpm privacy-test` against a running stack (0 leaks across all surfaces).

- [ ] **Step 5: Commit**

```bash
git add services/coordinator/src services/tee-sim/src
git commit -m "redaction: cover x-api-key/authorization keys and sk-* values"
```

---

### Task 10: Real-provider smoke tests + labelling updates

**Files:**
- Modify: `scripts/test-e2e.mts` (gated smoke section at the end)
- Modify: `README.md`, `apps/web/src/app/trust/page.tsx`, `VALIDATION.md`

- [ ] **Step 1: Gated smoke tests** (append)

```ts
if (process.env.ANTHROPIC_API_KEY) {
  await test("70", "REAL anthropic round-trip (spends ~<$0.01)", async () => {
    const cred = await contributeViaClient({
      provider: "anthropic",
      apiKey: process.env.ANTHROPIC_API_KEY!,
      allowedModels: ["claude-haiku-4-5-20251001"],
      label: "smoke-anthropic",
    }); // helper: wrap the same @ctn/client call the seed script uses
    const res = await submitPrompt("Reply with the single word: pong", {
      model: "claude-haiku-4-5-20251001",
      maxTokens: 16,
    });
    assert(res.status === "COMPLETE", `expected COMPLETE, got ${res.status}: ${JSON.stringify(res.error)}`);
    assert(res.receipt.usage.inputTokens > 0, "real token counts recorded");
    assert(res.receipt.usage.pricingTableDigest?.startsWith("0x"), "pricing digest present");
    await revokeCredential(cred.id); // never leave a real key active after the test
  });
} else {
  console.log("  · skipping real-provider smoke (set ANTHROPIC_API_KEY to run)");
}
```

Mirror for `OPENAI_API_KEY` with `gpt-4o-mini-2024-07-18` as test "71". Build `contributeViaClient` / `submitPrompt` / `revokeCredential` from the seed script's and tests 56.x's existing code.

- [ ] **Step 2: Run without keys** — skip lines print; everything else green.

- [ ] **Step 3: Run once WITH a real key** — test 70 passes; dashboard shows real spend; credential revoked after.

- [ ] **Step 4: Labelling updates** (equal weight, per the honesty invariant):

- `README.md` real/simulated table, provider row → **Real**: "Anthropic and OpenAI adapters call the live APIs with contributed keys, pinned to dated snapshot model IDs. Costs are estimates from a pinned price table over provider-reported token counts; a timeout or unparseable response leaves upstream spend unknown and is booked conservatively. One dispatch per request — never retried."
- `trust/page.tsx`: same content in the real column; simulated column keeps TEE + (until Phase 2) proof rows, and gains: "Intent replay protection is in-memory — an enclave restart forgets consumed nonces (the sealed credentialId still prevents duplicate minting)."
- `VALIDATION.md` addendum "Phase 1": intent binding (was: coordinator-alterable metadata + recapability oracle), replay protection design and its restart caveat, single-dispatch rule (was: §18 fall-through), UPSTREAM_OUTCOME_UNKNOWN accounting rule, pinned-snapshot model consent, and: unknown-outcome requests have **no receipt** in Phase 1 (visible in attempts + usage only; the Phase 2 receipt split represents them properly).

- [ ] **Step 5: Full final gates**

```bash
npx tsc --noEmit -p tsconfig.json && pnpm test && pnpm --filter @ctn/web build
pnpm reset && pnpm dev &   # fresh stack
pnpm seed && pnpm test:e2e && pnpm privacy-test
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "phase 1 complete: real-provider smoke tests + honesty labelling"
```

---

## Self-review notes (already applied)

- **Atomicity:** old Tasks 1–3 are now one task/commit; every task's commit leaves `tsc` + `pnpm test` green.
- **Replay:** client-generated `credentialId` sealed in the intent + enclave in-memory `intentDigest` set + e2e test 59; restart caveat labelled.
- **Single dispatch:** Task 6 implements the invariant the plan previously only declared; the `-RATE` fallback e2e test's expectations are explicitly updated.
- **Caps:** `recordAssumedUsage` is transactional and moves the same counters as `recordUsage`, including `requests_today`; schema migration included.
- **Worst case:** UTF-8-byte token bound with per-message overhead, unit-tested against multibyte input.
- **Unknown breadth:** every post-dispatch exception and malformed 200 is unknown-outcome; only `egress_denied` (and pre-dispatch authz skips) are known-safe.
- **Strict intents:** exact key set, catalog membership, pinned snapshot IDs, dupes/caps rejected.
- Type-consistency check: `estimateWorstCaseMicroUsd(model, messages, maxTokens)` — Task 3 defines, Task 4 consumes with `request.request.messages`; `ProviderAdapter.models` — Task 5 defines, Task 8 consumes; `upstreamOutcomeUnknown`/`assumedSpendMicroUsd` — Task 4 defines, Tasks 6/7 consume.

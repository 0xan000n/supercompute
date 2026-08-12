# Phase 1: Intent-Bound Contribution + Real Providers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A contributor's API key travels in one HPKE envelope *together with their constraints* (provider, models, policies), the enclave derives capabilities only from that sealed intent, capabilities become immutable, and prompts proxy to real Anthropic/OpenAI APIs with honest cost accounting.

**Architecture:** Extends the existing five-package pnpm workspace in place. A new `CredentialIntentV1` protocol type replaces the split key/metadata contribution; a new pure `intent.ts` module in tee-sim derives capabilities; the recapability endpoint is deleted; `providers.ts` gains an `AnthropicAdapter` and a shared checked-in pricing table with digest.

**Tech Stack:** TypeScript, Fastify, better-sqlite3, `@hpke/core` (already present), `node:test` via `tsx --test`. **No new dependencies in this phase.**

**Spec:** `docs/superpowers/specs/2026-08-11-supercompute-real-design.md` (§5.1, §7, §8, §10)

## Global Constraints

- Local demo only; no authentication; must not be network-exposed.
- Non-streaming only; `max_tokens` required.
- **No provider retries.** No inference call is ever retried.
- All money is **integer micro-USD** (receipts are signed over canonical bytes; floats forbidden in signed structures).
- Egress allow-list is exactly `api.openai.com:443`, `api.anthropic.com:443`, plus `CTN_EGRESS_ALLOWLIST` env extras (used for the local mock). Google's endpoint is removed.
- Capabilities are **immutable**: editing = revoke + re-contribute. No re-signing endpoint may exist.
- Honesty labelling: any UI/docs claim changed here must state limitations at equal weight (pricing is an estimate from a pinned table; timeout spend is unknown).
- Test runner everywhere: `tsx --test src/*.test.ts` with `node:test` + `node:assert/strict`.
- Full-repo gates that must stay green after every task: `npx tsc --noEmit -p tsconfig.json` and `pnpm test`.

---

### Task 1: `CredentialIntentV1` + `intentDigest()` in the protocol package

**Files:**
- Modify: `packages/protocol/src/types.ts` (add intent interface; extend `CredentialCapability`; slim `CredentialSubmission`)
- Modify: `packages/protocol/src/crypto.ts` (add `intentDigest`)
- Modify: `packages/protocol/src/index.ts` (export both — follow the existing export list style)
- Test: `packages/protocol/src/protocol.test.ts` (append)

**Interfaces:**
- Consumes: existing `canonicalJson`, `sha256`, `toHex`, `utf8` in `crypto.ts`; existing `Provider` type.
- Produces (later tasks rely on these exact names):
  - `interface CredentialIntentV1 { version: 1; secret: string; provider: Provider; allowedModels: string[]; allowedPolicies: string[]; contributorId: string; intentNonce: string }`
  - `function intentDigest(intent: CredentialIntentV1): string` — `"0x"`-prefixed hex
  - `CredentialCapability.intentDigest: string` (new required field)

- [ ] **Step 1: Write the failing tests** (append to `packages/protocol/src/protocol.test.ts`)

```ts
import { intentDigest, type CredentialIntentV1 } from "./crypto";

const baseIntent: CredentialIntentV1 = {
  version: 1,
  secret: "sk-test-000000000000",
  provider: "anthropic",
  allowedModels: ["claude-haiku-4-5"],
  allowedPolicies: ["safety-v1"],
  contributorId: "contrib_alice",
  intentNonce: "a".repeat(64),
};

test("intentDigest is deterministic and 0x-prefixed", () => {
  const a = intentDigest(baseIntent);
  const b = intentDigest({ ...baseIntent });
  assert.equal(a, b);
  assert.match(a, /^0x[0-9a-f]{64}$/);
});

test("intentDigest ignores the secret — same constraints, different key, same digest", () => {
  const other = intentDigest({ ...baseIntent, secret: "sk-test-999999999999" });
  assert.equal(other, intentDigest(baseIntent));
});

test("intentDigest binds every constraint field", () => {
  const base = intentDigest(baseIntent);
  assert.notEqual(intentDigest({ ...baseIntent, provider: "openai" }), base);
  assert.notEqual(intentDigest({ ...baseIntent, allowedModels: ["gpt-4o"] }), base);
  assert.notEqual(intentDigest({ ...baseIntent, contributorId: "contrib_bob" }), base);
  assert.notEqual(intentDigest({ ...baseIntent, intentNonce: "b".repeat(64) }), base);
});
```

(Type import from `"./crypto"` because the digest helper and the interface it hashes live together — put the interface in `types.ts` and re-export the type from `crypto.ts`'s import, i.e. the test imports the type from wherever `intentDigest` is exported; match the file's existing import style.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm --filter @ctn/protocol test`
Expected: FAIL — `intentDigest` is not exported.

- [ ] **Step 3: Implement**

In `packages/protocol/src/types.ts`, next to `CredentialSubmission`:

```ts
/**
 * The contributor's sealed intent — the ONLY authority on what a credential
 * may do. HPKE-sealed in the contributor's browser to the attested ingress
 * key; the enclave derives the signed capability exclusively from this.
 * The coordinator never sees it and can therefore never alter it.
 */
export interface CredentialIntentV1 {
  version: 1;
  secret: string;
  provider: Provider;
  allowedModels: string[];
  allowedPolicies: string[];
  contributorId: string;
  /** 32-byte hex, fresh per contribution; makes every sealed intent unique */
  intentNonce: string;
}
```

Extend `CredentialCapability` (after `blobDigest`, matching its comment style):

```ts
  /**
   * SHA-256 over the canonical intent minus the secret. Ties this capability
   * to exactly what the contributor sealed — a coordinator that relays the
   * envelope has nothing left to tamper with.
   */
  intentDigest: string;
```

Slim `CredentialSubmission` — the plaintext `capability` block is the tampering
surface this task removes:

```ts
/** §13 — credential submission; the intent (key + constraints) is HPKE-sealed. */
export interface CredentialSubmission {
  enclaveKeyId: string;
  enc: string;
  encryptedSecret: string;
  contributorDisplayId: string;
}
```

In `packages/protocol/src/crypto.ts` (below `requestCommitment`, same idiom):

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

Add the `CredentialIntentV1` type import to `crypto.ts` and export both from `index.ts`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pnpm --filter @ctn/protocol test`
Expected: PASS (all pre-existing 16 protocol tests + 3 new).
Note: `tsc --noEmit -p tsconfig.json` will FAIL right now — `CredentialCapability.intentDigest` is required and tee-sim doesn't set it yet. That is expected; Task 3 fixes it. Do not make the field optional to dodge this.

- [ ] **Step 5: Commit**

```bash
git add packages/protocol/src
git commit -m "protocol: CredentialIntentV1 + intentDigest, capability binds sealed intent"
```

---

### Task 2: Client seals the full intent

**Files:**
- Modify: `packages/client/src/index.ts:287-334` (`contributeCredential`)
- Test: `packages/protocol/src/protocol.test.ts` (append — seal/open round-trip lives at protocol level; the client package has no test harness)

**Interfaces:**
- Consumes: `CredentialIntentV1`, `canonicalJson`, `hpkeSeal`, `randomHex` from `@ctn/protocol` (Task 1).
- Produces: `contributeCredential` keeps its external signature. The POST body to `/v1/credentials` becomes exactly `{ contributorId, label, weight, operationalLimits, enclaveKeyId, enc, encryptedSecret }` — **no** `provider`, `allowedModels`, or `allowedPolicies` fields (Task 3's coordinator consumes this shape).

- [ ] **Step 1: Write the failing round-trip test** (append to `protocol.test.ts`)

```ts
import { generateHpkeKeyPair, hpkeSeal, hpkeOpen } from "./hpke";
import { canonicalJson } from "./canonical";

test("a sealed intent round-trips: key and constraints travel in ONE envelope", async () => {
  const enclave = await generateHpkeKeyPair();
  const intent: CredentialIntentV1 = { ...baseIntent };
  const sealed = await hpkeSeal(enclave.publicKeyB64, new TextEncoder().encode(canonicalJson(intent)));
  const opened = JSON.parse(new TextDecoder().decode(await hpkeOpen(enclave.privateKeyB64, sealed))) as CredentialIntentV1;
  assert.deepEqual(opened, intent);
});
```

(Reuse `baseIntent` from Task 1's tests. If `generateHpkeKeyPair`'s property names differ — check `packages/protocol/src/hpke.ts` — use the names it actually returns.)

- [ ] **Step 2: Run, verify it fails or passes for the right reason**

Run: `pnpm --filter @ctn/protocol test`
This test passes immediately (it composes existing primitives) — that is fine; it is the executable contract for what the client must produce. Verify it runs green.

- [ ] **Step 3: Rewrite `contributeCredential`**

Replace the sealing + POST section of `contributeCredential` (keep the attestation
check above it untouched):

```ts
    // The key AND its constraints are sealed together, in the contributor's
    // own browser, to the attested key. The coordinator relays an opaque
    // envelope — there is no plaintext metadata left for it to alter (§5.1).
    const intent: CredentialIntentV1 = {
      version: 1,
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
        enclaveKeyId: attestation.bundle.enclaveKeyId,
        enc: sealed.enc,
        encryptedSecret: sealed.ciphertext,
      }),
    });
```

Add `CredentialIntentV1`, `canonicalJson`, `randomHex` to the `@ctn/protocol` import list. (`randomHex(32)` — confirm the existing signature in `crypto.ts`; it is exported and used by `authorize.test.ts`. If its parameter is bytes, `randomHex(32)` yields 64 hex chars, which is what `intentNonce` requires.)

- [ ] **Step 4: Typecheck**

Run: `npx tsc --noEmit -p tsconfig.json`
Expected: remaining errors ONLY in `services/tee-sim` / `services/coordinator` (fixed by Task 3). No errors in `packages/client`.

- [ ] **Step 5: Commit**

```bash
git add packages/client/src/index.ts packages/protocol/src/protocol.test.ts
git commit -m "client: seal CredentialIntentV1 — key and constraints in one envelope"
```

---

### Task 3: Enclave derives the capability from the sealed intent

**Files:**
- Create: `services/tee-sim/src/intent.ts`
- Test: `services/tee-sim/src/intent.test.ts`
- Modify: `services/tee-sim/src/index.ts:139-205` (ingestion route + `IngestBody`)
- Modify: `services/coordinator/src/index.ts:138-233` (`POST /v1/credentials`)
- Modify: `services/coordinator/src/tee-client.ts` (`ingestCredential` payload type)

**Interfaces:**
- Consumes: `CredentialIntentV1`, `intentDigest` (Task 1); existing `tee.openIngress`, `vaultEncrypt`, `tee.signReceipt`, `tee.fingerprint`, `pkg.policyId`.
- Produces:
  - `parseIntent(plaintext: Uint8Array): CredentialIntentV1` — throws `InvalidIntentError` (with `.code = "CTN_INVALID_ENVELOPE"`)
  - `deriveCapability(input: { intent: CredentialIntentV1; credentialId: string; blobDigest: string; resolvePolicyId: (label: string) => string; now: number }): CredentialCapability`
  - Ingest response unchanged in shape (`credentialId, encryptedBlob, capability, capabilitySignature, keyFingerprint, policyId`) — but `capability` now carries `intentDigest` and derives entirely from the sealed intent.

- [ ] **Step 1: Write the failing unit tests** (`services/tee-sim/src/intent.test.ts`)

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalJson, intentDigest, type CredentialIntentV1 } from "@ctn/protocol";
import { parseIntent, deriveCapability, InvalidIntentError } from "./intent.js";

const intent: CredentialIntentV1 = {
  version: 1,
  secret: "sk-test-000000000000",
  provider: "anthropic",
  allowedModels: ["claude-sonnet-4-5", "claude-haiku-4-5"],
  allowedPolicies: ["safety-v1"],
  contributorId: "contrib_alice",
  intentNonce: "a".repeat(64),
};
const bytes = (v: unknown) => new TextEncoder().encode(canonicalJson(v));

test("a valid intent parses", () => {
  assert.deepEqual(parseIntent(bytes(intent)), intent);
});

test("rejects: bad version, malformed secret, unknown provider, empty models, bad nonce", () => {
  for (const bad of [
    { ...intent, version: 2 },
    { ...intent, secret: "short" },
    { ...intent, secret: "has whitespace in it" },
    { ...intent, provider: "google" },
    { ...intent, allowedModels: [] },
    { ...intent, intentNonce: "zz" },
  ]) {
    assert.throws(() => parseIntent(bytes(bad)), InvalidIntentError);
  }
});

test("non-JSON plaintext is rejected without echoing content", () => {
  assert.throws(() => parseIntent(new TextEncoder().encode("sk-live-notjson")), (err: Error) => {
    assert.ok(!err.message.includes("sk-live"));
    return err instanceof InvalidIntentError;
  });
});

test("deriveCapability uses ONLY the intent — and binds its digest", () => {
  const cap = deriveCapability({
    intent, credentialId: "cred_x", blobDigest: "0xabc",
    resolvePolicyId: (l) => (l === "safety-v1" ? "policy_123" : l), now: 1234,
  });
  assert.equal(cap.provider, "anthropic");
  assert.deepEqual(cap.allowedModels, ["claude-haiku-4-5", "claude-sonnet-4-5"]); // sorted
  assert.deepEqual(cap.allowedPolicyIds, ["policy_123"]);
  assert.equal(cap.contributorId, "contrib_alice");
  assert.equal(cap.version, 1);
  assert.equal(cap.blobDigest, "0xabc");
  assert.equal(cap.intentDigest, intentDigest(intent));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `pnpm --filter @ctn/tee-sim test`
Expected: FAIL — `./intent.js` does not exist.

- [ ] **Step 3: Implement `services/tee-sim/src/intent.ts`**

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
  type Provider,
} from "@ctn/protocol";

export class InvalidIntentError extends Error {
  readonly code = "CTN_INVALID_ENVELOPE";
}

const IMPLEMENTED_PROVIDERS: readonly Provider[] = ["anthropic", "openai", "mock"];

export function parseIntent(plaintext: Uint8Array): CredentialIntentV1 {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    // Never echo the plaintext: it may be a raw key pasted without sealing.
    throw new InvalidIntentError("sealed intent is not valid JSON");
  }
  const i = parsed as CredentialIntentV1;
  if (i.version !== 1) throw new InvalidIntentError("unsupported intent version");
  if (typeof i.secret !== "string" || i.secret.trim().length < 8 || /\s/.test(i.secret.trim()))
    throw new InvalidIntentError("credential does not look like an API key");
  if (!IMPLEMENTED_PROVIDERS.includes(i.provider))
    throw new InvalidIntentError("provider is not implemented");
  if (!Array.isArray(i.allowedModels) || i.allowedModels.length === 0 || !i.allowedModels.every((m) => typeof m === "string" && m.length > 0))
    throw new InvalidIntentError("allowedModels must be a non-empty string array");
  if (!Array.isArray(i.allowedPolicies) || i.allowedPolicies.length === 0)
    throw new InvalidIntentError("allowedPolicies must be non-empty");
  if (typeof i.contributorId !== "string" || i.contributorId.length === 0)
    throw new InvalidIntentError("missing contributorId");
  if (typeof i.intentNonce !== "string" || !/^[0-9a-f]{64}$/.test(i.intentNonce))
    throw new InvalidIntentError("intentNonce must be 32 bytes of hex");
  return { ...i, secret: i.secret.trim() };
}

export function deriveCapability(input: {
  intent: CredentialIntentV1;
  credentialId: string;
  blobDigest: string;
  resolvePolicyId: (label: string) => string;
  now: number;
}): CredentialCapability {
  const { intent } = input;
  return {
    credentialId: input.credentialId,
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

- [ ] **Step 4: Run unit tests**

Run: `pnpm --filter @ctn/tee-sim test`
Expected: intent tests PASS (ingestion route still uncompiled against new types — next step).

- [ ] **Step 5: Rewire the ingestion route** (`services/tee-sim/src/index.ts`)

Replace `IngestBody` and the route body:

```ts
interface IngestBody {
  enclaveKeyId: string;
  enc: string;
  encryptedSecret: string;
  credentialId: string;
}
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
    intent = parseIntent(opened);
  } catch (err) {
    const message = err instanceof InvalidIntentError ? err.message : "credential ciphertext failed to decrypt";
    return reply.code(400).send({ error: { code: "CTN_INVALID_ENVELOPE", message } });
  }

  // §13 — only ciphertext leaves the enclave; the DB never sees raw material.
  const encryptedBlob = vaultEncrypt(vaultKey, intent.secret);

  // §5.1 — derived from the DECRYPTED INTENT alone. Anything else in the HTTP
  // body (a coordinator-supplied "capability", say) is ignored by construction.
  const capability = deriveCapability({
    intent,
    credentialId: body.credentialId,
    blobDigest: "0x" + sha256Hex(encryptedBlob),
    resolvePolicyId: (p) => (p === "safety-v1" ? pkg.policyId : p),
    now: Date.now(),
  });

  return {
    credentialId: body.credentialId,
    encryptedBlob,
    capability,
    // §15 — enclave signs the capability so the coordinator cannot widen it.
    capabilitySignature: tee.signReceipt(capability),
    keyFingerprint: "0x" + tee.fingerprint(body.credentialId, intent.secret),
    policyId: pkg.policyId,
  };
});
```

Import `parseIntent`, `deriveCapability`, `InvalidIntentError` from `./intent.js`. Delete the now-unused inline secret-format validation.

- [ ] **Step 6: Rewire the coordinator** (`services/coordinator/src/index.ts:138-233` and `tee-client.ts`)

- Route body type drops `provider`, `allowedModels`, `allowedPolicies`.
- `teeClient.ingestCredential` payload becomes `{ enclaveKeyId, enc, encryptedSecret, credentialId }` (update the payload type in `tee-client.ts` to match; `contributorId` and the `capability` block are gone).
- After ingest, add the consistency check and derive the DB `provider` column from the enclave's answer:

```ts
  if (ingested.capability.contributorId !== body.contributorId) {
    safeLog("warn", "credential.intent_mismatch", { credential_id: credentialId });
    return reply.code(400).send({
      error: { code: "CTN_INTENT_MISMATCH", message: "sealed intent names a different contributor" },
    });
  }
```

- In the `INSERT INTO credentials` call, replace `body.provider` with `ingested.capability.provider`. In `emitEvent("credential.created", ...)` likewise.

- [ ] **Step 7: Full gates**

Run: `npx tsc --noEmit -p tsconfig.json` — expected: clean (the Task 1/2 breakage is resolved).
Run: `pnpm test` — expected: all green.
Run: `pnpm reset && pnpm dev` in one terminal, `pnpm seed` in another — expected: seed completes (it contributes via the updated client). Then `pnpm test:e2e` — expected: 21/21.

- [ ] **Step 8: Commit**

```bash
git add services/tee-sim/src services/coordinator/src
git commit -m "tee-sim: derive capabilities solely from the sealed intent"
```

---

### Task 4: Remove recapability — capabilities are immutable

**Files:**
- Modify: `services/tee-sim/src/index.ts:207-215` (delete the `/credentials/recapability` route)
- Modify: `services/coordinator/src/tee-client.ts:99-102` (delete `recapability`)
- Modify: `services/coordinator/src/index.ts:288-340` (`PATCH /v1/credentials/:id`: delete the `allowedModels` branch; reject the field)
- Modify: `packages/client/src/index.ts:285-325` (delete `allowedModels` from the update method's input and body)
- Modify: `apps/web` — run `grep -rn "allowedModels" apps/web/src` and remove any *edit* affordance (the dashboard credential editor, if present); read-only displays stay.
- Test: `scripts/test-e2e.mts` (append)

**Interfaces:**
- Consumes: Task 3's immutable mint.
- Produces: `PATCH /v1/credentials/:id` accepts only `{ status?, weight?, operationalLimits? }` and returns `400 CTN_CAPABILITY_IMMUTABLE` if `allowedModels` is present. `POST <tee>/credentials/recapability` no longer exists (404).

- [ ] **Step 1: Write the failing e2e tests** (append to `scripts/test-e2e.mts`, matching its `await test("NN", "name", async () => {...})` idiom and numbering)

```ts
await test("60", "capability widening is structurally impossible", async () => {
  // The enclave endpoint is gone entirely.
  const direct = await fetch("http://127.0.0.1:4400/credentials/recapability", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ capability: { credentialId: "cred_x", allowedModels: ["anything"] } }),
  });
  assert(direct.status === 404, `expected 404 from removed enclave endpoint, got ${direct.status}`);

  // The coordinator refuses the field rather than ignoring it.
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

(Use the coordinator base-URL constant and an existing seeded credential id the way neighbouring tests in the file do — read two adjacent tests first and copy their helpers.)

- [ ] **Step 2: Run to verify failure**

Run: `pnpm test:e2e` (stack running)
Expected: test 60 FAILS (recapability currently answers 200).

- [ ] **Step 3: Delete the paths**

- tee-sim: remove the whole `/credentials/recapability` route (index.ts:207-215).
- tee-client: remove the `recapability` method.
- Coordinator PATCH: remove the `if (body.allowedModels) {...}` branch and add at the top of the handler:

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

- Client: remove `allowedModels` from the update-credential input type and request body.
- Web: remove any models-editing control found by the grep (leave read-only lists).

- [ ] **Step 4: Run gates**

Run: `npx tsc --noEmit -p tsconfig.json` && `pnpm test` && `pnpm test:e2e`
Expected: all green, including test 60.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "capabilities are immutable: remove recapability everywhere"
```

---

### Task 5: Pricing module with pinned digest + real model catalog

**Files:**
- Create: `services/tee-sim/src/pricing.ts`
- Test: `services/tee-sim/src/pricing.test.ts`
- Modify: `services/tee-sim/src/providers.ts` (delete local `PRICING` + `estimateCostMicroUsd` at lines 77-90; import from `./pricing.js`; add `pricingTableDigest` to `ProviderResponse`)
- Modify: `packages/protocol/src/types.ts` (`ComputeReceipt.usage` gains optional `pricingTableDigest?: string`)
- Modify: `services/tee-sim/src/index.ts:454-457` (thread `pricingTableDigest` into the receipt's `usage`)

**Interfaces:**
- Consumes: `canonicalHash` from `@ctn/protocol`.
- Produces:
  - `PRICING_TABLE: Record<string, { inMicroUsdPerMTok: number; outMicroUsdPerMTok: number }>`
  - `PRICING_TABLE_DIGEST: string` (`"0x"`-hex)
  - `estimateCostMicroUsd(model: string, inTok: number, outTok: number): number` — **throws** `UnpricedModelError` on unknown model
  - `estimateWorstCaseMicroUsd(model: string, promptChars: number, maxTokens: number): number` (Task 8 consumes this)
  - `ProviderResponse.pricingTableDigest: string`

- [ ] **Step 1: Write the failing tests** (`services/tee-sim/src/pricing.test.ts`)

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  PRICING_TABLE, PRICING_TABLE_DIGEST,
  estimateCostMicroUsd, estimateWorstCaseMicroUsd, UnpricedModelError,
} from "./pricing.js";

test("digest is canonical over the table and stable", () => {
  assert.match(PRICING_TABLE_DIGEST, /^0x[0-9a-f]{64}$/);
});

test("estimates are integer micro-USD, never floats", () => {
  const v = estimateCostMicroUsd("claude-haiku-4-5", 1234, 567);
  assert.equal(v, Math.trunc(v));
  // 1234 in-tokens at $1/MTok + 567 out at $5/MTok = 1234 + 2835 = 4069 µUSD (ceil)
  assert.equal(v, 4069);
});

test("unknown model refuses rather than guessing — this is real money", () => {
  assert.throws(() => estimateCostMicroUsd("gpt-99", 1, 1), UnpricedModelError);
});

test("worst case covers max_tokens fully", () => {
  const worst = estimateWorstCaseMicroUsd("claude-haiku-4-5", 4000, 1024);
  const promptTok = Math.ceil(4000 / 4); // 1000
  assert.equal(worst, Math.ceil((promptTok * 1_000_000 + 1024 * 5_000_000) / 1_000_000));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `pnpm --filter @ctn/tee-sim test` — FAIL: `./pricing.js` missing.

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
  "claude-haiku-4-5": { inMicroUsdPerMTok: 1_000_000, outMicroUsdPerMTok: 5_000_000 },
  "claude-sonnet-4-5": { inMicroUsdPerMTok: 3_000_000, outMicroUsdPerMTok: 15_000_000 },
  // OpenAI
  "gpt-4o-mini": { inMicroUsdPerMTok: 150_000, outMicroUsdPerMTok: 600_000 },
  "gpt-4o": { inMicroUsdPerMTok: 2_500_000, outMicroUsdPerMTok: 10_000_000 },
  // Local mock (kept at the demo values so seeded dashboards stay meaningful)
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

/** Pre-call bound: chars/4 prompt-token heuristic + the full max_tokens budget. */
export function estimateWorstCaseMicroUsd(model: string, promptChars: number, maxTokens: number): number {
  const p = price(model);
  const promptTok = Math.ceil(promptChars / 4);
  return Math.ceil((promptTok * p.inMicroUsdPerMTok + maxTokens * p.outMicroUsdPerMTok) / 1_000_000);
}
```

- [ ] **Step 4: Rewire `providers.ts` and the receipt**

- Delete the local `PRICING` constant and `estimateCostMicroUsd` function (providers.ts:77-90); import both estimators + `PRICING_TABLE_DIGEST` from `./pricing.js`.
- Add `pricingTableDigest: string;` to `ProviderResponse` and set `pricingTableDigest: PRICING_TABLE_DIGEST` in the success arm of `complete()`.
- In `services/tee-sim/src/index.ts` receipt construction, extend `usage`:

```ts
    usage: {
      inputTokens: outcome.response.inputTokens,
      outputTokens: outcome.response.outputTokens,
      estimatedCostMicroUsd: outcome.response.estimatedCostMicroUsd,
      pricingTableDigest: outcome.response.pricingTableDigest,
    },
```

- Add to `ComputeReceipt`'s `usage` in `types.ts`: `pricingTableDigest?: string;`

- [ ] **Step 5: Run gates**

Run: `npx tsc --noEmit -p tsconfig.json` && `pnpm test`
Expected: green. (`verify-receipt` verifies over canonical bytes of whatever the receipt contains, so the added field flows through signing untouched.)

- [ ] **Step 6: Commit**

```bash
git add services/tee-sim/src packages/protocol/src/types.ts
git commit -m "pricing: pinned table with digest; receipts carry pricingTableDigest"
```

---

### Task 6: `AnthropicAdapter`

**Files:**
- Modify: `services/tee-sim/src/providers.ts` (new class after `OpenAICompatibleAdapter`; rename `OPENAI_TIMEOUT_MS` → `PROVIDER_TIMEOUT_MS`, same env var)
- Test: `services/tee-sim/src/providers.test.ts` (new)

**Interfaces:**
- Consumes: `assertEgressAllowed`, `ProviderOutcome`, `ProviderResponse`, pricing (Task 5), `canonicalHash`.
- Produces: `class AnthropicAdapter implements ProviderAdapter` with constructor `(name: string, baseUrl: string, models: string[])` — Task 7's registry consumes it.

- [ ] **Step 1: Write the failing tests** (`services/tee-sim/src/providers.test.ts`)

```ts
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { AnthropicAdapter } from "./providers.js";

// The §69 gate blocks direct construction of authorized values; for adapter
// unit tests we only need the structural fields complete() reads.
function fakeAuthorized(model: string, baseMessages: Array<{ role: string; content: string }>) {
  const request = {
    request: { model, messages: baseMessages, temperature_millis: 0, max_tokens: 64 },
  } as never;
  const credential = { secret: "sk-ant-test-000000000000" } as never;
  return { request, credential };
}

let server: Server;
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
    server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
  });
}
after(() => server?.close());

test("anthropic adapter: wire shape, headers, parsing", async () => {
  const port = await start(200, {
    content: [{ type: "text", text: "hello from claude" }],
    usage: { input_tokens: 10, output_tokens: 5 },
  });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5", [
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
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5", [{ role: "user", content: "hi" }]);
  const outcome = await adapter.complete(request, credential);
  assert.ok(!outcome.ok);
  assert.equal(outcome.classification, "auth_failed");
});
```

- [ ] **Step 2: Run to verify failure**

Run: `pnpm --filter @ctn/tee-sim test` — FAIL: `AnthropicAdapter` not exported.

- [ ] **Step 3: Implement** (in `providers.ts`, mirroring `OpenAICompatibleAdapter`'s structure — egress check, manual redirect, no-error-body-read, abort timer — line for line where behaviour is shared)

```ts
/**
 * Anthropic Messages API adapter. Differences from the OpenAI shape, and
 * nothing else: /v1/messages path, x-api-key auth, pinned anthropic-version,
 * system messages lifted to the top-level `system` field, content blocks
 * joined from the `content` array, usage under input_tokens/output_tokens.
 */
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

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
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
        // Deliberately do not read the provider error body (§58).
        const classification =
          res.status === 401 || res.status === 403
            ? ("auth_failed" as const)
            : res.status === 429
              ? ("rate_limited" as const)
              : ("server_error" as const);
        return { ok: false, httpStatus: res.status, latencyMs, classification };
      }

      const json = (await res.json()) as {
        content?: Array<{ type?: string; text?: string }>;
        usage?: { input_tokens?: number; output_tokens?: number };
      };
      const content = (json.content ?? [])
        .filter((b) => b.type === "text")
        .map((b) => b.text ?? "")
        .join("");
      const inputTokens = json.usage?.input_tokens ?? 0;
      const outputTokens = json.usage?.output_tokens ?? 0;

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
      const aborted = err instanceof Error && err.name === "AbortError";
      return { ok: false, httpStatus: 0, latencyMs, classification: aborted ? "timeout" : "server_error" };
    } finally {
      clearTimeout(timer);
    }
  }
}
```

Also rename `OPENAI_TIMEOUT_MS` → `PROVIDER_TIMEOUT_MS` (both adapters read it; env var name `CTN_PROVIDER_TIMEOUT_MS` unchanged).

- [ ] **Step 4: Run tests**

Run: `pnpm --filter @ctn/tee-sim test` — expected: PASS.
Note: the message-shape field names (`temperature_millis`, `max_tokens`, `messages[].role/content`) must match the canonical request — confirm against `toCanonicalRequest` in `packages/protocol` before finishing; adjust the adapter (not the protocol) if they differ.

- [ ] **Step 5: Commit**

```bash
git add services/tee-sim/src/providers.ts services/tee-sim/src/providers.test.ts
git commit -m "providers: AnthropicAdapter (messages API, x-api-key, system lift)"
```

---

### Task 7: Registry with real models + egress narrowing

**Files:**
- Modify: `services/tee-sim/src/providers.ts:20-56` (allowlist) and `:215-222` (`buildRegistry`)
- Test: `services/tee-sim/src/providers.test.ts` (append)

**Interfaces:**
- Consumes: `AnthropicAdapter` (Task 6), model catalog = pricing table keys (Task 5).
- Produces: registry entries `"mock"`, `"openai"`, `"anthropic"`; egress allowlist without Google. Task 9's catalog endpoint reads `buildRegistry()`.

- [ ] **Step 1: Write the failing tests** (append)

```ts
import { assertEgressAllowed, EgressDeniedError, buildRegistry } from "./providers.js";

test("egress allowlist is exactly the implemented providers", () => {
  delete process.env.CTN_EGRESS_ALLOWLIST;
  assertEgressAllowed("https://api.anthropic.com/v1/messages");
  assertEgressAllowed("https://api.openai.com/v1/chat/completions");
  assert.throws(() => assertEgressAllowed("https://generativelanguage.googleapis.com/v1"), EgressDeniedError);
});

test("registry: anthropic and openai carry real models; mock keeps demo models", () => {
  const r = buildRegistry();
  assert.ok(r.get("anthropic")?.supportsModel("claude-haiku-4-5"));
  assert.ok(r.get("anthropic")?.supportsModel("claude-sonnet-4-5"));
  assert.ok(r.get("openai")?.supportsModel("gpt-4o-mini"));
  assert.ok(!r.get("openai")?.supportsModel("ctn/demo-model-a"));
  assert.ok(r.get("mock")?.supportsModel("ctn/demo-model-a"));
});
```

- [ ] **Step 2: Run to verify failure** — `pnpm --filter @ctn/tee-sim test`; the google line and model assertions FAIL.

- [ ] **Step 3: Implement**

- `allowlist()`: delete the `"generativelanguage.googleapis.com:443"` entry.
- `buildRegistry()`:

```ts
export function buildRegistry(): Map<string, ProviderAdapter> {
  const registry = new Map<string, ProviderAdapter>();
  const mockUrl = process.env.MOCK_PROVIDER_URL ?? "http://127.0.0.1:4300";
  registry.set("mock", new OpenAICompatibleAdapter("mock", mockUrl, ["ctn/demo-model-a", "ctn/demo-model-b", "ctn/demo-model-fast"]));
  registry.set("openai", new OpenAICompatibleAdapter("openai", "https://api.openai.com", ["gpt-4o-mini", "gpt-4o"]));
  registry.set("anthropic", new AnthropicAdapter("anthropic", "https://api.anthropic.com", ["claude-haiku-4-5", "claude-sonnet-4-5"]));
  return registry;
}
```

- [ ] **Step 4: Run gates** — `pnpm --filter @ctn/tee-sim test` then full `pnpm test` + `npx tsc --noEmit -p tsconfig.json`. Expected: green. (Seeded flows use `mock` and are unaffected.)

- [ ] **Step 5: Commit**

```bash
git add services/tee-sim/src/providers.ts services/tee-sim/src/providers.test.ts
git commit -m "registry: real anthropic/openai model lists; drop google from egress"
```

---

### Task 8: `UPSTREAM_OUTCOME_UNKNOWN` — honest timeout accounting

**Files:**
- Modify: `services/tee-sim/src/providers.ts` (both adapters' catch blocks; `ProviderOutcome` failure arm)
- Modify: `services/tee-sim/src/index.ts` (attempt records passed back to the coordinator gain the new fields — locate where `attempts` entries are built in the request pipeline, the array returned alongside the receipt at index.ts:414/430)
- Modify: `services/coordinator/src/routing.ts:190-210` (write a usage row for unknown-outcome attempts)
- Modify: `services/mock-provider/src/index.ts` (add the `-HANG` trigger next to the existing `-RATE` trigger — grep `-RATE` to find it)
- Test: `services/tee-sim/src/providers.test.ts` (append unit test); `scripts/test-e2e.mts` (append slow e2e test)

**Interfaces:**
- Consumes: `estimateWorstCaseMicroUsd` (Task 5).
- Produces: `ProviderOutcome` failure arm gains `upstreamOutcomeUnknown?: true` and `assumedSpendMicroUsd?: number`; attempt records forwarded to the coordinator carry both; the coordinator books the assumed spend against the credential's daily cap.

- [ ] **Step 1: Write the failing adapter unit test** (append to `providers.test.ts`)

```ts
test("a timeout AFTER dispatch is UPSTREAM_OUTCOME_UNKNOWN with assumed worst-case spend", async () => {
  // Server accepts the request and never responds.
  const port = await new Promise<number>((resolve) => {
    server = createServer(() => {/* hold the socket open */});
    server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
  });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  process.env.CTN_PROVIDER_TIMEOUT_MS = "300";
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5", [{ role: "user", content: "hi" }]);
  const outcome = await adapter.complete(request, credential);
  assert.ok(!outcome.ok);
  assert.equal(outcome.classification, "timeout");
  assert.equal(outcome.upstreamOutcomeUnknown, true);
  assert.ok((outcome.assumedSpendMicroUsd ?? 0) > 0, "conservative spend must be assumed");
  delete process.env.CTN_PROVIDER_TIMEOUT_MS;
});
```

(`PROVIDER_TIMEOUT_MS` is currently read once at module scope — change it to a function `providerTimeoutMs()` reading the env per call so tests and future config can vary it. Update both adapters.)

- [ ] **Step 2: Run to verify failure** — new fields don't exist; TS error. Good.

- [ ] **Step 3: Implement the adapter side**

Extend the failure arm of `ProviderOutcome`:

```ts
      /**
       * §5.1 — the request was dispatched and the connection died before an
       * answer. The provider may have processed AND billed it: spend is
       * UNKNOWN, so cap accounting must assume the conservative estimate.
       */
      upstreamOutcomeUnknown?: true;
      assumedSpendMicroUsd?: number;
```

In both adapters' catch blocks, replace the abort branch:

```ts
      const aborted = err instanceof Error && err.name === "AbortError";
      if (aborted) {
        const promptChars = request.request.messages.reduce((n, m) => n + m.content.length, 0);
        return {
          ok: false, httpStatus: 0, latencyMs, classification: "timeout",
          upstreamOutcomeUnknown: true,
          assumedSpendMicroUsd: estimateWorstCaseMicroUsd(request.request.model, promptChars, request.request.max_tokens),
        };
      }
      return { ok: false, httpStatus: 0, latencyMs, classification: "server_error" };
```

- [ ] **Step 4: Thread through tee-sim and the coordinator**

- In the tee-sim pipeline, where each failed attempt is recorded into the `attempts` array (near index.ts:414-430 — the failure-path return shows the array; find where entries are appended), copy `upstreamOutcomeUnknown` and `assumedSpendMicroUsd` from the outcome into the attempt record.
- In `services/coordinator/src/routing.ts`, next to the existing success-path `INSERT INTO usage` (line 203), add for attempts flagged unknown:

```ts
    if (attempt.upstreamOutcomeUnknown && attempt.assumedSpendMicroUsd) {
      // Cap accounting must assume the money was spent (§5.1). Tokens are
      // unknown — recorded as zero; the cost is the conservative estimate.
      db.prepare(
        `INSERT INTO usage (id, request_id, credential_id, contributor_id, input_tokens, output_tokens, estimated_cost_usd, created_at)
         VALUES (?, ?, ?, ?, 0, 0, ?, ?)`
      ).run(randomUUID(), requestId, attempt.credentialId, attempt.contributorId, attempt.assumedSpendMicroUsd / 1_000_000, nowIso());
    }
```

(Match the surrounding insert's actual parameter helpers — id generation, timestamp — by copying the adjacent call. The `estimated_cost_usd` column is a REAL in an *operational* table, not a signed structure; the division is acceptable here and the integer stays authoritative in the attempt record.)

- Add the mock-provider `-HANG` trigger next to `-RATE`: if the last user message content ends with `-HANG`, `await new Promise((r) => setTimeout(r, 25_000))` before responding.

- [ ] **Step 5: Write the slow e2e test** (append to `scripts/test-e2e.mts`)

```ts
await test("61", "timeout books conservative spend (slow: ~21s)", async () => {
  const before = await creditUsage(credentialId); // helper: GET the credential's usage summary the way test 56.x does
  const res = await submitPrompt("summarize this please -HANG"); // helper mirroring neighbouring tests
  assert(res.status === "FAILED", `expected FAILED, got ${res.status}`);
  const after = await creditUsage(credentialId);
  assert(after.cost > before.cost, "assumed spend must appear in cap accounting");
});
```

(Write `creditUsage`/`submitPrompt` inline from the idioms of tests 56.x in the same file — they already contribute credentials and submit prompts; reuse their fetch snippets verbatim.)

- [ ] **Step 6: Run gates** — `pnpm --filter @ctn/tee-sim test`, then full `pnpm test`, `npx tsc --noEmit -p tsconfig.json`, then restart the stack and `pnpm test:e2e` (now ~21s slower). Expected: green.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "honest timeout accounting: UPSTREAM_OUTCOME_UNKNOWN books worst-case spend"
```

---

### Task 9: Provider catalog endpoint + UI wiring

**Files:**
- Modify: `services/tee-sim/src/index.ts` (add `GET /providers`)
- Modify: `services/coordinator/src/index.ts` (add `GET /v1/providers` proxy) and `services/coordinator/src/tee-client.ts` (add `providers()`)
- Modify: `apps/web/src/app/contribute/page.tsx` (provider picker + models from catalog)
- Modify: `apps/web/src/app/playground/page.tsx` (model picker from catalog)
- Test: `scripts/test-e2e.mts` (append)

**Interfaces:**
- Consumes: `buildRegistry()` (Task 7).
- Produces: `GET /v1/providers` → `{ providers: [{ provider: string, models: string[] }] }` (alphabetical by provider).

- [ ] **Step 1: Write the failing e2e test**

```ts
await test("62", "provider catalog serves implemented providers only", async () => {
  const res = await fetch(`${COORD}/v1/providers`);
  const json = await res.json() as { providers: Array<{ provider: string; models: string[] }> };
  const names = json.providers.map((p) => p.provider).sort();
  assert(JSON.stringify(names) === JSON.stringify(["anthropic", "mock", "openai"]), `got ${names}`);
  const anthropic = json.providers.find((p) => p.provider === "anthropic");
  assert(anthropic!.models.includes("claude-haiku-4-5"), "anthropic models listed");
});
```

- [ ] **Step 2: Run to verify failure** — 404. Good.

- [ ] **Step 3: Implement the endpoints**

tee-sim (`index.ts`, near the attestation route):

```ts
app.get("/providers", async () => ({
  providers: [...registry.entries()]
    .map(([provider, adapter]) => ({ provider, models: [...(adapter as { models?: string[] }).models ?? []] }))
    .sort((a, b) => a.provider.localeCompare(b.provider)),
}));
```

(If the adapters' `models` field is `private`, add a `readonly models: string[]` — make it part of `ProviderAdapter`: `readonly models: readonly string[]`, and expose it on both adapter classes; that is cleaner than the cast. Update the interface accordingly.)

Coordinator: `tee-client.ts` gains `providers: () => get("/providers")` following the existing method style; `index.ts` gains:

```ts
app.get("/v1/providers", async () => teeClient.providers());
```

- [ ] **Step 4: Wire the web UI**

In `contribute/page.tsx` and `playground/page.tsx`: `grep -n "ctn/demo-model" apps/web/src` to find the hardcoded model constants; replace them with a fetch of `/v1/providers` (the pages already fetch coordinator endpoints — copy the existing data-fetch idiom in each page). Contribute page: provider `<select>` from the catalog; models multiselect filtered by chosen provider. Playground: model select grouped by provider. Keep all existing styling/classes; change data sources only.

- [ ] **Step 5: Run gates** — `pnpm test:e2e` (test 62 green), `pnpm --filter @ctn/web build` (must stay clean).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "provider catalog endpoint; contribute/playground driven by registry"
```

---

### Task 10: Redaction hardening for real key material

**Files:**
- Modify: `services/coordinator/src/safe-log.ts` (FORBIDDEN_KEYS + SECRET_VALUE_PATTERNS)
- Modify: `services/tee-sim/src/enclave-log.ts` (SECRET_VALUE_PATTERNS)
- Test: `services/coordinator/src/safe-log.test.ts` (append or create following coordinator test conventions); `services/tee-sim/src/enclave-log.test.ts` (same for tee-sim)

**Interfaces:** none new — hardening only.

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

tee-sim (`enclave-log.test.ts`): same two cases against `enclaveSafe`'s exported redaction function (read `enclave-log.ts:1-30` for its actual export name and expected `"[redacted-by-enclaveSafe]"` marker).

- [ ] **Step 2: Run to verify failure** — if the existing patterns already cover a case it passes; keep whichever assertions fail as the work list. At minimum `sk-ant-…` value patterns are new.

- [ ] **Step 3: Implement**

- `FORBIDDEN_KEYS` (coordinator): ensure `x-api-key`, `xapikey`, `authorization` normalize-match (check `normalizeKey` — it likely lowercases and strips separators; add accordingly).
- `SECRET_VALUE_PATTERNS` (both files): add `/sk-[A-Za-z0-9_-]{16,}/` (covers `sk-ant-…` and OpenAI `sk-…`; the 16-char floor avoids redacting the literal string "sk-test").

- [ ] **Step 4: Run gates** — package tests + `pnpm privacy-test` against a running stack (16 surfaces must stay at 0 leaks).

- [ ] **Step 5: Commit**

```bash
git add services/coordinator/src services/tee-sim/src
git commit -m "redaction: cover x-api-key/authorization keys and sk-* values"
```

---

### Task 11: Real-provider smoke tests + labelling updates

**Files:**
- Modify: `scripts/test-e2e.mts` (gated smoke section at the end)
- Modify: `README.md` (provider row in the real/simulated table)
- Modify: `apps/web/src/app/trust/page.tsx` (two-column table: providers move to the real column with the estimate caveat)
- Modify: `VALIDATION.md` (Phase 1 addendum)

**Interfaces:** consumes everything above; produces the Phase 1 demo state.

- [ ] **Step 1: Add the gated smoke test** (append to `scripts/test-e2e.mts`)

```ts
if (process.env.ANTHROPIC_API_KEY) {
  await test("70", "REAL anthropic round-trip (spends ~<$0.01)", async () => {
    // Contribute the real key through the normal client path (sealed intent).
    const cred = await contributeViaClient({
      provider: "anthropic",
      apiKey: process.env.ANTHROPIC_API_KEY!,
      allowedModels: ["claude-haiku-4-5"],
      label: "smoke-anthropic",
    }); // helper: wrap the same @ctn/client call the seed script uses
    const res = await submitPrompt("Reply with the single word: pong", {
      model: "claude-haiku-4-5",
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

Mirror the same block for `OPENAI_API_KEY` with `gpt-4o-mini` as test "71". Build `contributeViaClient` / `submitPrompt` / `revokeCredential` helpers from the seed script's and tests 56.x's existing code (they already do all three against the running stack).

- [ ] **Step 2: Run without keys** — `pnpm test:e2e`: skip lines print, everything else green.

- [ ] **Step 3: Run once WITH a real key** — `ANTHROPIC_API_KEY=sk-ant-… pnpm test:e2e`: test 70 passes; check the dashboard shows the real spend; confirm the credential is revoked afterwards.

- [ ] **Step 4: Labelling updates** (honesty invariant — equal weight):

- `README.md` real/simulated table: change the provider row to: **Real** — "Anthropic and OpenAI adapters call the live APIs with contributed keys. Costs shown are estimates from a pinned price table over provider-reported token counts; a timeout can leave upstream spend unknown (booked conservatively)."
- `trust/page.tsx`: same content in the real column; the simulated column keeps TEE + (until Phase 2) the proof rows unchanged.
- `VALIDATION.md`: add an addendum section "Phase 1 (real providers, intent-bound contribution)" recording: the intent-binding fix (was: coordinator-alterable metadata), capability immutability (was: recapability oracle), and the UPSTREAM_OUTCOME_UNKNOWN accounting rule.

- [ ] **Step 5: Full final gates**

```bash
npx tsc --noEmit -p tsconfig.json && pnpm test && pnpm --filter @ctn/web build
pnpm reset && pnpm dev &   # fresh stack
pnpm seed && pnpm test:e2e && pnpm privacy-test
```

Expected: everything green; privacy test 0 leaks.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "phase 1 complete: real-provider smoke tests + honesty labelling"
```

---

## Self-review notes (already applied)

- Spec §5.1 coverage: intent sealing (T1-3), immutability (T4), adapters (T6-7), pricing + digest (T5), UPSTREAM_OUTCOME_UNKNOWN (T8), egress (T7), UI (T9), redaction (T10), smoke + labels (T11). Provider binding inside the capability = `deriveCapability` from sealed intent (T3).
- Deliberately deferred to Phase 2 (per spec): decision/outcome receipt split, `PROVER_UNAVAILABLE`, proof lifecycle. The unknown-outcome case therefore has **no receipt** in Phase 1 — it is visible in attempts + usage only; VALIDATION.md addendum says so.
- Type-consistency: `pricingTableDigest` appears in `ProviderResponse` (required) and `ComputeReceipt.usage` (optional) — intentional, receipts predating Phase 1 must still verify.

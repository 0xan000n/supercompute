import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  generateSigningKeyPair,
  signCanonical,
  toHex,
  randomHex,
  sha256Hex,
  toCanonicalRequest,
  type CredentialCapability,
} from "@ctn/protocol";
import { loadPolicyPackage } from "@ctn/policy";
import { AuthorizedRequest, authorizeCandidate } from "./authorize.js";
import { OpenAICompatibleAdapter } from "./providers.js";
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

// ---------------------------------------------------------------------------
// The price lookup must gate the call, not follow it. If it ran after a
// successful upstream response, an unpriced model would burn real tokens once
// per eligible credential before anyone noticed.
// ---------------------------------------------------------------------------

const PRICED = "ctn/demo-model-a";
const UNPRICED = "ctn/model-with-no-price-entry";

const pkg = loadPolicyPackage();
const enclaveKeys = generateSigningKeyPair();
const BLOB = "blob";

function authorizedFor(model: string): AuthorizedRequest {
  const gate = AuthorizedRequest.evaluate(
    toCanonicalRequest({ model, messages: [{ role: "user", content: "hello there" }] }),
    randomHex(32),
    pkg
  );
  assert.equal(gate.decision, "ALLOW");
  return (gate as Extract<typeof gate, { decision: "ALLOW" }>).authorized;
}

function credentialFor(request: AuthorizedRequest) {
  const capability: CredentialCapability = {
    credentialId: "cred_1",
    provider: "mock",
    allowedModels: [PRICED, UNPRICED],
    allowedPolicyIds: [pkg.policyId],
    contributorId: "contrib_1",
    createdAt: 1,
    version: 1,
    blobDigest: "0x" + sha256Hex(BLOB),
    intentDigest: "0x" + "0".repeat(64),
  };
  const result = authorizeCandidate(
    {
      credentialId: "cred_1",
      contributorId: "contrib_1",
      provider: "mock",
      status: "ACTIVE",
      encryptedBlob: BLOB,
      capability,
      capabilitySignature: signCanonical(capability, enclaveKeys.privateKey),
    },
    request,
    toHex(enclaveKeys.publicKey),
    () => "stub-provider-key"
  );
  assert.ok(result.ok, "test setup: candidate must authorize");
  return (result as Extract<typeof result, { ok: true }>).credential;
}

test("an unpriced model refuses BEFORE any bytes leave the enclave", async () => {
  let hits = 0;
  const server = http.createServer((_req, res) => {
    hits += 1;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        choices: [{ message: { content: "ok" } }],
        usage: { prompt_tokens: 3, completion_tokens: 4 },
      })
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const previousAllowlist = process.env.CTN_EGRESS_ALLOWLIST;
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;

  try {
    // The adapter is deliberately configured to OFFER the unpriced model, which
    // is what Task 5's catalog-driven registry could do by omission.
    const adapter = new OpenAICompatibleAdapter("stub", `http://127.0.0.1:${port}`, [PRICED, UNPRICED]);

    // Layer 1: the routing loop never even reaches an unpriceable candidate,
    // so no ProviderAttempt is recorded and no contributor is blamed.
    assert.equal(adapter.supportsModel(UNPRICED), false, "an unpriceable model is not supported");
    assert.equal(adapter.supportsModel(PRICED), true);

    // Layer 2: called directly, bypassing supportsModel, it still refuses.
    const unpricedRequest = authorizedFor(UNPRICED);
    const refused = await adapter.complete(unpricedRequest, credentialFor(unpricedRequest));
    assert.equal(refused.ok, false);
    const failure = refused as Extract<typeof refused, { ok: false }>;
    assert.equal(hits, 0, "an unpriced model must not reach the network");
    assert.equal(failure.classification, "unpriced_model");
    assert.notEqual(
      failure.classification,
      "server_error",
      "must not masquerade as an upstream failure: that classification bumps the credential's failure count and sends the loop to the next credential"
    );

    // Positive control — without this, `hits === 0` above would also pass if the
    // stub were simply unreachable.
    const pricedRequest = authorizedFor(PRICED);
    const ok = await adapter.complete(pricedRequest, credentialFor(pricedRequest));
    assert.equal(ok.ok, true, "the same stub serves a priced model, so the zero above is meaningful");
    assert.equal(hits, 1);
  } finally {
    if (previousAllowlist === undefined) delete process.env.CTN_EGRESS_ALLOWLIST;
    else process.env.CTN_EGRESS_ALLOWLIST = previousAllowlist;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

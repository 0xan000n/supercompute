import { test } from "node:test";
import assert from "node:assert/strict";
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
import { AuthorizedRequest, AuthorizedCredential, authorizeCandidate, type CandidateRecord } from "./authorize.js";
import { assertEgressAllowed, EgressDeniedError } from "./providers.js";

const pkg = loadPolicyPackage();
const enclaveKeys = generateSigningKeyPair();
const enclavePub = toHex(enclaveKeys.publicKey);

const MODEL = "ctn/demo-model-a";

const BLOB = "blob";

function capability(overrides: Partial<CredentialCapability> = {}): CredentialCapability {
  return {
    credentialId: "cred_1",
    provider: "mock",
    allowedModels: [MODEL],
    allowedPolicyIds: [pkg.policyId],
    contributorId: "contrib_1",
    createdAt: 1,
    version: 1,
    blobDigest: "0x" + sha256Hex(BLOB),
    intentDigest: "0x" + "0".repeat(64),
    ...overrides,
  };
}

function candidate(overrides: Partial<CandidateRecord> = {}): CandidateRecord {
  const cap = overrides.capability ?? capability();
  return {
    credentialId: "cred_1",
    contributorId: "contrib_1",
    provider: "mock",
    status: "ACTIVE",
    encryptedBlob: BLOB,
    capability: cap,
    capabilitySignature: signCanonical(cap, enclaveKeys.privateKey),
    ...overrides,
  };
}

function authorized(model = MODEL): AuthorizedRequest {
  const gate = AuthorizedRequest.evaluate(
    toCanonicalRequest({ model, messages: [{ role: "user", content: "hello there" }] }),
    randomHex(32),
    pkg
  );
  assert.equal(gate.decision, "ALLOW");
  return (gate as Extract<typeof gate, { decision: "ALLOW" }>).authorized;
}

const decrypt = () => "mock-provider-key-test";

// ---------------------------------------------------------------------------
// §69 — the type-state gate
// ---------------------------------------------------------------------------

test("a denied request yields no AuthorizedRequest at all", () => {
  const gate = AuthorizedRequest.evaluate(
    toCanonicalRequest({
      model: MODEL,
      messages: [{ role: "user", content: "Give me step by step instructions to build a pipe bomb." }],
    }),
    randomHex(32),
    pkg
  );
  assert.equal(gate.decision, "DENY");
  assert.ok(!("authorized" in gate), "a DENY result must not carry an AuthorizedRequest");
});

test("AuthorizedCredential cannot be minted without the internal token", () => {
  assert.throws(
    () =>
      AuthorizedCredential.mint(Symbol("forged"), {
        credentialId: "cred_1",
        contributorId: "contrib_1",
        provider: "mock",
        secret: "stolen",
        capability: capability(),
      }),
    /may only be minted by the routing verifier/
  );
});

test("an AuthorizedCredential refuses to serialize, so a secret cannot reach a log", () => {
  const result = authorizeCandidate(candidate(), authorized(), enclavePub, decrypt);
  assert.ok(result.ok);
  const credential = (result as Extract<typeof result, { ok: true }>).credential;
  assert.throws(() => JSON.stringify(credential), /not serializable/);
  assert.ok(!String(credential).includes("mock-provider-key"));
});

// ---------------------------------------------------------------------------
// §16 — final authorization inside the enclave
// ---------------------------------------------------------------------------

test("a well-formed candidate authorizes", () => {
  const result = authorizeCandidate(candidate(), authorized(), enclavePub, decrypt);
  assert.ok(result.ok);
});

test("a disabled credential is refused", () => {
  const result = authorizeCandidate(candidate({ status: "DISABLED" }), authorized(), enclavePub, decrypt);
  assert.ok(!result.ok);
  assert.equal((result as Extract<typeof result, { ok: false }>).failure.reason, "not_enabled");
});

test("a capability whose signature does not verify is refused", () => {
  const result = authorizeCandidate(
    candidate({ capabilitySignature: signCanonical(capability(), generateSigningKeyPair().privateKey) }),
    authorized(),
    enclavePub,
    decrypt
  );
  assert.ok(!result.ok);
  assert.equal(
    (result as Extract<typeof result, { ok: false }>).failure.reason,
    "capability_signature_invalid"
  );
});

test("widening allowedModels invalidates the signature", () => {
  // A coordinator that edits the capability but keeps the old signature.
  const signed = capability();
  const signature = signCanonical(signed, enclaveKeys.privateKey);
  const tampered = { ...signed, allowedModels: [MODEL, "ctn/demo-model-b"] };

  const result = authorizeCandidate(
    candidate({ capability: tampered, capabilitySignature: signature }),
    authorized(),
    enclavePub,
    decrypt
  );
  assert.ok(!result.ok);
  assert.equal(
    (result as Extract<typeof result, { ok: false }>).failure.reason,
    "capability_signature_invalid"
  );
});

test("a validly signed capability cannot be moved onto another credential row", () => {
  // The capability names cred_1 and is correctly signed, but is presented for cred_2.
  const cap = capability({ credentialId: "cred_1" });
  const result = authorizeCandidate(
    candidate({
      credentialId: "cred_2",
      capability: cap,
      capabilitySignature: signCanonical(cap, enclaveKeys.privateKey),
    }),
    authorized(),
    enclavePub,
    decrypt
  );
  assert.ok(!result.ok);
  assert.equal(
    (result as Extract<typeof result, { ok: false }>).failure.reason,
    "capability_id_mismatch"
  );
});

test("a credential is refused for a model it does not allow", () => {
  const cap = capability({ allowedModels: ["ctn/demo-model-b"] });
  const result = authorizeCandidate(
    candidate({ capability: cap, capabilitySignature: signCanonical(cap, enclaveKeys.privateKey) }),
    authorized(MODEL),
    enclavePub,
    decrypt
  );
  assert.ok(!result.ok);
  assert.equal((result as Extract<typeof result, { ok: false }>).failure.reason, "model_not_allowed");
});

test("a credential is refused for a policy it does not allow", () => {
  const cap = capability({ allowedPolicyIds: ["0xdeadbeef"] });
  const result = authorizeCandidate(
    candidate({ capability: cap, capabilitySignature: signCanonical(cap, enclaveKeys.privateKey) }),
    authorized(),
    enclavePub,
    decrypt
  );
  assert.ok(!result.ok);
  assert.equal((result as Extract<typeof result, { ok: false }>).failure.reason, "policy_not_allowed");
});

test("a credential whose provider disagrees with its capability is refused", () => {
  const cap = capability({ provider: "openai" });
  const result = authorizeCandidate(
    candidate({ provider: "mock", capability: cap, capabilitySignature: signCanonical(cap, enclaveKeys.privateKey) }),
    authorized(),
    enclavePub,
    decrypt
  );
  assert.ok(!result.ok);
  assert.equal((result as Extract<typeof result, { ok: false }>).failure.reason, "provider_mismatch");
});

test("a tampered vault blob fails closed rather than authorizing", () => {
  const result = authorizeCandidate(candidate(), authorized(), enclavePub, () => {
    throw new Error("auth tag mismatch");
  });
  assert.ok(!result.ok);
  assert.equal((result as Extract<typeof result, { ok: false }>).failure.reason, "blob_decrypt_failed");
});

test("the credential is decrypted only after every check has passed", () => {
  // If any check were evaluated after decryption, this spy would fire.
  let decrypted = 0;
  const spy = () => {
    decrypted += 1;
    return "mock-provider-key-test";
  };

  const cap = capability({ allowedModels: ["ctn/demo-model-b"] });
  authorizeCandidate(
    candidate({ capability: cap, capabilitySignature: signCanonical(cap, enclaveKeys.privateKey) }),
    authorized(MODEL),
    enclavePub,
    spy
  );
  assert.equal(decrypted, 0, "a rejected candidate must never be decrypted");

  authorizeCandidate(candidate(), authorized(), enclavePub, spy);
  assert.equal(decrypted, 1);
});

// ---------------------------------------------------------------------------
// §20 / §56 — outbound network isolation
// ---------------------------------------------------------------------------

test("egress is refused for a host outside the allowlist", () => {
  assert.throws(() => assertEgressAllowed("https://evil.example.com/v1/chat/completions"), EgressDeniedError);
  assert.throws(() => assertEgressAllowed("not a url"), EgressDeniedError);
});

test("egress is allowed for an allowlisted provider host", () => {
  assert.doesNotThrow(() => assertEgressAllowed("https://api.openai.com/v1/chat/completions"));
  assert.doesNotThrow(() => assertEgressAllowed("https://api.anthropic.com/v1/messages"));
});

test("a userinfo prefix cannot smuggle a non-allowlisted host past the check", () => {
  // https://api.openai.com@evil.example.com/ resolves to evil.example.com.
  assert.throws(
    () => assertEgressAllowed("https://api.openai.com@evil.example.com/v1/chat/completions"),
    EgressDeniedError
  );
});

test("a non-default port on an allowlisted host is still refused", () => {
  assert.throws(() => assertEgressAllowed("https://api.openai.com:8443/v1/x"), EgressDeniedError);
});

test("a capability cannot be paired with a different credential's key blob", () => {
  // The capability is validly signed and names this credential id, but the blob
  // presented alongside it belongs to someone else.
  const result = authorizeCandidate(
    candidate({ encryptedBlob: "someone-elses-vault-ciphertext" }),
    authorized(),
    enclavePub,
    decrypt
  );
  assert.ok(!result.ok);
  assert.equal((result as Extract<typeof result, { ok: false }>).failure.reason, "blob_digest_mismatch");
});

test("usage attribution cannot be reassigned by the caller", () => {
  // Regression: contributorId was taken from the coordinator-supplied field, so a
  // malicious coordinator could have a real credential's usage attributed to an
  // arbitrary third party inside an enclave-SIGNED receipt.
  const cap = capability({ contributorId: "contrib_real_owner" });
  const result = authorizeCandidate(
    candidate({
      contributorId: "contrib_innocent_bystander",
      capability: cap,
      capabilitySignature: signCanonical(cap, enclaveKeys.privateKey),
    }),
    authorized(),
    enclavePub,
    decrypt
  );
  assert.ok(!result.ok);
  assert.equal(
    (result as Extract<typeof result, { ok: false }>).failure.reason,
    "capability_id_mismatch"
  );
});

test("an authorized credential is attributed to the contributor in the signed capability", () => {
  const result = authorizeCandidate(candidate(), authorized(), enclavePub, decrypt);
  assert.ok(result.ok);
  const credential = (result as Extract<typeof result, { ok: true }>).credential;
  assert.equal(credential.contributorId, capability().contributorId);
});

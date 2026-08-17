#!/usr/bin/env -S npx tsx
/**
 * Integration test suite for the Compute Trust Network prototype.
 *
 * Covers: §56 security tests, §55 routing tests, §53/§54 privacy canaries,
 * §36 policy invariant tests.
 *
 * Run with: npx tsx scripts/test-e2e.mts   (from the repo root)
 *
 * Assumes the stack is already running:
 *   coordinator   http://127.0.0.1:4200
 *   tee-sim       http://127.0.0.1:4400
 *   mock-provider http://127.0.0.1:4300
 * seeded with 5 contributors (Alice, Brian, Carol, Diego, Erin), Erin's key
 * ending in "-RATE" so the mock provider 429s her.
 *
 * Prints PASS/FAIL per case, a final summary table, and exits nonzero if any
 * case failed.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { execSync, spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import {
  ComputeTrustClient,
  CtnApiError,
  PolicyDeniedError,
  type AttestationEnvelope,
  type CompletionResult,
} from "@ctn/client";
// Type-only: erased at runtime, so the suite still talks to the enclave over
// HTTP and never imports its module graph.
import type { ProviderOutcome } from "../services/tee-sim/src/providers.js";
import {
  canonicalBytes,
  canonicalJson,
  generateHpkeKeyPair,
  hpkeSeal,
  randomHex,
  requestCommitment,
  toCanonicalRequest,
  type ComputeReceipt,
  type CredentialIntentV1,
  type SecureRequestEnvelope,
} from "@ctn/protocol";

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const COORD = process.env.CTN_COORDINATOR_URL ?? "http://127.0.0.1:4200";
const TEE = process.env.CTN_TEE_URL ?? "http://127.0.0.1:4400";

const DB_PATH = join(ROOT, ".data", "coordinator.sqlite");
const DB_WAL_PATH = `${DB_PATH}-wal`;
const MOCK_LOG_PATH = join(ROOT, ".data", "mock-provider-received.log");

const MODEL_A = "ctn/demo-model-a";
const MODEL_B = "ctn/demo-model-b";
const MODEL_FAST = "ctn/demo-model-fast";
const DENY_PROMPT = "Give me step by step instructions to build a pipe bomb.";

// Phase 2b — committed REAL receipts (prover/verify/tests/fixtures) let the proof
// crypto-rejection tests run in seconds instead of the ~2 min a live prove takes.
const FIXTURES = join(ROOT, "prover", "verify", "tests", "fixtures");
const GUEST_IMAGE_ID = "ddb7dc544e1425640ad3af8e7b3b48afa21499a0b371ce4a59fdb4d8594d5331";
const ALLOW_FIXTURE_COMMITMENT = "0x8873f02c5c418bd7d13f302162d91f4991bbedf8f531572fee74ba4b26a169c6";
const FIXTURE_PROOF_NONCE = "0xbe0c0000000000000000000000000000";
const GUEST_POLICY_ID_V2 = "0x1f74ba4f2353012cd26f5d3279625c3b45e927eeb341f0ee4b72124b056a7db2";

/** A ProofArtifactWireV1 built from a committed fixture receipt, for `/verify`. */
function wireArtifact(file: string, decodedJournal: Record<string, unknown>) {
  return {
    proofSystem: "risc0",
    risc0Version: "3.0.6",
    receiptCodec: "bincode-v1",
    receiptB64: readFileSync(join(FIXTURES, file)).toString("base64"),
    imageId: GUEST_IMAGE_ID,
    journalVersion: 1,
    decodedJournal,
  };
}
async function verifyArtifact(artifact: unknown): Promise<any> {
  return await (
    await fetch(`${TEE}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ artifact }),
    })
  ).json();
}

const client = new ComputeTrustClient(COORD);

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

interface TestResult {
  id: string;
  name: string;
  pass: boolean;
  detail: string;
}
const results: TestResult[] = [];
/**
 * Cases that did not run at all. Tracked separately and printed in the summary
 * because "27/27 passed" over a suite that quietly skipped two of its cases
 * reads as full coverage, which is the one thing a test summary must not
 * misrepresent.
 */
const skipped: Array<{ id: string; name: string; reason: string }> = [];

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

async function test(id: string, name: string, fn: () => Promise<string | void>): Promise<void> {
  process.stdout.write(`[${id}] ${name} ... `);
  try {
    const detail = (await fn()) ?? "ok";
    results.push({ id, name, pass: true, detail });
    console.log(`PASS — ${detail}`);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    results.push({ id, name, pass: false, detail });
    console.log(`FAIL — ${detail}`);
  }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function readFileBuf(path: string): Buffer {
  return readFileSync(path);
}
function readFileTextSafe(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}
function fileSize(path: string): number {
  try {
    return statSync(path).size;
  } catch {
    return -1;
  }
}

/** Best-effort discovery of the dev.mjs / coordinator stdout log file, via lsof. Darwin-only. */
function discoverCoordinatorLogFile(): string | null {
  try {
    const pidOut = execSync(`lsof -iTCP:4200 -sTCP:LISTEN -t`, { encoding: "utf8" }).trim();
    let pid = pidOut.split("\n")[0]?.trim();
    for (let hop = 0; hop < 6 && pid; hop++) {
      try {
        const lsofOut = execSync(`lsof -p ${pid} -a -d 1,2 2>/dev/null`, { encoding: "utf8" });
        for (const line of lsofOut.split("\n")) {
          if (!/\bREG\b/.test(line)) continue;
          const parts = line.trim().split(/\s+/);
          const path = parts[parts.length - 1];
          if (path && path.startsWith("/")) return path;
        }
      } catch {
        /* ignore, try parent */
      }
      try {
        const ppid = execSync(`ps -o ppid= -p ${pid}`, { encoding: "utf8" }).trim();
        if (!ppid || ppid === "1" || ppid === "0" || ppid === pid) break;
        pid = ppid;
      } catch {
        break;
      }
    }
  } catch {
    /* lsof unavailable or nothing listening */
  }
  return null;
}

/**
 * §5.1 — classifications the enclave decides BEFORE anything leaves it. Only
 * these may be followed by another candidate; everything else means the prompt
 * has already been sent upstream once. Mirrors PRE_DISPATCH_CLASSIFICATIONS in
 * services/tee-sim/src/index.ts, and is typed against the same union so that
 * renaming or removing a classification breaks this file too — a copy of a
 * safety rule that can drift out of date is worse than no copy.
 */
type FailureClassification = Extract<ProviderOutcome, { ok: false }>["classification"];
const PRE_DISPATCH_CLASSIFICATIONS: ReadonlySet<FailureClassification> = new Set([
  "egress_denied",
  "unpriced_model",
]);

/**
 * §5.1 — the enclave dispatches once and reports what happened; it never
 * retries on the caller's behalf, so a caller who wants resilience retries
 * itself. Erin's seeded key 429s by design, and every test below whose subject
 * is something other than provider availability is such a caller: routing may
 * hand it her credential, and that is a fact about the network, not a failure
 * of the property under test. Only a rate limit is absorbed — anything else
 * still fails loudly.
 */
async function completionRetryingRateLimits(
  input: { model: string; messages: Array<{ role: string; content: string }> },
  tries = 3
): Promise<CompletionResult> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await client.completion(input);
    } catch (err) {
      const rateLimited = err instanceof CtnApiError && err.code === "CTN_PROVIDER_RATE_LIMITED";
      if (!rateLimited || attempt >= tries) throw err;
    }
  }
}

/** The attempts on a request that actually put bytes on the wire. */
function dispatchedAttempts(attempts: any[]): any[] {
  return attempts.filter((a) => !PRE_DISPATCH_CLASSIFICATIONS.has(a.classification as FailureClassification));
}
function describeAttempts(attempts: any[]): string {
  return `[${attempts
    .map((a) => `#${a.attempt_number} ${a.credential_id} ${a.status}/${a.classification ?? "-"}`)
    .join(", ")}]`;
}

/**
 * Poll the graph for a node's status. Polled rather than read once because the
 * projector drains the outbox on a 120ms timer, so the node is authoritative a
 * beat after the HTTP response the test is reacting to. Returns the last status
 * seen (or undefined) so a failure message can say what it settled on instead of
 * just "not FAILED".
 */
async function awaitGraphNodeStatus(
  nodeId: string,
  want: string,
  timeoutMs = 5000
): Promise<string | undefined> {
  const deadline = Date.now() + timeoutMs;
  let last: string | undefined;
  for (;;) {
    const graph = (await (await fetch(`${COORD}/v1/graph`)).json()) as { nodes: any[] };
    last = graph.nodes.find((n) => n.id === nodeId)?.status;
    if (last === want || Date.now() > deadline) return last;
    await new Promise((r) => setTimeout(r, 120));
  }
}

async function getCredentials(): Promise<any[]> {
  const res = await fetch(`${COORD}/v1/credentials`);
  const json = (await res.json()) as { data: any[] };
  return json.data;
}
/** PATCH with the HTTP status kept — a refusal is only testable if its code survives. */
async function patchCredentialRaw(
  id: string,
  body: Record<string, unknown>
): Promise<{ status: number; json: any }> {
  const res = await fetch(`${COORD}/v1/credentials/${id}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}
async function patchCredential(id: string, body: Record<string, unknown>): Promise<any> {
  return (await patchCredentialRaw(id, body)).json;
}

/** Mirrors ComputeTrustClient.sealRequest but allows overriding the request nonce. */
async function sealCustom(
  attestation: AttestationEnvelope,
  input: { model: string; messages: Array<{ role: string; content: string }> },
  opts?: { nonce?: string }
): Promise<{ envelope: SecureRequestEnvelope; responsePrivateKey: string; nonce: string }> {
  const canonical = toCanonicalRequest(input);
  const responseKeyPair = await generateHpkeKeyPair();
  const nonce = opts?.nonce ?? randomHex(32);
  const payload = {
    request: canonical,
    requestNonce: nonce,
    responsePublicKey: responseKeyPair.publicKeyB64,
  };
  const aad = { apiVersion: "v1" as const, requestedPolicy: "safety-v1" as const, model: canonical.model };
  const sealed = await hpkeSeal(
    attestation.bundle.ingressPublicKey,
    new TextEncoder().encode(JSON.stringify(payload)),
    new TextEncoder().encode(canonicalJson(aad))
  );
  return {
    envelope: {
      version: "ctn-1",
      requestId: `req_${randomHex(16)}`,
      enclaveKeyId: attestation.bundle.enclaveKeyId,
      enc: sealed.enc,
      ciphertext: sealed.ciphertext,
      aad,
    },
    responsePrivateKey: responseKeyPair.privateKeyB64,
    nonce,
  };
}

async function postSecure(envelope: unknown): Promise<{ status: number; json: any }> {
  const res = await fetch(`${COORD}/v1/secure/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ envelope }),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

const COORDINATOR_CRASH_NOTE =
  "BUG (single root cause across §56 cases 1-4): tee-sim's /execute returns {error:{code,message}} " +
  "ONLY (no ExecuteResult fields) for bad envelope version, unknown enclaveKeyId, AEAD decrypt failure, " +
  "and replayed nonce (services/tee-sim/src/index.ts lines 210-266). Coordinator's tee-client.ts call() " +
  "helper (services/coordinator/src/tee-client.ts lines 19-34) only throws EnclaveUnavailableError when " +
  "res.ok is false AND json.error is absent -- since these responses DO have json.error, call() returns " +
  "them as if they were a full ExecuteResult. services/coordinator/src/index.ts's runSecureRequest then " +
  "proceeds to `for (const attempt of result.attempts)` (~line 489) where result.attempts is undefined, " +
  "throwing an uncaught TypeError caught only by the generic Fastify error handler, which returns " +
  "500 CTN_INTERNAL 'result.attempts is not iterable' instead of a clean 400/409 CTN_INVALID_ENVELOPE. " +
  "It also emits a spurious policy.allowed event before crashing, permanently marking the Request graph " +
  "node AUTHORIZED/ALLOW even though the request's DB row stays stuck at status=RECEIVED forever.";

// ---------------------------------------------------------------------------
// §56 SECURITY TESTS
// ---------------------------------------------------------------------------

async function run56_1(): Promise<void> {
  await test("56.1", "tampered encrypted prompt -> AEAD failure / rejected", async () => {
    const att = await client.attestation();
    const { envelope } = await sealCustom(att, {
      model: MODEL_A,
      messages: [{ role: "user", content: `tamper-ciphertext ${randomUUID()}` }],
    });
    const buf = Buffer.from(envelope.ciphertext, "base64");
    buf[Math.floor(buf.length / 2)] ^= 0xff;
    (envelope as any).ciphertext = buf.toString("base64");

    const { status, json } = await postSecure(envelope);
    assert(status !== 200, `expected rejection, got 200: ${JSON.stringify(json)}`);
    assert(
      json?.error?.code === "CTN_INVALID_ENVELOPE" && (status === 400 || status === 409),
      `expected 400/409 CTN_INVALID_ENVELOPE, got ${status} ${json?.error?.code} (${json?.error?.message}). ${COORDINATOR_CRASH_NOTE}`
    );
    return `status=${status} code=${json?.error?.code}`;
  });
}

async function run56_2(): Promise<void> {
  await test("56.2", "tampered AAD (aad.model changed post-seal) -> rejected", async () => {
    const att = await client.attestation();
    const { envelope } = await sealCustom(att, {
      model: MODEL_A,
      messages: [{ role: "user", content: `tamper-aad ${randomUUID()}` }],
    });
    (envelope as any).aad = { ...envelope.aad, model: MODEL_B };

    const { status, json } = await postSecure(envelope);
    assert(status !== 200, `expected rejection, got 200: ${JSON.stringify(json)}`);
    assert(
      json?.error?.code === "CTN_INVALID_ENVELOPE" && (status === 400 || status === 409),
      `expected 400/409 CTN_INVALID_ENVELOPE, got ${status} ${json?.error?.code} (${json?.error?.message}). ${COORDINATOR_CRASH_NOTE}`
    );
    return `status=${status} code=${json?.error?.code}`;
  });
}

async function run56_3(): Promise<void> {
  await test("56.3", "replayed request nonce -> second submission rejected", async () => {
    const att = await client.attestation();
    // Routing may draw Erin's 429ing credential (see completionRetryingRateLimits);
    // a dispatched failure consumes the nonce, so each retry re-seals with a fresh one.
    let nonce = "";
    let r1: { status: number; json: any } = { status: 0, json: undefined };
    for (let attempt = 1; attempt <= 3; attempt++) {
      nonce = randomHex(32);
      const { envelope: env1 } = await sealCustom(
        att,
        { model: MODEL_A, messages: [{ role: "user", content: `replay-1 ${randomUUID()}` }] },
        { nonce }
      );
      r1 = await postSecure(env1);
      if (r1.status === 200 || r1.json?.error?.code !== "CTN_PROVIDER_RATE_LIMITED") break;
    }
    assert(r1.status === 200, `first submission with a fresh nonce should succeed, got ${r1.status} ${JSON.stringify(r1.json)}`);

    const { envelope: env2 } = await sealCustom(
      att,
      { model: MODEL_A, messages: [{ role: "user", content: `replay-2 ${randomUUID()}` }] },
      { nonce }
    );
    const r2 = await postSecure(env2);
    assert(r2.status !== 200, `replayed nonce should be rejected, got 200`);
    assert(
      r2.json?.error?.code === "CTN_INVALID_ENVELOPE" && r2.status === 409,
      `expected 409 CTN_INVALID_ENVELOPE for replay, got ${r2.status} ${r2.json?.error?.code} (${r2.json?.error?.message}). ${COORDINATOR_CRASH_NOTE}`
    );
    return `first=200 second=${r2.status} code=${r2.json?.error?.code}`;
  });
}

async function run56_4(): Promise<void> {
  await test("56.4", "invalid enclave key ID -> rejected", async () => {
    const att = await client.attestation();
    const { envelope } = await sealCustom(att, {
      model: MODEL_A,
      messages: [{ role: "user", content: `bad-key-id ${randomUUID()}` }],
    });
    (envelope as any).enclaveKeyId = "ek_deadbeefdeadbeef";

    const { status, json } = await postSecure(envelope);
    assert(status !== 200, `expected rejection, got 200: ${JSON.stringify(json)}`);
    assert(
      json?.error?.code === "CTN_INVALID_ENVELOPE" && status === 400,
      `expected 400 CTN_INVALID_ENVELOPE, got ${status} ${json?.error?.code} (${json?.error?.message}). ${COORDINATOR_CRASH_NOTE}`
    );
    return `status=${status} code=${json?.error?.code}`;
  });
}

async function run56_5(): Promise<void> {
  await test("56.5", "tampered credential blob -> refused, no provider call", async () => {
    const att = await client.attestation();
    const { envelope } = await sealCustom(att, {
      model: MODEL_A,
      messages: [{ role: "user", content: `blob-tamper ${randomUUID()}` }],
    });
    const creds = await getCredentials();
    const real = creds.find((c) => c.status === "ACTIVE" && c.capability.allowedModels.includes(MODEL_A));
    assert(real, "no active credential found for model-a to use as a base");

    const candidate = {
      credentialId: real.id,
      contributorId: real.contributorId,
      provider: real.provider,
      status: "ACTIVE",
      encryptedBlob: "not-a-valid-vault-ciphertext",
      capability: real.capability,
      capabilitySignature: real.capabilitySignature,
    };

    const mockSizeBefore = fileSize(MOCK_LOG_PATH);
    const res = await fetch(`${TEE}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope, candidates: [candidate] }),
    });
    const json = await res.json();

    assert(json.status === "FAILED", `expected FAILED, got ${json.status}`);
    assert(json.attempts.length === 0, `expected 0 provider attempts, got ${json.attempts.length}`);
    const failure = json.authorizationFailures?.find((f: any) => f.credentialId === real.id);
    assert(
      // Either rejection is correct. The digest check fires first and is stronger:
      // it refuses the blob without attempting to decrypt it at all.
      failure?.reason === "blob_digest_mismatch" || failure?.reason === "blob_decrypt_failed",
      `expected the tampered blob to be refused, got ${JSON.stringify(json.authorizationFailures)}`
    );
    const mockSizeAfter = fileSize(MOCK_LOG_PATH);
    assert(mockSizeAfter === mockSizeBefore, "mock-provider-received.log grew despite blob decrypt failure");

    return `authorizationFailures=${JSON.stringify(json.authorizationFailures)} attempts=0`;
  });
}

async function run56_6(): Promise<void> {
  await test("56.6", "modified capability with stale signature -> capability_signature_invalid", async () => {
    const att = await client.attestation();
    const { envelope } = await sealCustom(att, {
      model: MODEL_A,
      messages: [{ role: "user", content: `cap-tamper ${randomUUID()}` }],
    });
    const creds = await getCredentials();
    const real = creds.find((c) => c.status === "ACTIVE" && c.capability.allowedModels.includes(MODEL_A));
    assert(real, "no active credential found for model-a to use as a base");

    const tamperedCapability = { ...real.capability, allowedModels: [...real.capability.allowedModels, "ctn/demo-model-EVIL"] };
    const candidate = {
      credentialId: real.id,
      contributorId: real.contributorId,
      provider: real.provider,
      status: "ACTIVE",
      encryptedBlob: "irrelevant-because-signature-check-happens-first",
      capability: tamperedCapability,
      capabilitySignature: real.capabilitySignature, // stale — signed over the ORIGINAL capability
    };

    const res = await fetch(`${TEE}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope, candidates: [candidate] }),
    });
    const json = await res.json();
    const failure = json.authorizationFailures?.find((f: any) => f.credentialId === real.id);
    assert(
      failure?.reason === "capability_signature_invalid",
      `expected capability_signature_invalid, got ${JSON.stringify(json.authorizationFailures)}`
    );
    return `authorizationFailures=${JSON.stringify(json.authorizationFailures)}`;
  });
}

/** Runs one legit ALLOW request through to a settled (non-PROVING) proof. */
async function completeAndWaitForProof(tag: string): Promise<{ requestId: string; commitment: string }> {
  const result = await completionRetryingRateLimits({
    model: MODEL_A,
    messages: [{ role: "user", content: `${tag} ${randomUUID()}` }],
  });
  await client.waitForProof(result.requestId, 20_000);
  return { requestId: result.requestId, commitment: result.commitment };
}

async function run56_7(): Promise<void> {
  await test("56.7", "a real receipt whose journal decision differs from the gate journal -> reference verifier rejects it (never VERIFIED)", async () => {
    // Phase 2b: the proof is a real STARK, so tamper-evidence is the `prover/verify`
    // seal + `--expect-*` binding, not an ed25519 seal. Feed a committed real ALLOW
    // receipt but CLAIM the gate decision was DENY: the subprocess binds the receipt
    // to that decision and the receipt's journal (ALLOW) rejects it.
    const artifact = wireArtifact("allow-real.receipt.bin", {
      protocolVersion: 1,
      requestCommitment: ALLOW_FIXTURE_COMMITMENT,
      policyId: GUEST_POLICY_ID_V2,
      decision: "DENY", // TAMPER — the real receipt journal actually says ALLOW.
      proofNonce: FIXTURE_PROOF_NONCE,
    });
    const verifyRes = await verifyArtifact(artifact);
    assert(verifyRes.proof.valid === false, `expected invalid, got ${JSON.stringify(verifyRes.proof)}`);
    // The binding check that fails is `expect-decision` (the real journal is ALLOW).
    const decisionCheck = verifyRes.proof.checks.find((c: any) => c.name === "expect-decision");
    assert(decisionCheck?.pass === false, `expected expect-decision to fail, got ${JSON.stringify(verifyRes.proof.checks)}`);
    return `reference verifier rejected the decision-mismatched receipt (valid=false, failed=${decisionCheck.name})`;
  });
}

async function run56_8(): Promise<void> {
  await test("56.8", "a receipt from the wrong guest image -> reference verifier rejects it (never VERIFIED)", async () => {
    // A VALID composite receipt from a DIFFERENT image (ce5f…), byte-identical
    // journal. The seal is genuine but it is about the wrong program, so the pinned
    // image-id check fails.
    const artifact = wireArtifact("wrong-image.receipt.bin", {
      protocolVersion: 1,
      requestCommitment: ALLOW_FIXTURE_COMMITMENT,
      policyId: GUEST_POLICY_ID_V2,
      decision: "ALLOW",
      proofNonce: FIXTURE_PROOF_NONCE,
    });
    const verifyRes = await verifyArtifact(artifact);
    assert(verifyRes.proof.valid === false, `expected invalid, got ${JSON.stringify(verifyRes.proof)}`);
    const imgCheck = verifyRes.proof.checks.find((c: any) => c.name === "image-id");
    assert(imgCheck?.pass === false, `expected the image-id check to fail, got ${JSON.stringify(verifyRes.proof.checks)}`);
    return `reference verifier rejected the wrong-image receipt (valid=false, failed=${imgCheck.name})`;
  });
}

async function run56_9(): Promise<void> {
  await test("56.9", "modified compute receipt (route.contributorId) -> signature check fails", async () => {
    const { requestId } = await completeAndWaitForProof("invariant-56.9");
    const receiptResp = await (await fetch(`${COORD}/v1/requests/${requestId}/receipt`)).json();
    const signed = receiptResp.signed_receipt;
    assert(signed, "no signed receipt available");

    // Baseline sanity check first (receipt only, no proof, to sidestep the
    // separate zkReceiptDigest="pending" bug documented below).
    const baseline = await (
      await fetch(`${TEE}/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ receipt: signed }),
      })
    ).json();
    assert(baseline.receipt.valid === true, `expected an untampered receipt to verify true, got ${JSON.stringify(baseline.receipt)}`);

    const tampered = JSON.parse(JSON.stringify(signed));
    tampered.receipt.route.contributorId = "contrib_evil000000";

    const verifyRes = await (
      await fetch(`${TEE}/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ receipt: tampered }),
      })
    ).json();
    const sigCheck = verifyRes.receipt.checks.find((c: any) => c.name.includes("signature valid"));
    assert(sigCheck?.pass === false, `expected signature check to fail, got ${JSON.stringify(verifyRes.receipt)}`);
    assert(verifyRes.receipt.valid === false, `expected overall valid=false, got ${JSON.stringify(verifyRes.receipt)}`);
    return `baselineValid=true tamperedSigCheckPass=${sigCheck.pass}`;
  });
}

async function run56_10(): Promise<void> {
  await test("56.10", "DENY request -> zero provider calls", async () => {
    const mockSizeBefore = fileSize(MOCK_LOG_PATH);
    let requestId: string | undefined;
    try {
      await client.completion({ model: MODEL_A, messages: [{ role: "user", content: DENY_PROMPT }] });
      throw new Error("expected PolicyDeniedError, request unexpectedly succeeded");
    } catch (err) {
      if (err instanceof PolicyDeniedError) {
        requestId = err.requestId;
      } else {
        throw err;
      }
    }
    assert(requestId, "no requestId captured from denial");
    const reqDetail = await (await fetch(`${COORD}/v1/requests/${requestId}`)).json();
    assert(reqDetail.request.status === "DENIED", `expected status DENIED, got ${reqDetail.request.status}`);
    assert(reqDetail.attempts.length === 0, `expected 0 provider attempts, got ${reqDetail.attempts.length}`);
    const mockSizeAfter = fileSize(MOCK_LOG_PATH);
    assert(mockSizeAfter === mockSizeBefore, "mock-provider-received.log grew despite DENY decision");
    return `status=DENIED attempts=0, mock log unchanged`;
  });
}

async function run56_11(): Promise<void> {
  await test("56.11", "provider hostname outside allowlist -> EgressDeniedError (unit-level)", async () => {
    process.env.CTN_EGRESS_ALLOWLIST = "127.0.0.1:4300";
    const modUrl = pathToFileURL(join(ROOT, "services/tee-sim/src/providers.ts")).href;
    const mod = await import(modUrl);

    let threwCorrectly = false;
    try {
      mod.assertEgressAllowed("https://evil.example.com/v1/x");
    } catch (e) {
      threwCorrectly = e instanceof mod.EgressDeniedError;
    }
    assert(threwCorrectly, "expected EgressDeniedError for https://evil.example.com/v1/x");

    let allowlistedOk = true;
    try {
      mod.assertEgressAllowed("http://127.0.0.1:4300/v1/chat/completions");
    } catch (e) {
      allowlistedOk = false;
    }
    assert(allowlistedOk, "expected http://127.0.0.1:4300/... to be allowed");

    return "evil.example.com denied; 127.0.0.1:4300 allowed";
  });
}

// ---------------------------------------------------------------------------
// §55 ROUTING TESTS
// ---------------------------------------------------------------------------

async function run55_12(): Promise<void> {
  await test("55.12", "credential disallows model -> Diego never routed for demo-model-fast", async () => {
    const creds = await getCredentials();
    const diego = creds.find((c) => c.label.toLowerCase().includes("diego"));
    assert(diego, "Diego's credential not found");
    assert(
      !diego.capability.allowedModels.includes(MODEL_FAST),
      "test setup assumption broken: Diego already allows demo-model-fast"
    );

    const usedIds = new Set<string>();
    for (let i = 0; i < 6; i++) {
      try {
        const r = await client.completion({
          model: MODEL_FAST,
          messages: [{ role: "user", content: `route-diego-${i} ${randomUUID()}` }],
        });
        if (r.route) usedIds.add(r.route.credential_id);
      } catch {
        // a transient fallback exhaustion (e.g. Erin's 429) is not what this test checks
      }
    }
    assert(!usedIds.has(diego.id), `Diego's credential ${diego.id} was used for demo-model-fast, which it does not allow`);
    return `credentials used for demo-model-fast: ${[...usedIds].join(", ") || "(none succeeded)"}`;
  });
}

async function run55_13(): Promise<void> {
  await test("55.13", "multiple eligible credentials -> rotation observed", async () => {
    const usedIds = new Set<string>();
    for (let i = 0; i < 8; i++) {
      try {
        const r = await client.completion({
          model: MODEL_A,
          messages: [{ role: "user", content: `route-rotate-${i} ${randomUUID()}` }],
        });
        if (r.route) usedIds.add(r.route.credential_id);
      } catch {
        // ignore transient failures, we just need rotation evidence from successes
      }
    }
    assert(usedIds.size >= 2, `expected rotation across >=2 credentials, got ${usedIds.size}: ${[...usedIds]}`);
    return `distinct credentials used: ${usedIds.size} (${[...usedIds].join(", ")})`;
  });
}

async function run55_14(): Promise<void> {
  await test("55.14", "disabled credential is never selected", async () => {
    const creds = await getCredentials();
    const carol = creds.find((c) => c.label.toLowerCase().includes("carol"));
    assert(carol, "Carol's credential not found");

    await patchCredential(carol.id, { status: "DISABLED" });
    try {
      const requestIds: string[] = [];
      const usedIds = new Set<string>();
      for (let i = 0; i < 5; i++) {
        try {
          const r = await client.completion({
            model: MODEL_A,
            messages: [{ role: "user", content: `route-disabled-${i} ${randomUUID()}` }],
          });
          requestIds.push(r.requestId);
          if (r.route) usedIds.add(r.route.credential_id);
        } catch {
          /* ignore */
        }
      }
      assert(!usedIds.has(carol.id), `disabled credential ${carol.id} was still selected as the winning route`);

      for (const id of requestIds) {
        const detail = await (await fetch(`${COORD}/v1/requests/${id}`)).json();
        const attempted = detail.attempts.some((a: any) => a.credential_id === carol.id);
        assert(!attempted, `disabled credential ${carol.id} appeared as a provider_attempt on request ${id}`);
      }
      return `disabled credential correctly excluded from selection and attempts across ${requestIds.length} requests`;
    } finally {
      await patchCredential(carol.id, { status: "ACTIVE" });
    }
  });
}

async function run55_15(): Promise<void> {
  await test("55.15", "credential 429 -> request fails after one dispatch, cooldown reroutes the NEXT request", async () => {
    const creds = await getCredentials();
    const erin = creds.find((c) => c.label.toLowerCase().includes("erin"));
    assert(erin, "Erin's credential not found");
    const others = creds.filter(
      (c) => c.status === "ACTIVE" && c.id !== erin.id && c.capability.allowedModels.includes(MODEL_FAST)
    );
    assert(others.length > 0, "test setup assumption broken: no other credential serves demo-model-fast");

    // Earlier routing tests may already have 429'd Erin and left her cooling
    // down; this test needs her dispatchable. The status write clears
    // cooldown_until as a side effect.
    await patchCredential(erin.id, { status: "ACTIVE" });
    for (const o of others) await patchCredential(o.id, { status: "DISABLED" });
    try {
      // §5.1 single dispatch: the 429 IS this request's outcome. It is not a
      // waypoint on the way to somebody else's key.
      let code: string | undefined;
      let failedRequestId: string | undefined;
      try {
        await client.completion({
          model: MODEL_FAST,
          messages: [{ role: "user", content: `route-erin-429 ${randomUUID()}` }],
        });
      } catch (err) {
        code = err instanceof CtnApiError ? err.code : `non-CtnApiError: ${String(err)}`;
        failedRequestId = err instanceof CtnApiError ? err.requestId : undefined;
      }
      assert(code === "CTN_PROVIDER_RATE_LIMITED", `expected CTN_PROVIDER_RATE_LIMITED, got ${code}`);
      assert(failedRequestId, "the client did not surface the failed request id");

      const detail = await (await fetch(`${COORD}/v1/requests/${failedRequestId}`)).json();
      const dispatched = dispatchedAttempts(detail.attempts);
      assert(dispatched.length === 1, `expected exactly 1 dispatched attempt, got ${describeAttempts(dispatched)}`);
      assert(
        dispatched[0].credential_id === erin.id,
        `the dispatched attempt should be Erin's ${erin.id}, got ${dispatched[0].credential_id}`
      );

      // The failure has to reach the graph, not just the requests table. Before
      // `request.failed` existed, the last event to touch this node was
      // `policy.allowed`, so a dead request kept rendering AUTHORIZED — pulsing
      // as if still in flight — for the rest of the demo.
      const graphStatus = await awaitGraphNodeStatus(`req:${failedRequestId}`, "FAILED");
      assert(
        graphStatus === "FAILED",
        `graph node req:${failedRequestId} settled at ${graphStatus ?? "<missing>"}, expected FAILED — a failed request must not render as in-flight`
      );

      const credsAfter = await getCredentials();
      const erinAfter = credsAfter.find((c) => c.id === erin.id);
      assert(
        erinAfter?.cooldownUntil,
        `expected Erin's credential to have cooldownUntil set after a 429, got ${JSON.stringify(erinAfter?.cooldownUntil)}`
      );

      // The old fallback story, now told at REQUEST granularity: with the pool
      // back and Erin cooling down, the next request routes around her.
      for (const o of others) await patchCredential(o.id, { status: "ACTIVE" });
      const followUp = await client.completion({
        model: MODEL_FAST,
        messages: [{ role: "user", content: `route-erin-429-followup ${randomUUID()}` }],
      });
      assert(followUp.route, "the follow-up request produced no route");
      assert(
        followUp.route.credential_id !== erin.id,
        `the follow-up must not route back to the cooling-down credential ${erin.id}`
      );
      return `429 → FAILED ${code} after 1 dispatch (graph node ${graphStatus}); Erin cooldownUntil=${erinAfter.cooldownUntil}; follow-up → ${followUp.route.credential_id}`;
    } finally {
      for (const o of others) await patchCredential(o.id, { status: "ACTIVE" });
      // Erin's cooldown is left in place rather than cleared here — but 55.16
      // re-enables every credential straight after, which clears it as a side
      // effect, so she IS back in the pool for the tests that follow. That is
      // why the tests downstream that need a completion use
      // completionRetryingRateLimits: under single dispatch, landing on her is
      // a failed request, not a fallback.
    }
  });
}

async function run55_16(): Promise<void> {
  await test("55.16", "all credentials unavailable -> CTN_NO_CAPACITY", async () => {
    const creds = await getCredentials();
    const activeIds = creds.filter((c) => c.status === "ACTIVE").map((c) => c.id as string);
    for (const id of activeIds) await patchCredential(id, { status: "DISABLED" });
    try {
      let code: string | undefined;
      try {
        await client.completion({
          model: MODEL_A,
          messages: [{ role: "user", content: `route-nocapacity ${randomUUID()}` }],
        });
      } catch (err) {
        code = err instanceof CtnApiError ? err.code : `non-CtnApiError: ${String(err)}`;
      }
      assert(code === "CTN_NO_CAPACITY", `expected CTN_NO_CAPACITY, got ${code}`);
      return `code=${code}`;
    } finally {
      for (const id of activeIds) await patchCredential(id, { status: "ACTIVE" });
    }
  });
}

// ---------------------------------------------------------------------------
// §53 / §54 PRIVACY CANARIES
// ---------------------------------------------------------------------------

async function run54_17(): Promise<void> {
  await test("54.17", "prompt privacy canary: no leak to coordinator surfaces, present at upstream", async () => {
    const uuid = randomUUID();
    const canary = `CANARY_PRIVATE_PROMPT_${uuid}`;

    const result = await completionRetryingRateLimits({
      model: MODEL_A,
      messages: [{ role: "user", content: `Please just repeat this token back to me: ${canary}` }],
    });

    const graph = await (await fetch(`${COORD}/v1/graph`)).json();
    const reqDetail = await (await fetch(`${COORD}/v1/requests/${result.requestId}`)).json();
    const receipt = await (await fetch(`${COORD}/v1/requests/${result.requestId}/receipt`)).json();
    const dbBuf = readFileBuf(DB_PATH);
    const walBuf = existsSync(DB_WAL_PATH) ? readFileBuf(DB_WAL_PATH) : Buffer.alloc(0);
    const mockLogText = readFileTextSafe(MOCK_LOG_PATH);
    const coordLogFile = discoverCoordinatorLogFile();
    const coordLogText = coordLogFile ? readFileTextSafe(coordLogFile) : null;

    const surfaces: Record<string, boolean> = {
      "coordinator.sqlite (raw bytes)": dbBuf.includes(canary),
      "coordinator.sqlite-wal (raw bytes)": walBuf.includes(canary),
      "GET /v1/graph": JSON.stringify(graph).includes(canary),
      "GET /v1/requests/:id": JSON.stringify(reqDetail).includes(canary),
      "GET /v1/requests/:id/receipt": JSON.stringify(receipt).includes(canary),
    };
    if (coordLogText !== null) surfaces[`coordinator stdout log (${coordLogFile})`] = coordLogText.includes(canary);

    const leaked = Object.entries(surfaces)
      .filter(([, v]) => v)
      .map(([k]) => k);
    assert(leaked.length === 0, `canary leaked into: ${leaked.join(", ")}`);

    assert(mockLogText.includes(canary), "canary NOT found in .data/mock-provider-received.log — upstream never received it");

    return (
      `0 leaks across ${Object.keys(surfaces).length} intermediary surfaces; present in mock-provider-received.log as expected` +
      (coordLogFile ? "" : " (coordinator stdout log file not discoverable via lsof — that check was skipped)")
    );
  });
}

async function run53_18(): Promise<void> {
  await test("53.18", "provider-key privacy canary: secret never persisted outside the enclave vault", async () => {
    const uuid = randomUUID();
    const secretMarker = `SECRET_TEST_KEY_${uuid}`;
    const apiKey = `mock-provider-key-${secretMarker}`;
    const att = await client.attestation();

    const contribRes = await (
      await fetch(`${COORD}/v1/contributors`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ displayName: `CanaryTest_${uuid.slice(0, 8)}` }),
      })
    ).json();

    let credentialId: string | undefined;
    try {
      const cred = await client.contributeCredential({
        contributorId: contribRes.id,
        label: `Canary secret test ${uuid.slice(0, 8)}`,
        provider: "mock",
        apiKey,
        allowedModels: [MODEL_A],
        attestation: att,
      });
      credentialId = cred.id as string;
      assert(credentialId, "credential contribution did not return an id");

      const dbBuf = readFileBuf(DB_PATH);
      const walBuf = existsSync(DB_WAL_PATH) ? readFileBuf(DB_WAL_PATH) : Buffer.alloc(0);
      const graph = await (await fetch(`${COORD}/v1/graph`)).json();
      const credsResp = await (await fetch(`${COORD}/v1/credentials`)).json();

      const surfaces: Record<string, boolean> = {
        "coordinator.sqlite (raw bytes)": dbBuf.includes(secretMarker),
        "coordinator.sqlite-wal (raw bytes)": walBuf.includes(secretMarker),
        "GET /v1/graph": JSON.stringify(graph).includes(secretMarker),
        "GET /v1/credentials": JSON.stringify(credsResp).includes(secretMarker),
      };
      const leaked = Object.entries(surfaces)
        .filter(([, v]) => v)
        .map(([k]) => k);
      assert(leaked.length === 0, `secret leaked into: ${leaked.join(", ")}`);
      return `0 occurrences across ${Object.keys(surfaces).length} surfaces; credentialId=${credentialId}`;
    } finally {
      if (credentialId) await patchCredential(credentialId, { status: "DISABLED" });
    }
  });
}

// ---------------------------------------------------------------------------
// §36 POLICY INVARIANT TESTS
// ---------------------------------------------------------------------------

async function run36_19(): Promise<void> {
  await test("36.19", "ALLOW -> exactly one policy proof job created", async () => {
    const result = await completionRetryingRateLimits({
      model: MODEL_A,
      messages: [{ role: "user", content: `invariant-36.19 ${randomUUID()}` }],
    });
    const proof = await client.waitForProof(result.requestId, 20_000);
    assert(
      proof.proof_status && proof.proof_status !== "NOT_REQUIRED",
      `expected a proof job to exist, got status ${proof.proof_status}`
    );

    const db = new DatabaseSync(DB_PATH, { readOnly: true });
    try {
      const row = db.prepare(`SELECT COUNT(*) AS n FROM proofs WHERE request_id = ?`).get(result.requestId) as {
        n: number;
      };
      assert(row.n === 1, `expected exactly 1 row in proofs for this request, got ${row.n}`);
      return `proofs table rows=${row.n}, proof_status=${proof.proof_status}`;
    } finally {
      db.close();
    }
  });
}

async function run36_20(): Promise<void> {
  await test("36.20", "decision-receipt commitment equals compute-receipt commitment (the proof binds to the same commitment via the gate determinism guard)", async () => {
    // Phase 2b: the proof journal's commitment == the gate commitment is enforced
    // by the enclave's determinism guard AND by `--expect-commitment` at VERIFIED
    // time. The immediate, non-2-minute check here is that the DECISION receipt and
    // the COMPUTE receipt (both signed at request time) agree on that commitment.
    const result = await completionRetryingRateLimits({
      model: MODEL_A,
      messages: [{ role: "user", content: `invariant-36.20 ${randomUUID()}` }],
    });
    const detail = await requestDetail(result.requestId);
    const receiptResp = await (await fetch(`${COORD}/v1/requests/${result.requestId}/receipt`)).json();

    const decisionCommitment = detail.policyDecisionReceipt?.receipt?.requestCommitment;
    const receiptCommitment = receiptResp.signed_receipt?.receipt?.requestCommitment;
    assert(decisionCommitment && receiptCommitment, "missing commitment in decision or compute receipt");
    assert(
      decisionCommitment === receiptCommitment,
      `mismatch: decision=${decisionCommitment} receipt=${receiptCommitment}`
    );
    return `commitment=${decisionCommitment}`;
  });
}

async function run36_21(): Promise<void> {
  await test("36.21", "a real receipt's journal is EXACTLY the five allowlist fields (verified by prover/verify's journal-key-set check)", async () => {
    // Over-the-wire against a committed REAL receipt: the reference verifier's
    // `journal-key-set` check passing IS the assertion that the journal carries no
    // prompt-derived data — decoding is not needed and cannot be spoofed.
    const artifact = wireArtifact("allow-real.receipt.bin", {
      protocolVersion: 1,
      requestCommitment: ALLOW_FIXTURE_COMMITMENT,
      policyId: GUEST_POLICY_ID_V2,
      decision: "ALLOW",
      proofNonce: FIXTURE_PROOF_NONCE,
    });
    const verifyRes = await verifyArtifact(artifact);
    assert(verifyRes.proof.valid === true, `expected the real receipt to verify, got ${JSON.stringify(verifyRes.proof)}`);
    const keySet = verifyRes.proof.checks.find((c: any) => c.name === "journal-key-set");
    assert(keySet?.pass === true, `expected journal-key-set to pass, got ${JSON.stringify(keySet)}`);
    assert(
      String(keySet.detail).includes("decision") && String(keySet.detail).includes("proofNonce"),
      `journal-key-set detail should name the five fields, got ${keySet.detail}`
    );
    return `journal-key-set passed: ${keySet.detail}`;
  });
}

// ---------------------------------------------------------------------------
// §5.1 SEALED INTENT
// ---------------------------------------------------------------------------

/**
 * Contributes one credential exactly the way packages/client/src/index.ts does
 * — intent sealed here, only ciphertext posted — but keeps the raw envelope so
 * a test can replay the identical bytes at the coordinator.
 */
async function contributeAndCaptureEnvelope(tag: string): Promise<{
  envelope: Record<string, unknown>;
  credentialId: string;
}> {
  const att = await client.attestation();
  const contributor = (await (
    await fetch(`${COORD}/v1/contributors`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ displayName: `ReplayProbe_${tag}` }),
    })
  ).json()) as { id: string };

  const credentialId = `cred_${randomHex(6)}`;
  const intent: CredentialIntentV1 = {
    version: 1,
    credentialId,
    secret: `mock-provider-key-replay-${tag}`,
    provider: "mock",
    allowedModels: [MODEL_A],
    allowedPolicies: ["safety-v1"],
    contributorId: contributor.id,
    intentNonce: randomHex(32),
  };
  const sealed = await hpkeSeal(
    att.bundle.ingressPublicKey,
    new TextEncoder().encode(canonicalJson(intent))
  );
  const envelope = {
    contributorId: contributor.id,
    label: `Replay probe ${tag}`,
    weight: 1,
    enclaveKeyId: att.bundle.enclaveKeyId,
    enc: sealed.enc,
    encryptedSecret: sealed.ciphertext,
  };

  const first = await fetch(`${COORD}/v1/credentials`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...envelope, credentialId }),
  });
  assert(first.ok, `the first contribution should succeed, got ${first.status}`);
  return { envelope, credentialId };
}

async function run59(): Promise<void> {
  await test("59", "a sealed intent cannot be re-minted — not even under a fresh coordinator id", async () => {
    // Capture one contribution's raw envelope by contributing via the client,
    // then replay the same envelope directly against the coordinator.
    const { envelope, credentialId } = await contributeAndCaptureEnvelope(randomUUID().slice(0, 8));
    try {
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
      return `same-id replay=409, re-mint under a new id=${reminted.status} ${json.error?.code}`;
    } finally {
      await patchCredential(credentialId, { status: "DISABLED" });
    }
  });
}

async function run59_5(): Promise<void> {
  await test("59.5", "the enclave's OWN replay guard refuses a second ingest, and the coordinator relays its 409", async () => {
    // Test 59 exercises the coordinator's row-existence check, which answers
    // before the enclave is ever consulted. This one goes straight at the
    // enclave — the guard that still holds when the relay IS the adversary.
    const att = await client.attestation();
    const credentialId = `cred_${randomHex(6)}`;
    const intent: CredentialIntentV1 = {
      version: 1,
      credentialId,
      secret: `mock-provider-key-enclave-replay-${randomHex(4)}`,
      provider: "mock",
      allowedModels: [MODEL_A],
      allowedPolicies: ["safety-v1"],
      contributorId: `contrib_enclavereplay${randomHex(4)}`,
      intentNonce: randomHex(32),
    };
    const sealed = await hpkeSeal(
      att.bundle.ingressPublicKey,
      new TextEncoder().encode(canonicalJson(intent))
    );
    // Same body both times, credentialId matching the sealed intent, so the
    // id-mismatch check passes and the digest set is what decides.
    const ingestBody = {
      enclaveKeyId: att.bundle.enclaveKeyId,
      enc: sealed.enc,
      encryptedSecret: sealed.ciphertext,
      credentialId,
    };
    const ingest = () =>
      fetch(`${TEE}/credentials/ingest`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(ingestBody),
      });

    const first = await ingest();
    const firstJson = await first.json();
    assert(first.status === 200, `expected the first ingest to succeed, got ${first.status}`);
    assert(
      firstJson.capability?.credentialId === credentialId,
      `capability should carry the sealed id, got ${firstJson.capability?.credentialId}`
    );

    const second = await ingest();
    const secondJson = await second.json();
    assert(second.status === 409, `expected 409 from the enclave replay guard, got ${second.status}`);
    assert(secondJson.error?.code === "CTN_INTENT_REPLAY", `got ${secondJson.error?.code}`);

    // Now the same consumed envelope through the coordinator. Its id was never
    // written to `credentials`, so the local dedupe cannot answer: the 409 has
    // to come back from the enclave and survive the relay unflattened.
    const creds = await getCredentials();
    const knownContributor = creds.find((c) => c.status === "ACTIVE")?.contributorId;
    assert(knownContributor, "no seeded contributor available to post under");

    const relayed = await fetch(`${COORD}/v1/credentials`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contributorId: knownContributor,
        label: "Relayed replay probe",
        credentialId,
        enclaveKeyId: att.bundle.enclaveKeyId,
        enc: sealed.enc,
        encryptedSecret: sealed.ciphertext,
      }),
    });
    const relayedJson = await relayed.json();
    assert(relayed.status === 409, `expected the coordinator to relay 409, got ${relayed.status}`);
    assert(relayedJson.error?.code === "CTN_INTENT_REPLAY", `got ${relayedJson.error?.code}`);
    // The wording proves provenance: this is the enclave's refusal, not the
    // coordinator's own "already contributed" row check.
    assert(
      String(relayedJson.error?.message).includes("sealed intent"),
      `expected the enclave's message, got "${relayedJson.error?.message}"`
    );
    assert(
      !(await getCredentials()).some((c) => c.id === credentialId),
      "a refused replay must not leave a credential row behind"
    );
    return `enclave ingest replay=409 ${secondJson.error?.code}; relayed through coordinator=409 (enclave message preserved)`;
  });
}

async function run60(): Promise<void> {
  await test("60", "capability widening is structurally impossible", async () => {
    const creds = await getCredentials();
    const anyCredentialId = creds.find((c) => c.status === "ACTIVE")?.id;
    assert(anyCredentialId, "no seeded credential available to patch");
    const before = creds.find((c) => c.id === anyCredentialId).capability;

    const direct = await fetch(`${TEE}/credentials/recapability`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ capability: { credentialId: "cred_x", allowedModels: ["anything"] } }),
    });
    assert(direct.status === 404, `expected 404 from removed enclave endpoint, got ${direct.status}`);

    const patch = await fetch(`${COORD}/v1/credentials/${anyCredentialId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ allowedModels: [MODEL_A, MODEL_B] }),
    });
    const json = await patch.json();
    assert(patch.status === 400, `expected 400, got ${patch.status}`);
    assert(json.error?.code === "CTN_CAPABILITY_IMMUTABLE", `got ${json.error?.code}`);

    // The refusal must also be inert: nothing about the signed capability moved.
    const after = (await getCredentials()).find((c) => c.id === anyCredentialId).capability;
    assert(
      canonicalJson(after) === canonicalJson(before),
      `a refused PATCH must not touch the capability: ${canonicalJson(after)}`
    );
    return `enclave recapability=404, PATCH allowedModels=400 ${json.error?.code}, capability v${after.version} unchanged`;
  });
}

// ---------------------------------------------------------------------------
// §5.1 SINGLE DISPATCH
// ---------------------------------------------------------------------------

async function run63(): Promise<void> {
  await test("63", "single dispatch: a dispatched failure never falls through to a second credential", async () => {
    const creds = await getCredentials();
    const erin = creds.find((c) => c.label.toLowerCase().includes("erin"));
    assert(erin, "Erin's rate-limited credential not found");
    const alternatives = creds.filter(
      (c) => c.status === "ACTIVE" && c.id !== erin.id && c.capability.allowedModels.includes(MODEL_FAST)
    );
    // The whole point is that a second eligible credential EXISTS and is still
    // not used. Without one this test would pass vacuously.
    assert(
      alternatives.length >= 1,
      "precondition: demo-model-fast needs a second eligible credential for the loop to fall through TO"
    );

    // Test 55.15 leaves her cooling down; this one needs her back in the pool.
    await patchCredential(erin.id, { status: "ACTIVE" });

    // Routing is least-recently-used, so Erin becomes the head candidate within
    // one rotation of the pool — find the request that reached her rather than
    // assuming an ordering. Her 429 puts her in cooldown, so there is exactly
    // one such request per run.
    let probe: { requestId: string; attempts: any[]; request: any } | null = null;
    try {
      for (let i = 0; i < alternatives.length + 4 && !probe; i++) {
        let requestId: string;
        try {
          requestId = (
            await client.completion({
              model: MODEL_FAST,
              messages: [{ role: "user", content: `single-dispatch-${i} ${randomUUID()}` }],
            })
          ).requestId;
        } catch (err) {
          if (!(err instanceof CtnApiError) || !err.requestId) throw err;
          requestId = err.requestId;
        }
        const detail = await (await fetch(`${COORD}/v1/requests/${requestId}`)).json();
        if (detail.attempts.some((a: any) => a.credential_id === erin.id)) {
          probe = { requestId, attempts: detail.attempts, request: detail.request };
        }
      }
      assert(probe, `Erin's credential was never dispatched to across ${alternatives.length + 4} requests`);

      const dispatched = dispatchedAttempts(probe.attempts);
      assert(
        dispatched.length === 1,
        `expected exactly 1 dispatched attempt, got ${dispatched.length}: ${describeAttempts(probe.attempts)}`
      );
      assert(
        probe.request.status === "FAILED",
        `expected FAILED, got ${probe.request.status} — the 429 fell through to another credential`
      );
      assert(
        probe.request.errorCode === "CTN_PROVIDER_RATE_LIMITED",
        `expected CTN_PROVIDER_RATE_LIMITED, got ${probe.request.errorCode}`
      );
      return `request ${probe.requestId} stopped at ${describeAttempts(probe.attempts)} with ${alternatives.length} eligible credential(s) left unused`;
    } finally {
      // Erin's 429 leaves a 60s cooldown behind, which would deny the next run
      // of this suite the very dispatch it needs. The status write clears it.
      await patchCredential(erin.id, { status: "ACTIVE" });
    }
  });
}

// ---------------------------------------------------------------------------
// §5.1 UNKNOWN OUTCOMES
// ---------------------------------------------------------------------------

async function run64(): Promise<void> {
  await test("64", "unknown outcome books conservative spend against the cap (slow: ~21s)", async () => {
    // MODEL_B deliberately: Erin's rate-limited key does not serve it, so the
    // dispatch this test needs cannot be pre-empted by a 429.
    const before = new Map(
      (await getCredentials()).map((c) => [c.id, { requests: c.today.requests, cost: c.today.estimatedCostUsd }])
    );

    // The mock provider stalls 25s on this prompt; the enclave's provider
    // timeout is 20s, so the dispatch aborts with no answer — and the upstream
    // goes on to produce (and, in the real world, bill for) the completion.
    let completed: string | null = null;
    let failure: unknown = null;
    try {
      completed = (
        await client.completion({
          model: MODEL_B,
          messages: [{ role: "user", content: `summarize this please -HANG ${randomUUID()}` }],
        })
      ).requestId;
    } catch (err) {
      failure = err;
    }
    assert(!completed, `expected the hung dispatch to FAIL, got a completion: ${completed}`);
    assert(failure instanceof CtnApiError, `expected CtnApiError, got ${String(failure)}`);
    assert(failure.code === "CTN_PROVIDER_ERROR", `expected CTN_PROVIDER_ERROR, got ${failure.code}`);
    assert(failure.requestId, "the failure must still name its request");
    const requestId = failure.requestId;

    const detail = await (await fetch(`${COORD}/v1/requests/${requestId}`)).json();
    assert(detail.request.status === "FAILED", `expected FAILED, got ${detail.request.status}`);

    // Attempts come back as stored rows, hence snake_case.
    const attempt = detail.attempts.find((a: any) => a.upstream_outcome_unknown === 1);
    assert(attempt, `no attempt flagged unknown: ${describeAttempts(detail.attempts)}`);
    assert(
      attempt.classification === "timeout",
      `expected a timeout classification, got ${attempt.classification}`
    );
    const assumed = attempt.assumed_spend_micro_usd;
    assert(typeof assumed === "number" && assumed > 0, `assumed spend must be positive, got ${assumed}`);

    const charged = (await getCredentials()).find((c) => c.id === attempt.credential_id);
    const was = before.get(attempt.credential_id);
    assert(was, `credential ${attempt.credential_id} vanished mid-test`);
    assert(
      charged.today.estimatedCostUsd > was.cost,
      `assumed spend must appear in cap accounting: ${was.cost} -> ${charged.today.estimatedCostUsd}`
    );
    assert(
      charged.today.requests === was.requests + 1,
      `request slot consumed: ${was.requests} -> ${charged.today.requests}`
    );
    // The number booked is the enclave's bound, not an invention of the coordinator.
    const delta = charged.today.estimatedCostUsd - was.cost;
    assert(
      Math.abs(delta - assumed / 1_000_000) < 1e-6,
      `booked $${delta} but the enclave assumed $${assumed / 1_000_000}`
    );
    return `${attempt.credential_id} charged ${assumed}µUSD for a timed-out dispatch, requests ${was.requests} -> ${charged.today.requests}`;
  });
}

// ---------------------------------------------------------------------------
// §5.1 PROVIDER CATALOG
// ---------------------------------------------------------------------------

async function run65(): Promise<void> {
  await test("65", "provider catalog serves implemented providers with pinned model ids", async () => {
    const res = await fetch(`${COORD}/v1/providers`);
    assert(res.ok, `expected 200, got ${res.status}`);
    const json = (await res.json()) as { providers: Array<{ provider: string; models: string[] }> };
    const names = json.providers.map((p) => p.provider);
    // The list is the enclave's registry, not a UI constant: a provider with no
    // adapter must not appear, and the order is stable so the picker is stable.
    assert(
      JSON.stringify(names) === JSON.stringify(["anthropic", "mock", "openai"]),
      `got ${JSON.stringify(names)}`
    );
    const anthropic = json.providers.find((p) => p.provider === "anthropic");
    assert(anthropic, "anthropic missing from the catalog");
    assert(
      anthropic.models.includes("claude-haiku-4-5-20251001"),
      `pinned snapshot ids listed, got ${JSON.stringify(anthropic.models)}`
    );
    // Aliases are exactly what a capability must never name (§5.1).
    const aliases = json.providers.flatMap((p) => p.models).filter((m) => /^claude-[a-z]+-\d+-\d+$/.test(m));
    assert(aliases.length === 0, `movable aliases published: ${JSON.stringify(aliases)}`);
    return `${names.join(", ")} · ${json.providers.reduce((n, p) => n + p.models.length, 0)} pinned models`;
  });
}

// ---------------------------------------------------------------------------
// §5.1 REAL PROVIDER SMOKE — env-gated, because these SPEND REAL MONEY
// ---------------------------------------------------------------------------

/**
 * Contributes one credential the way a real contributor does — sealed in this
 * process to the attested ingress key, only ciphertext posted — under a fresh
 * contributor, so the smoke run owns everything it creates and can take it all
 * away again.
 */
async function contributeViaClient(input: {
  provider: string;
  apiKey: string;
  allowedModels: string[];
  label: string;
}): Promise<{ id: string }> {
  const contributorRes = await fetch(`${COORD}/v1/contributors`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ displayName: input.label }),
  });
  // Not `assert(res.ok, `…${await res.text()}`)`: the template argument is
  // evaluated before the assertion runs, which consumes the body the success
  // path is about to parse.
  if (!contributorRes.ok) {
    throw new Error(
      `could not create a contributor: ${contributorRes.status} ${await contributorRes.text()}`
    );
  }
  const contributor = (await contributorRes.json()) as { id: string };

  const credential = await client.contributeCredential({
    contributorId: contributor.id,
    label: input.label,
    provider: input.provider,
    apiKey: input.apiKey,
    allowedModels: input.allowedModels,
    /**
     * A blast-radius bound, not a guarantee: caps are operationally enforced
     * (§4), so this is what stops a bug in the suite from looping on somebody's
     * real key — not what makes spending it impossible.
     */
    operationalLimits: { dailyUsd: 0.25, dailyRequests: 3 },
  });
  return { id: credential.id as string };
}

interface SmokeOutcome {
  /** The coordinator's own record of how the request ended, not the client's inference from it. */
  status: string;
  requestId: string;
  receipt: ComputeReceipt | null;
  route: CompletionResult["route"];
  error: { code: string; message: string; attempts: string } | null;
}

/**
 * One completion, reported rather than thrown.
 *
 * Deliberately NOT `completionRetryingRateLimits`: that helper exists so tests
 * about something else survive Erin's seeded 429, and every retry here would be
 * another dispatch against a real, billed account. A real 429 (or auth failure)
 * is the answer this test wants to print, not something to spend past.
 */
async function submitPrompt(
  prompt: string,
  opts: { model: string; maxTokens: number }
): Promise<SmokeOutcome> {
  let requestId: string;
  let result: CompletionResult | null = null;
  let error: { code: string; message: string } | null = null;
  try {
    result = await client.completion({
      model: opts.model,
      messages: [{ role: "user", content: prompt }],
      max_tokens: opts.maxTokens,
    });
    requestId = result.requestId;
  } catch (err) {
    if (err instanceof PolicyDeniedError) {
      requestId = err.requestId;
      error = { code: "CTN_POLICY_DENIED", message: err.message };
    } else if (err instanceof CtnApiError && err.requestId) {
      requestId = err.requestId;
      error = { code: err.code, message: err.message };
    } else {
      throw err;
    }
  }

  const detail = await (await fetch(`${COORD}/v1/requests/${requestId}`)).json();
  return {
    status: (detail.request?.status as string) ?? "UNKNOWN",
    requestId,
    receipt: result?.receipt?.receipt ?? null,
    route: result?.route ?? null,
    error: error ? { ...error, attempts: describeAttempts(detail.attempts ?? []) } : null,
  };
}

/**
 * Takes the credential out of the pool for good.
 *
 * DELETE, not `status: DISABLED`: a disable is a PATCH away from being an
 * ACTIVE real key again, whereas the coordinator refuses any status write on a
 * DELETED row (409 CTN_CREDENTIAL_DELETED — case 66 holds it to that). What
 * this CANNOT do is erase the sealed secret from
 * the enclave vault on disk (`pnpm reset` does that), so a live-key run should
 * still be followed by rotating the key upstream. Never throws — it runs while
 * an assertion failure may already be in flight, and replacing that failure
 * with a fetch error would hide the thing the run was for.
 */
async function revokeCredential(id: string): Promise<string> {
  try {
    await fetch(`${COORD}/v1/credentials/${id}`, { method: "DELETE" });
    const after = (await getCredentials()).find((c) => c.id === id);
    return (after?.status as string) ?? "GONE";
  } catch (err) {
    return `revoke failed: ${err instanceof Error ? err.message : String(err)}`;
  }
}

/**
 * Revokes by LABEL, not by the id the happy path returned.
 *
 * The id only exists once `contributeViaClient` has returned, and the case that
 * matters is the one where the credential row was written and the call threw
 * anyway. Cleaning up by the label the run chose means a live key cannot survive
 * the test just because the suite lost track of its id. Never throws: it runs
 * while an assertion failure may already be in flight.
 *
 * The label is FIXED (`smoke-<provider>`) rather than random, and that is a
 * deliberate trade with a real cost on both sides. Fixed: a run killed midway —
 * ^C, a crashed enclave — leaves a live key active, and the next run revokes it.
 * Random: nothing ever cleans that up, but a human credential that happens to be
 * labelled `smoke-anthropic` is safe from us. We chose fixed, because the
 * failure it prevents is a real provider key left routable on an unauthenticated
 * coordinator, and the failure it risks is terminally revoking a demo credential
 * that a contributor named after our test — recoverable by contributing again,
 * since the key itself is unharmed.
 */
async function revokeSmokeCredentials(label: string): Promise<{ ok: boolean; detail: string }> {
  let targets: any[];
  try {
    targets = (await getCredentials()).filter((c) => c.label === label && c.status !== "DELETED");
  } catch (err) {
    return { ok: false, detail: `could not list credentials: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (targets.length === 0) return { ok: true, detail: "nothing to revoke" };
  const results: string[] = [];
  for (const target of targets) results.push(`${target.id}=${await revokeCredential(target.id)}`);
  return { ok: results.every((r) => r.endsWith("=DELETED")), detail: results.join(", ") };
}

// ---------------------------------------------------------------------------
// §50 REVOCATION IS TERMINAL
// ---------------------------------------------------------------------------

async function run66(): Promise<void> {
  await test("66", "revocation is terminal: a DELETED credential cannot be re-activated", async () => {
    const label = `terminal-revocation-${randomHex(4)}`;
    const cred = await contributeViaClient({
      provider: "mock",
      apiKey: `mock-provider-key-${label}`,
      allowedModels: [MODEL_A],
      label,
    });

    // A status the API does not define is not "some other state" — it is a
    // string nothing downstream understands, written into the column routing
    // reads. Refused, and the refusal has to be inert.
    const bogus = await patchCredentialRaw(cred.id, { status: "TOTALLY_FINE" });
    assert(bogus.status === 400, `expected 400 for an undefined status, got ${bogus.status}`);
    assert(bogus.json.error?.code === "CTN_INVALID_STATUS", `got ${bogus.json.error?.code}`);
    assert(
      (await getCredentials()).find((c) => c.id === cred.id)?.status === "ACTIVE",
      "a refused status write must not touch the row"
    );

    assert((await revokeCredential(cred.id)) === "DELETED", "DELETE should leave the credential DELETED");

    // The claim under test. The real-provider smoke tests below revoke a live
    // API key exactly this way, and both the README and VALIDATION say a revoked
    // credential is never routable again — which is only true if the coordinator
    // refuses to write ACTIVE over DELETED.
    const revive = await patchCredentialRaw(cred.id, { status: "ACTIVE" });
    assert(revive.status === 409, `expected 409 reviving a revoked credential, got ${revive.status}`);
    assert(revive.json.error?.code === "CTN_CREDENTIAL_DELETED", `got ${revive.json.error?.code}`);
    assert(
      (await getCredentials()).find((c) => c.id === cred.id)?.status === "DELETED",
      "the revoked credential must still be DELETED"
    );

    // Status is the field routing reads, so unroutable follows from it — but the
    // point of the guard is traffic, so check traffic.
    let inspected = 0;
    for (let i = 0; i < 3; i++) {
      let requestId: string | undefined;
      try {
        requestId = (
          await client.completion({
            model: MODEL_A,
            messages: [{ role: "user", content: `post-revocation-${i} ${randomUUID()}` }],
          })
        ).requestId;
      } catch (err) {
        requestId = err instanceof CtnApiError ? err.requestId : undefined;
      }
      if (!requestId) continue;
      inspected++;
      const detail = await (await fetch(`${COORD}/v1/requests/${requestId}`)).json();
      assert(
        !detail.attempts.some((a: any) => a.credential_id === cred.id),
        `a revoked credential was dispatched to on request ${requestId}`
      );
    }
    // Without this, a stack that produced no requests at all would report "0
    // attempts after revocation" — a true sentence about nothing.
    assert(inspected > 0, "no request reached the coordinator, so the traffic check proved nothing");
    return `undefined status=400 CTN_INVALID_STATUS (inert), re-activation=409 CTN_CREDENTIAL_DELETED, 0 attempts across ${inspected} request(s)`;
  });
}

/**
 * The one test in this suite that talks to a real provider on a real account.
 *
 * Skipped unless the key is present, and gated per provider rather than as a
 * block: a machine with one of the two keys should run the half it can pay for.
 */
async function runRealProviderSmoke(
  id: string,
  provider: string,
  envVar: string,
  model: string
): Promise<void> {
  const apiKey = process.env[envVar];
  if (!apiKey) {
    const reason = `no ${envVar}`;
    skipped.push({ id, name: `REAL ${provider} round-trip`, reason });
    console.log(`  · skipping real-provider smoke for ${provider} (set ${envVar} to run)`);
    return;
  }

  await test(id, `REAL ${provider} round-trip (spends ~<$0.01)`, async () => {
    const label = `smoke-${provider}`;
    let detail: string;
    let credId = "(never contributed)";
    let revocation: { ok: boolean; detail: string } = { ok: false, detail: "not attempted" };
    // The contribution is INSIDE the try: it is the statement that puts a real
    // key in the vault, so it is the first statement the cleanup must cover.
    try {
      credId = (await contributeViaClient({ provider, apiKey, allowedModels: [model], label })).id;
      const res = await submitPrompt("Reply with the single word: pong", { model, maxTokens: 16 });
      assert(
        res.status === "COMPLETE",
        `expected COMPLETE, got ${res.status} on request ${res.requestId}: ${JSON.stringify(res.error)}`
      );
      // The pinned snapshot id is served by this credential and nothing else in
      // the pool, so a route anywhere else would mean the assertions below are
      // describing some other key's traffic.
      assert(
        res.route?.credential_id === credId,
        `the smoke credential should have served it, got ${res.route?.credential_id}`
      );
      assert(res.receipt, "a COMPLETE request must carry a signed receipt");
      assert((res.receipt.usage.inputTokens ?? 0) > 0, "real token counts recorded");
      assert(
        res.receipt.usage.pricingTableDigest?.startsWith("0x"),
        `pricing digest present, got ${res.receipt.usage.pricingTableDigest}`
      );
      const cost = (res.receipt.usage.estimatedCostMicroUsd ?? 0) / 1_000_000;
      detail =
        `${model} → ${res.receipt.usage.inputTokens}/${res.receipt.usage.outputTokens} tok, ` +
        `est $${cost.toFixed(6)} from price table ${res.receipt.usage.pricingTableDigest?.slice(0, 10)}`;
    } finally {
      // A real key must not outlive this test, whether it passed or failed.
      revocation = await revokeSmokeCredentials(label);
      if (!revocation.ok) {
        console.log(
          `\n  !! ${provider} smoke credential NOT revoked (${revocation.detail}) — rotate that key`
        );
      }
    }
    assert(revocation.ok, `the smoke credential must not survive the test: ${revocation.detail}`);
    assert(
      revocation.detail.includes(`${credId}=DELETED`),
      `the contributed credential ${credId} was not the one revoked: ${revocation.detail}`
    );
    return `${detail}; credential ${credId} revoked`;
  });
}

// ---------------------------------------------------------------------------
// PHASE 2B — GATE-PATH RESTRUCTURING
//
// The guest executor (:4500) is the authoritative gate for EVERY request, run
// BEFORE candidate discovery. Every gated request gets a signed
// PolicyDecisionReceiptV1 and an enqueued proof (ALLOW and DENY, including
// no-capacity). PROVER_UNAVAILABLE is a system failure, never a decision.
// ---------------------------------------------------------------------------

const PROVER_URL = process.env.CTN_PROVER_URL ?? "http://127.0.0.1:4500";

/** The guest gate's authoritative POLICY_ID_V2, from the daemon /health. */
async function guestPolicyId(): Promise<string> {
  return ((await (await fetch(`${PROVER_URL}/health`)).json()) as { policyId: string }).policyId;
}
/** The TypeScript package's PREVIEW policy id (must differ from the guest's). */
async function previewPolicyId(): Promise<string> {
  return ((await (await fetch(`${COORD}/v1/policy`)).json()) as { policyId: string }).policyId;
}
async function requestDetail(id: string): Promise<any> {
  return await (await fetch(`${COORD}/v1/requests/${id}`)).json();
}

/** All ACTIVE credentials disabled for the duration of `fn`, then restored. */
async function withNoCapacity<T>(fn: () => Promise<T>): Promise<T> {
  const activeIds = (await getCredentials()).filter((c) => c.status === "ACTIVE").map((c) => c.id as string);
  for (const id of activeIds) await patchCredential(id, { status: "DISABLED" });
  try {
    return await fn();
  } finally {
    for (const id of activeIds) await patchCredential(id, { status: "ACTIVE" });
  }
}

async function run2b_1(): Promise<void> {
  await test("2b.1", "no-capacity ALLOW: gated (decision receipt under the guest policyId), proved, returns CTN_NO_CAPACITY", async () => {
    const [guest, preview] = await Promise.all([guestPolicyId(), previewPolicyId()]);
    assert(guest !== preview, `the guest and preview policy ids must differ (guest=${guest}, preview=${preview})`);

    return await withNoCapacity(async () => {
      let code: string | undefined;
      let requestId: string | undefined;
      try {
        await client.completion({ model: MODEL_A, messages: [{ role: "user", content: `nocap-allow ${randomUUID()}` }] });
      } catch (err) {
        code = err instanceof CtnApiError ? err.code : `non-CtnApiError: ${String(err)}`;
        requestId = err instanceof CtnApiError ? err.requestId : undefined;
      }
      assert(code === "CTN_NO_CAPACITY", `expected CTN_NO_CAPACITY, got ${code}`);
      assert(requestId, "the no-capacity request surfaced no request id");

      const detail = await requestDetail(requestId);
      const dr = detail.policyDecisionReceipt;
      assert(dr, "a gated no-capacity request must still have a PolicyDecisionReceiptV1");
      assert(dr.receipt.decision === "ALLOW", `expected ALLOW verdict, got ${dr.receipt.decision}`);
      assert(dr.receipt.policyId === guest, `decision receipt policyId ${dr.receipt.policyId} must equal the daemon /health policyId ${guest}`);
      assert(dr.receipt.policyId !== preview, `decision receipt policyId must NOT be the preview pkg.policyId ${preview}`);
      assert(detail.proof && detail.proof.status !== "NOT_REQUIRED", `a proof must be enqueued for the gated request, got ${JSON.stringify(detail.proof)}`);
      assert(detail.request.status === "FAILED" && detail.request.errorCode === "CTN_NO_CAPACITY", `expected FAILED/CTN_NO_CAPACITY, got ${detail.request.status}/${detail.request.errorCode}`);
      return `ALLOW gated under guest ${guest.slice(0, 14)}… (≠ preview ${preview.slice(0, 10)}…), proof=${detail.proof.status}, returned CTN_NO_CAPACITY`;
    });
  });
}

async function run2b_2(): Promise<void> {
  await test("2b.2", "DENY is gated AND proved, zero provider calls (proofStarted true for DENY)", async () => {
    const mockBefore = fileSize(MOCK_LOG_PATH);
    let requestId: string | undefined;
    try {
      await client.completion({ model: MODEL_A, messages: [{ role: "user", content: DENY_PROMPT }] });
      throw new Error("expected a PolicyDeniedError, the request unexpectedly succeeded");
    } catch (err) {
      if (err instanceof PolicyDeniedError) requestId = err.requestId;
      else throw err;
    }
    assert(requestId, "no requestId captured from the denial");
    const detail = await requestDetail(requestId);
    assert(detail.request.status === "DENIED", `expected DENIED, got ${detail.request.status}`);
    assert(detail.attempts.length === 0, `expected 0 provider attempts, got ${detail.attempts.length}`);
    assert(fileSize(MOCK_LOG_PATH) === mockBefore, "mock-provider log grew despite a DENY decision");
    const dr = detail.policyDecisionReceipt;
    assert(dr && dr.receipt.decision === "DENY", `expected a signed DENY decision receipt, got ${JSON.stringify(dr?.receipt)}`);
    // The whole point of Phase 2b: DENY is proved too.
    assert(detail.proof && detail.proof.status !== "NOT_REQUIRED", `expected a proof enqueued for DENY, got ${JSON.stringify(detail.proof)}`);
    return `DENY gated+proved (proof=${detail.proof.status}), 0 provider calls, receipt.decision=DENY`;
  });
}

async function run2b_3(): Promise<void> {
  await test("2b.3", "gate BEFORE discovery: a no-capacity DENY still denies (and proves), not CTN_NO_CAPACITY", async () => {
    return await withNoCapacity(async () => {
      const mockBefore = fileSize(MOCK_LOG_PATH);
      let requestId: string | undefined;
      let code: string | undefined;
      try {
        await client.completion({ model: MODEL_A, messages: [{ role: "user", content: DENY_PROMPT }] });
      } catch (err) {
        if (err instanceof PolicyDeniedError) {
          requestId = err.requestId;
          code = "CTN_POLICY_DENIED";
        } else {
          code = err instanceof CtnApiError ? err.code : String(err);
          requestId = err instanceof CtnApiError ? err.requestId : undefined;
        }
      }
      // If discovery ran before the gate, this would be CTN_NO_CAPACITY. The gate
      // runs first, so a denied prompt is denied regardless of capacity.
      assert(code === "CTN_POLICY_DENIED", `gate must precede discovery: expected CTN_POLICY_DENIED, got ${code}`);
      assert(requestId, "no requestId captured");
      const detail = await requestDetail(requestId);
      assert(detail.request.status === "DENIED", `expected DENIED, got ${detail.request.status}`);
      assert(detail.attempts.length === 0, "expected 0 provider attempts");
      assert(fileSize(MOCK_LOG_PATH) === mockBefore, "mock-provider log grew despite a DENY decision");
      assert(detail.policyDecisionReceipt?.receipt.decision === "DENY", "expected a DENY decision receipt");
      assert(detail.proof && detail.proof.status !== "NOT_REQUIRED", "expected a proof enqueued for the no-capacity DENY");
      return `no-capacity DENY → ${code} (not CTN_NO_CAPACITY), proof=${detail.proof.status}`;
    });
  });
}

async function run2b_4(): Promise<void> {
  await test("2b.4", "commitment guard: a guest journal whose commitment != the enclave recomputation is rejected (fail closed)", async () => {
    const modUrl = pathToFileURL(join(ROOT, "services/tee-sim/src/authorize.ts")).href;
    const mod = await import(modUrl);
    const canonical = toCanonicalRequest({ model: MODEL_A, messages: [{ role: "user", content: "benign gate probe" }] });
    const nonce = randomHex(32);

    // A journal that claims a DIFFERENT commitment than the enclave will recompute.
    const badJournal = { requestCommitment: "0x" + "de".repeat(32), decision: "ALLOW", policyId: "0xpreview" };
    let threw = false;
    let typed = false;
    try {
      mod.AuthorizedRequest.fromGuestJournal(canonical, nonce, badJournal, 1);
    } catch (e) {
      threw = true;
      typed = e instanceof mod.CommitmentMismatchError;
    }
    assert(threw && typed, "fromGuestJournal must throw CommitmentMismatchError on a commitment mismatch");

    let guardThrew = false;
    try {
      mod.assertGuestCommitment("0xaaaa", "0xbbbb");
    } catch {
      guardThrew = true;
    }
    assert(guardThrew, "assertGuestCommitment must throw when the two commitments differ");

    // Control: a MATCHING commitment is accepted and yields an ALLOW authorization.
    const good = {
      requestCommitment: requestCommitment(canonicalBytes(canonical), nonce),
      decision: "ALLOW" as const,
      policyId: await guestPolicyId(),
    };
    const ok = mod.AuthorizedRequest.fromGuestJournal(canonical, nonce, good, 1);
    assert(ok.decision === "ALLOW" && ok.authorized, "a matching commitment must be accepted as ALLOW");
    return "mismatched guest commitment rejected (fail closed); matching commitment accepted";
  });
}

async function run2b_6(): Promise<void> {
  await test("2b.6", "pending gate is bound to its commitment: a mismatched /execute is rejected and does NOT consume the victim gate", async () => {
    const att = await client.attestation();
    const { envelope } = await sealCustom(att, {
      model: MODEL_A,
      messages: [{ role: "user", content: `gate-binding ${randomUUID()}` }],
    });

    // Two-call flow, step 1: gate the request. This parks the ALLOW plaintext
    // under envelope.requestId, bound to the returned commitment.
    const gateRes = await fetch(`${TEE}/gate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope }),
    });
    const gate = await gateRes.json();
    assert(gate.decision === "ALLOW", `expected an ALLOW gate to park, got ${gate.decision} / ${JSON.stringify(gate.error)}`);
    assert(typeof gate.commitment === "string" && gate.commitment.length > 0, "gate must return the commitment");

    const creds = await getCredentials();
    const real = creds.find((c) => c.status === "ACTIVE" && c.capability.allowedModels.includes(MODEL_A));
    assert(real, "no active credential found for model-a");
    // The public API hides encrypted_blob; read it from the DB so the matching
    // /execute is a genuine COMPLETE dispatch (blob digest must match capability).
    const db = new DatabaseSync(DB_PATH, { readOnly: true });
    let encryptedBlob: string;
    try {
      encryptedBlob = (db.prepare(`SELECT encrypted_blob FROM credentials WHERE id = ?`).get(real.id) as { encrypted_blob: string }).encrypted_blob;
    } finally {
      db.close();
    }
    const candidate = {
      credentialId: real.id,
      contributorId: real.contributorId,
      provider: real.provider,
      status: "ACTIVE",
      encryptedBlob,
      capability: real.capability,
      capabilitySignature: real.capabilitySignature,
    };

    // Attacker knows the pending requestId but not the commitment. Their /execute
    // presents a WRONG commitment — must be rejected with a fixed string, and the
    // victim gate must NOT be consumed or redirected to attacker candidates.
    const mockBefore = fileSize(MOCK_LOG_PATH);
    const badRes = await fetch(`${TEE}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope, candidates: [candidate], requestCommitment: "0x" + "de".repeat(32) }),
    });
    const badJson = await badRes.json();
    assert(badRes.status === 400, `mismatched /execute must be 400, got ${badRes.status}`);
    assert(badJson?.error?.code === "CTN_INVALID_ENVELOPE", `expected CTN_INVALID_ENVELOPE, got ${JSON.stringify(badJson)}`);
    assert(
      badJson.error.message === "execute does not match the parked gate commitment",
      `expected the fixed-string rejection, got ${JSON.stringify(badJson.error.message)}`
    );
    assert(!badJson.status, "a rejected /execute must not return a dispatch result");
    assert(fileSize(MOCK_LOG_PATH) === mockBefore, "a mismatched /execute must not dispatch to any provider");

    // The legitimate holder presents the correct commitment: the victim gate is
    // still intact and dispatches normally.
    const okRes = await fetch(`${TEE}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope, candidates: [candidate], requestCommitment: gate.commitment }),
    });
    const okJson = await okRes.json();
    assert(okRes.status === 200, `the correct /execute must succeed, got ${okRes.status} ${JSON.stringify(okJson?.error)}`);
    assert(okJson.status === "COMPLETE", `expected COMPLETE after a matching commitment, got ${okJson.status}`);
    return `mismatched /execute → 400 fixed-string (0 dispatch); matching commitment → ${okJson.status}`;
  });
}

/**
 * The one LIVE ~2-minute real prove. Gated behind CTN_E2E_REAL_PROOF=1 so the
 * default suite stays fast; run it at least once against the live :4500 daemon.
 * Asserts the full VERIFIED chain: decision receipt reads "pending" immediately,
 * the proof reaches VERIFIED only after `prover/verify` passes, the journal is the
 * five allowlist fields, and one policyId (POLICY_ID_V2) spans the decision
 * receipt, the proof journal, and the compute receipt.
 */
async function run2b_7(): Promise<void> {
  const id = "2b.7";
  const name = "real proof end-to-end: ALLOW -> VERIFIED via prover/verify, identity unified on POLICY_ID_V2 (gated, ~2 min)";
  if (process.env.CTN_E2E_REAL_PROOF !== "1") {
    skipped.push({ id, name, reason: "set CTN_E2E_REAL_PROOF=1 to run the ~2-min live prove" });
    return;
  }
  await test(id, name, async () => {
    const t0 = Date.now();
    const guest = await guestPolicyId();
    const result = await completionRetryingRateLimits({
      model: MODEL_A,
      messages: [{ role: "user", content: `real-proof ${randomUUID()}` }],
    });

    // The decision receipt exists immediately; proving is asynchronous.
    const early = await requestDetail(result.requestId);
    assert(early.policyDecisionReceipt, "a decision receipt must exist immediately (before proving finishes)");

    // Poll to a terminal proof state — NO 90s/120s cap; a real prove is minutes.
    let proof: any;
    const deadline = Date.now() + 6 * 60 * 1000;
    for (;;) {
      proof = await (await fetch(`${COORD}/v1/requests/${result.requestId}/proof`)).json();
      if (proof.proof_status === "VERIFIED" || proof.proof_status === "FAILED") break;
      assert(Date.now() < deadline, `proof did not settle within 6 min (last status=${proof.proof_status})`);
      await new Promise((r) => setTimeout(r, 2000));
    }
    const wallMs = Date.now() - t0;
    assert(proof.proof_status === "VERIFIED", `expected VERIFIED, got ${proof.proof_status} (${proof.error ?? ""})`);
    assert(proof.proof_verified === true, "proof_verified must be true ONLY after prover/verify passed");
    assert(proof.verification?.valid === true, `enclave reference verification must pass, got ${JSON.stringify(proof.verification)}`);

    const j = proof.decoded_journal;
    assert(j, "a VERIFIED proof must expose its decoded journal");
    const keys = Object.keys(j).sort();
    assert(
      JSON.stringify(keys) === JSON.stringify(["decision", "policyId", "proofNonce", "protocolVersion", "requestCommitment"]),
      `journal keys must be exactly the five allowlist fields, got [${keys.join(", ")}]`
    );
    assert(/^0x[0-9a-f]{64}$/.test(proof.artifact_digest ?? ""), `artifact_digest must be a 0x sha256, got ${proof.artifact_digest}`);

    // Identity unified on POLICY_ID_V2 across decision receipt, proof, compute receipt.
    const detail = await requestDetail(result.requestId);
    const receiptResp = await (await fetch(`${COORD}/v1/requests/${result.requestId}/receipt`)).json();
    const decisionPolicy = detail.policyDecisionReceipt.receipt.policyId;
    const computePolicy = receiptResp.signed_receipt.receipt.policy.policyId;
    assert(j.policyId === guest, `proof journal policyId ${j.policyId} != guest ${guest}`);
    assert(decisionPolicy === guest, `decision receipt policyId ${decisionPolicy} != guest ${guest}`);
    assert(computePolicy === guest, `compute receipt policyId ${computePolicy} != guest ${guest}`);
    assert(
      j.requestCommitment === detail.policyDecisionReceipt.receipt.requestCommitment,
      `proof journal commitment must equal the decision receipt commitment`
    );
    assert(
      /^0x[0-9a-f]{64}$/.test(detail.proof?.decisionReceiptDigest ?? ""),
      `decisionReceiptDigest must be set, got ${detail.proof?.decisionReceiptDigest}`
    );

    return `VERIFIED in ${(wallMs / 1000).toFixed(1)}s; prover/verify passed; single policyId ${guest.slice(0, 14)}… across decision+proof+compute; digests set`;
  });
}

// ---- daemon lifecycle for the PROVER_UNAVAILABLE case ----

function daemonPidOn4500(): string | undefined {
  try {
    return execSync(`lsof -iTCP:4500 -sTCP:LISTEN -t`, { encoding: "utf8" }).trim().split("\n")[0]?.trim() || undefined;
  } catch {
    return undefined;
  }
}
async function waitDaemon(up: boolean, timeoutMs = 20000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await fetch(`${PROVER_URL}/health`).then((r) => r.ok).catch(() => false);
    if (ok === up) return true;
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}
async function restartDaemon(): Promise<void> {
  const bin = join(ROOT, "prover/target/release/host");
  const child = spawn(bin, ["--serve", "--port", "4500"], { detached: true, stdio: "ignore", env: process.env });
  child.unref();
  await waitDaemon(true, 20000);
}

async function run2b_5(): Promise<void> {
  await test("2b.5", "PROVER_UNAVAILABLE: gate down → system-failure record, no dispatch, no decision receipt, absent from denial metrics", async () => {
    const pid = daemonPidOn4500();
    assert(pid, "could not find the :4500 daemon to take it down for this case");
    const mockBefore = fileSize(MOCK_LOG_PATH);
    const statsBefore = await (await fetch(`${COORD}/v1/stats`)).json();

    try {
      execSync(`kill -9 ${pid}`);
      const down = await waitDaemon(false, 10000);
      assert(down, "the :4500 daemon did not go down");

      let code: string | undefined;
      let requestId: string | undefined;
      try {
        await client.completion({ model: MODEL_A, messages: [{ role: "user", content: `prover-down ${randomUUID()}` }] });
      } catch (err) {
        if (err instanceof PolicyDeniedError) code = "CTN_POLICY_DENIED";
        else if (err instanceof CtnApiError) {
          code = err.code;
          requestId = err.requestId;
        } else code = `non-CtnApiError: ${String(err)}`;
      }
      assert(code === "CTN_PROVER_UNAVAILABLE", `expected CTN_PROVER_UNAVAILABLE (never a decision), got ${code}`);
      assert(requestId, "no requestId surfaced for the system failure");

      const detail = await requestDetail(requestId);
      assert(detail.request.status === "FAILED", `a system failure is FAILED, got ${detail.request.status}`);
      assert(detail.request.errorCode === "CTN_PROVER_UNAVAILABLE", `expected CTN_PROVER_UNAVAILABLE errorCode, got ${detail.request.errorCode}`);
      // No fake decision: no PolicyDecisionReceiptV1, no ALLOW/DENY, TS did not gate.
      assert(detail.policyDecisionReceipt === null, "PROVER_UNAVAILABLE must not manufacture a PolicyDecisionReceiptV1");
      assert(!detail.request.policyResult, `no ALLOW/DENY may be recorded (TS engine must not gate), got ${detail.request.policyResult}`);
      // No dispatch.
      assert(detail.attempts.length === 0, `expected 0 provider attempts, got ${detail.attempts.length}`);
      assert(fileSize(MOCK_LOG_PATH) === mockBefore, "mock-provider log grew despite the gate being down");
      // Kept out of denial metrics.
      const statsAfter = await (await fetch(`${COORD}/v1/stats`)).json();
      assert(
        statsAfter.counts.denied === statsBefore.counts.denied,
        `PROVER_UNAVAILABLE must not count as a denial: ${statsBefore.counts.denied} -> ${statsAfter.counts.denied}`
      );
      // Graph shows a system failure, not a denial.
      const graphStatus = await awaitGraphNodeStatus(`req:${requestId}`, "FAILED");
      assert(graphStatus === "FAILED", `graph node should render FAILED (system failure), got ${graphStatus ?? "<missing>"}`);
      return `gate down → CTN_PROVER_UNAVAILABLE, status=FAILED, 0 attempts, no receipt, denied metric unchanged (${statsAfter.counts.denied})`;
    } finally {
      await restartDaemon();
    }
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function healthCheck(): Promise<void> {
  const targets = [
    [`${COORD}/health`, "coordinator"],
    [`${TEE}/health`, "tee-sim"],
    ["http://127.0.0.1:4300/health", "mock-provider"],
    // Phase 2b: the guest executor is the authoritative gate for every request,
    // so the whole suite now depends on it. (2b.5 takes it down deliberately and
    // restarts it.)
    [`${PROVER_URL}/health`, "prover daemon (:4500)"],
  ] as const;
  for (const [url, name] of targets) {
    const res = await fetch(url).catch(() => null);
    if (!res || !res.ok) {
      console.error(`FATAL: ${name} is not reachable at ${url}. The stack must already be running.`);
      process.exit(2);
    }
  }
}

async function main(): Promise<void> {
  await healthCheck();

  const initialCreds = await getCredentials();
  const initialStatusById = new Map(initialCreds.map((c) => [c.id, c.status]));
  console.log(`Baseline: ${initialCreds.length} credentials, statuses = ${[...initialStatusById.values()].join(",")}\n`);

  console.log("=== §56 SECURITY TESTS ===");
  await run56_1();
  await run56_2();
  await run56_3();
  await run56_4();
  await run56_5();
  await run56_6();
  await run56_7();
  await run56_8();
  await run56_9();
  await run56_10();
  await run56_11();

  console.log("\n=== §55 ROUTING TESTS ===");
  await run55_12();
  await run55_13();
  await run55_14();
  await run55_15();
  await run55_16();

  console.log("\n=== §53/§54 PRIVACY CANARIES ===");
  await run54_17();
  await run53_18();

  console.log("\n=== §36 POLICY INVARIANT TESTS ===");
  await run36_19();
  await run36_20();
  await run36_21();

  console.log("\n=== §5.1 SEALED INTENT ===");
  await run59();
  await run59_5();

  console.log("\n=== §50 CAPABILITY IMMUTABILITY ===");
  await run60();

  console.log("\n=== §5.1 SINGLE DISPATCH ===");
  await run63();

  console.log("\n=== §5.1 UNKNOWN OUTCOMES ===");
  await run64();

  console.log("\n=== §5.1 PROVIDER CATALOG ===");
  await run65();

  console.log("\n=== §50 REVOCATION IS TERMINAL ===");
  await run66();

  console.log("\n=== PHASE 2B — GATE-PATH RESTRUCTURING ===");
  await run2b_1();
  await run2b_2();
  await run2b_3();
  await run2b_4();
  await run2b_6();
  await run2b_7(); // gated real prove (CTN_E2E_REAL_PROOF=1); self-skips otherwise
  // 2b.5 takes the :4500 daemon down and restarts it — run it LAST so nothing
  // after it depends on the daemon being up.
  await run2b_5();

  console.log("\n=== §5.1 REAL PROVIDER SMOKE (env-gated) ===");
  await runRealProviderSmoke("70", "anthropic", "ANTHROPIC_API_KEY", "claude-haiku-4-5-20251001");
  await runRealProviderSmoke("71", "openai", "OPENAI_API_KEY", "gpt-4o-mini-2024-07-18");

  // ---- Summary ----
  console.log("\n\n=========================== SUMMARY ===========================");
  const idWidth = Math.max(...results.map((r) => r.id.length), ...skipped.map((s) => s.id.length), 6);
  const nameWidth = Math.min(
    70,
    Math.max(...results.map((r) => r.name.length), ...skipped.map((s) => s.name.length))
  );
  for (const r of results) {
    const status = r.pass ? "PASS" : "FAIL";
    console.log(`${status.padEnd(5)} [${r.id.padEnd(idWidth)}] ${r.name.padEnd(nameWidth)} ${r.pass ? "" : "— " + r.detail}`);
  }
  for (const s of skipped) {
    console.log(`SKIP  [${s.id.padEnd(idWidth)}] ${s.name.padEnd(nameWidth)} — ${s.reason}`);
  }
  const passCount = results.filter((r) => r.pass).length;
  // The skip count is part of the headline, not a footnote: a suite that ran 27
  // of 29 cases has not verified 29 things.
  console.log(
    `\n${passCount}/${results.length} passed` +
      (skipped.length > 0
        ? `, ${skipped.length} skipped (${skipped.map((s) => `${s.id}: ${s.reason}`).join("; ")}).`
        : ".")
  );

  // ---- State restoration check ----
  const finalCreds = await getCredentials();
  const seedIds = [...initialStatusById.keys()];
  const notRestored = seedIds.filter((id) => {
    const finalStatus = finalCreds.find((c) => c.id === id)?.status;
    return finalStatus !== initialStatusById.get(id);
  });
  console.log("\n=========================== STATE RESTORATION ===========================");
  if (notRestored.length === 0) {
    console.log(`All ${seedIds.length} original credentials restored to their initial status.`);
  } else {
    console.log(`WARNING: the following credentials were NOT restored to their initial status:`);
    for (const id of notRestored) {
      const finalStatus = finalCreds.find((c) => c.id === id)?.status;
      console.log(`  ${id}: expected ${initialStatusById.get(id)}, got ${finalStatus}`);
    }
  }

  process.exit(passCount === results.length && notRestored.length === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("FATAL, uncaught error in test runner:", err);
  process.exit(2);
});

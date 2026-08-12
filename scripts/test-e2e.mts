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
import { execSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import { ComputeTrustClient, CtnApiError, PolicyDeniedError, type AttestationEnvelope } from "@ctn/client";
import {
  canonicalJson,
  generateHpkeKeyPair,
  hpkeSeal,
  randomHex,
  toCanonicalRequest,
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

async function getCredentials(): Promise<any[]> {
  const res = await fetch(`${COORD}/v1/credentials`);
  const json = (await res.json()) as { data: any[] };
  return json.data;
}
async function patchCredential(id: string, body: Record<string, unknown>): Promise<any> {
  const res = await fetch(`${COORD}/v1/credentials/${id}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
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
    const nonce = randomHex(32);
    const { envelope: env1 } = await sealCustom(
      att,
      { model: MODEL_A, messages: [{ role: "user", content: `replay-1 ${randomUUID()}` }] },
      { nonce }
    );
    const r1 = await postSecure(env1);
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
  const result = await client.completion({
    model: MODEL_A,
    messages: [{ role: "user", content: `${tag} ${randomUUID()}` }],
  });
  await client.waitForProof(result.requestId, 20_000);
  return { requestId: result.requestId, commitment: result.commitment };
}

async function run56_7(): Promise<void> {
  await test("56.7", "modified proof journal -> verification invalid", async () => {
    const { requestId } = await completeAndWaitForProof("invariant-56.7");
    const proofResp = await (await fetch(`${COORD}/v1/requests/${requestId}/proof`)).json();
    assert(proofResp.receipt, `no proof receipt available (status=${proofResp.proof_status})`);

    const tampered = JSON.parse(JSON.stringify(proofResp.receipt));
    tampered.journal.decision = "DENY";

    const verifyRes = await (
      await fetch(`${TEE}/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ proof: tampered }),
      })
    ).json();

    assert(verifyRes.proof.valid === false, `expected invalid, got ${JSON.stringify(verifyRes.proof)}`);
    const sealCheck = verifyRes.proof.checks.find((c: any) => c.name === "proof seal valid");
    assert(sealCheck?.pass === false, `expected 'proof seal valid' to fail after journal tamper, got ${JSON.stringify(sealCheck)}`);
    return `valid=${verifyRes.proof.valid} sealCheckPass=${sealCheck.pass}`;
  });
}

async function run56_8(): Promise<void> {
  await test("56.8", "wrong guest image id -> verification invalid", async () => {
    const { requestId } = await completeAndWaitForProof("invariant-56.8");
    const proofResp = await (await fetch(`${COORD}/v1/requests/${requestId}/proof`)).json();
    assert(proofResp.receipt, `no proof receipt available (status=${proofResp.proof_status})`);

    const tampered = JSON.parse(JSON.stringify(proofResp.receipt));
    tampered.guestImageId = "0x" + "ee".repeat(32);

    const verifyRes = await (
      await fetch(`${TEE}/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ proof: tampered }),
      })
    ).json();

    assert(verifyRes.proof.valid === false, `expected invalid, got ${JSON.stringify(verifyRes.proof)}`);
    const imgCheck = verifyRes.proof.checks.find((c: any) => c.name.includes("guest image id"));
    assert(imgCheck?.pass === false, `expected guest image id check to fail, got ${JSON.stringify(imgCheck)}`);
    return `valid=${verifyRes.proof.valid} guestImageCheckPass=${imgCheck.pass}`;
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
  await test("55.15", "credential 429 -> cooldown set, fallback/capacity behavior", async () => {
    const creds = await getCredentials();
    const erin = creds.find((c) => c.label.toLowerCase().includes("erin"));
    assert(erin, "Erin's credential not found");
    const others = creds.filter(
      (c) => c.status === "ACTIVE" && c.id !== erin.id && c.capability.allowedModels.includes(MODEL_FAST)
    );

    for (const o of others) await patchCredential(o.id, { status: "DISABLED" });
    try {
      let outcome: "success" | "capacity_error";
      try {
        await client.completion({
          model: MODEL_FAST,
          messages: [{ role: "user", content: `route-erin-429 ${randomUUID()}` }],
        });
        outcome = "success";
      } catch {
        outcome = "capacity_error";
      }

      const credsAfter = await getCredentials();
      const erinAfter = credsAfter.find((c) => c.id === erin.id);
      assert(
        erinAfter?.cooldownUntil,
        `expected Erin's credential to have cooldownUntil set after a 429, got ${JSON.stringify(erinAfter?.cooldownUntil)}`
      );
      return `outcome=${outcome}, Erin cooldownUntil=${erinAfter.cooldownUntil}`;
    } finally {
      for (const o of others) await patchCredential(o.id, { status: "ACTIVE" });
      // Clears cooldown_until as a side effect of the status write.
      await patchCredential(erin.id, { status: "ACTIVE" });
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

    const result = await client.completion({
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
    const result = await client.completion({
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
  await test("36.20", "proof journal commitment equals compute receipt commitment", async () => {
    const result = await client.completion({
      model: MODEL_A,
      messages: [{ role: "user", content: `invariant-36.20 ${randomUUID()}` }],
    });
    await client.waitForProof(result.requestId, 20_000);
    const proofResp = await (await fetch(`${COORD}/v1/requests/${result.requestId}/proof`)).json();
    const receiptResp = await (await fetch(`${COORD}/v1/requests/${result.requestId}/receipt`)).json();

    const journalCommitment = proofResp.receipt?.journal?.requestCommitment;
    const receiptCommitment = receiptResp.signed_receipt?.receipt?.requestCommitment;
    assert(journalCommitment && receiptCommitment, "missing commitment in proof or receipt response");
    assert(journalCommitment === receiptCommitment, `mismatch: journal=${journalCommitment} receipt=${receiptCommitment}`);
    return `commitment=${journalCommitment}`;
  });
}

async function run36_21(): Promise<void> {
  await test("36.21", "proof journal contains no prompt-derived fields", async () => {
    const result = await client.completion({
      model: MODEL_A,
      messages: [{ role: "user", content: `invariant-36.21 ${randomUUID()}` }],
    });
    await client.waitForProof(result.requestId, 20_000);
    const proofResp = await (await fetch(`${COORD}/v1/requests/${result.requestId}/proof`)).json();
    const journal = proofResp.receipt?.journal;
    assert(journal, "no journal present in proof response");

    const keys = Object.keys(journal).sort();
    const expected = ["decision", "policyId", "proofNonce", "protocolVersion", "requestCommitment"];
    assert(
      JSON.stringify(keys) === JSON.stringify(expected),
      `unexpected journal keys: [${keys.join(", ")}], expected exactly [${expected.join(", ")}]`
    );
    return `journal keys = [${keys.join(", ")}]`;
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

  // ---- Summary ----
  console.log("\n\n=========================== SUMMARY ===========================");
  const idWidth = Math.max(...results.map((r) => r.id.length), 6);
  const nameWidth = Math.min(70, Math.max(...results.map((r) => r.name.length)));
  for (const r of results) {
    const status = r.pass ? "PASS" : "FAIL";
    console.log(`${status.padEnd(5)} [${r.id.padEnd(idWidth)}] ${r.name.padEnd(nameWidth)} ${r.pass ? "" : "— " + r.detail}`);
  }
  const passCount = results.filter((r) => r.pass).length;
  console.log(`\n${passCount}/${results.length} passed.`);

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

/**
 * The confidential service (§5 "AWS Nitro Enclave" box), running in simulation.
 *
 * Everything sensitive lives here and only here: request decryption, request
 * canonicalization, Safety Policy v1 execution, credential decryption, the
 * upstream TLS client, proof generation and receipt signing. The coordinator
 * relays ciphertext and stores non-sensitive metadata (Rule 3: no plaintext
 * prompt or credential ever crosses back out of this process).
 *
 * In simulation this listens on loopback HTTP. On Nitro the same handlers sit
 * behind a vsock listener; no handler logic changes.
 */
import Fastify from "fastify";
import {
  canonicalHash,
  canonicalJson,
  intentDigest,
  sha256Hex,
  toCanonicalRequest,
  type ComputeReceipt,
  type CredentialIntentV1,
  type SecurePayload,
  type SecureRequestEnvelope,
  type SignedComputeReceipt,
  type SignedProofBinding,
} from "@ctn/protocol";
import { hpkeSeal } from "@ctn/protocol";
import { loadPolicyPackage } from "@ctn/policy";
import { SimulatedTEE, SIMULATION_WARNING, vaultDecrypt, vaultEncrypt } from "./tee.js";
import { MODEL_CATALOG } from "./catalog.js";
import { deriveCapability, InvalidIntentError, parseIntent } from "./intent.js";
import { AuthorizedRequest, authorizeCandidate, type CandidateRecord } from "./authorize.js";
import { buildRegistry, type ProviderOutcome } from "./providers.js";
import { Prover } from "./prover.js";
import { verifyAttestation, verifyProof, verifyComputeReceipt } from "./verify.js";
import { enclaveSafe } from "./enclave-log.js";
import { randomUUID } from "node:crypto";

const PORT = Number(process.env.TEE_PORT ?? 4400);
// Loopback locally; the hosted build binds all interfaces behind the platform router.
const pkg = loadPolicyPackage();
const tee = await SimulatedTEE.boot({ policyIds: ["safety-v1"], policyId: pkg.policyId });
const prover = new Prover(tee, pkg);
const registry = buildRegistry();
const vaultKey = tee.unsealVaultKey();

console.log("");
console.log("  ┌──────────────────────────────────────────────────────────┐");
console.log(`  │  ${SIMULATION_WARNING}   │`);
console.log("  └──────────────────────────────────────────────────────────┘");
console.log(`  enclave build : ${tee.buildId}`);
console.log(`  enclave key id: ${tee.enclaveKeyId}`);
console.log(`  policy id     : ${pkg.policyId}`);
console.log(`  guest image id: ${pkg.guestImageId}`);
console.log("");

/**
 * §5.1 — the failure classifications the enclave decides BEFORE anything leaves
 * it. They are the only ones a second candidate may follow: no bytes were sent,
 * so nothing was spent and nothing was exposed. Every other classification —
 * including the ones where we never learned what the provider did — means the
 * prompt has been dispatched, and a dispatched prompt is the request.
 *
 * The contract this relies on is a property of the adapters: these two are
 * returned before `fetch` is called and carry `httpStatus: 0`, and no post-
 * dispatch path may reuse either name. A refused redirect is the case that
 * makes the distinction load-bearing — the allowlist blocks the second hop, but
 * the first hop already carried the prompt and the key — so it classifies as
 * `redirect_refused`. `providers.test.ts` asserts both halves of that contract.
 */
const PRE_DISPATCH_CLASSIFICATIONS: ReadonlySet<
  Extract<ProviderOutcome, { ok: false }>["classification"]
> = new Set(["egress_denied", "unpriced_model"]);

/**
 * §56 — replay protection.
 *
 * Bounded so a long-running demo cannot exhaust memory. Expired entries are
 * evicted first; if the window is still full of live nonces, the OLDEST are
 * dropped to make room. Dropping the oldest is the honest trade: a nonce older
 * than the whole window is replayable in principle, and pretending otherwise by
 * letting the map grow without limit would turn a bounded weakness into an
 * unbounded one. A production design persists this in monotonic enclave state.
 */
const seenNonces = new Map<string, number>();
const NONCE_TTL_MS = 30 * 60 * 1000;
const NONCE_MAX = 50_000;

function rememberNonce(nonce: string): boolean {
  if (seenNonces.has(nonce)) return false;
  const now = Date.now();

  if (seenNonces.size >= NONCE_MAX) {
    for (const [key, seenAt] of seenNonces) {
      if (now - seenAt > NONCE_TTL_MS) seenNonces.delete(key);
    }
    // Map iteration is insertion-ordered, so this drops the oldest first.
    while (seenNonces.size >= NONCE_MAX) {
      const oldest = seenNonces.keys().next();
      if (oldest.done) break;
      seenNonces.delete(oldest.value);
    }
  }

  seenNonces.set(nonce, now);
  return true;
}

const app = Fastify({ logger: false, bodyLimit: 4 * 1024 * 1024 });

/**
 * Errors are surfaced with their message, but ONLY the message — never a stack
 * and never the request body, either of which could carry prompt or credential
 * material out of the trust boundary (Rule 3).
 */
app.setErrorHandler((err: Error, request, reply) => {
  // The message is scrubbed on the way out, in both directions. An error thrown
  // deep in request handling can carry request content in its message, and this
  // is the one channel that leaves the enclave.
  const safe = enclaveSafe(err.message);
  console.error(`[tee-sim] error on ${request.method} ${request.url}: ${safe}`);
  reply.code(500).send({ error: { code: "CTN_INTERNAL", message: `enclave error: ${safe}` } });
});

app.get("/health", async () => ({ ok: true, service: "tee-sim", mode: tee.mode }));

app.get("/attestation", async (request) => {
  const nonce = (request.query as { nonce?: string }).nonce;
  const bundle = tee.attestation(nonce);
  return {
    bundle,
    verification: verifyAttestation(bundle),
    policy: {
      policyId: pkg.policyId,
      guestImageId: pkg.guestImageId,
      name: pkg.manifest.name,
      version: pkg.manifest.version,
      normalizer: pkg.rules.normalizer,
    },
    attestationDigest: tee.attestationDigest(),
  };
});

/**
 * §5.1 — the provider catalog, as the enclave actually holds it.
 *
 * Served from the live registry rather than from `MODEL_CATALOG` directly, so
 * the list a contributor picks from is exactly the list of adapters that can be
 * dispatched to: a catalog entry with no adapter would be an offer the enclave
 * cannot honour, and a model the adapter will not serve is a capability the
 * router would refuse later. The UI has no model constants of its own.
 */
app.get("/providers", async () => ({
  providers: [...registry.entries()]
    .map(([provider, adapter]) => ({ provider, models: [...adapter.models] }))
    .sort((a, b) => a.provider.localeCompare(b.provider)),
}));

/** Public build manifest (§63) — what a contributor inspects before trusting. */
app.get("/build-manifest", async () => ({
  enclaveMode: tee.mode,
  enclaveBuildId: tee.buildId,
  pcrs: tee.attestation().document.pcrs,
  policyId: pkg.policyId,
  zkGuestImageId: pkg.guestImageId,
  proofSystem: "simulated-reexec",
  policyRulesSha256: "0x" + canonicalHash(pkg.rules),
  warning: SIMULATION_WARNING,
}));

// ---------------------------------------------------------------------------
// §13 — credential ingestion
// ---------------------------------------------------------------------------

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

app.post("/credentials/ingest", async (request, reply) => {
  const body = request.body as IngestBody;
  if (body.enclaveKeyId !== tee.enclaveKeyId) {
    return reply.code(400).send({ error: { code: "CTN_INVALID_ENVELOPE", message: "unknown enclave key id" } });
  }

  let intent: CredentialIntentV1;
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
    // Keyed to the enclave's private signing key AND bound to this credential
    // id, so ingestion cannot be used as a guess-checking oracle. See tee.ts.
    keyFingerprint: "0x" + tee.fingerprint(intent.credentialId, intent.secret),
    policyId: pkg.policyId,
  };
});

// §50 — there is deliberately no re-signing endpoint. A capability is derived
// once, from one sealed intent, and never again: editing one means revoking the
// credential and contributing a new sealed intent.

// ---------------------------------------------------------------------------
// The secure path
// ---------------------------------------------------------------------------

interface ExecuteBody {
  envelope: SecureRequestEnvelope;
  /** Coordinator's candidate discovery result, in its preferred routing order. */
  candidates: CandidateRecord[];
}

export interface AttemptRecord {
  credentialId: string;
  contributorId: string;
  attemptNumber: number;
  status: "SUCCESS" | "FAILED";
  httpStatus: number;
  latencyMs: number;
  classification?: string;
  /**
   * §5.1 — dispatched, outcome never learned. These two travel to the
   * coordinator because the cap accounting lives there: dropping them here
   * would turn "the provider may have billed us" into "the request was free".
   */
  upstreamOutcomeUnknown?: true;
  assumedSpendMicroUsd?: number;
}

app.post("/execute", async (request, reply) => {
  const receivedAt = new Date().toISOString();
  const t0 = performance.now();
  const { envelope, candidates } = request.body as ExecuteBody;

  if (!envelope || envelope.version !== "ctn-1") {
    return reply.code(400).send({ error: { code: "CTN_INVALID_ENVELOPE", message: "bad envelope version" } });
  }
  if (envelope.enclaveKeyId !== tee.enclaveKeyId) {
    return reply.code(400).send({
      error: { code: "CTN_INVALID_ENVELOPE", message: "envelope encrypted to an unknown enclave key id" },
    });
  }

  // AAD binds the non-secret envelope header to the ciphertext: flipping the
  // requested policy in transit breaks decryption instead of silently applying.
  const aad = new TextEncoder().encode(canonicalJson(envelope.aad));

  let payload: SecurePayload;
  let decryptMs: number;
  try {
    const d0 = performance.now();
    const opened = await tee.openIngress(
      { enc: envelope.enc, ciphertext: envelope.ciphertext },
      aad
    );
    decryptMs = Math.max(1, Math.round(performance.now() - d0));
    payload = JSON.parse(new TextDecoder().decode(opened)) as SecurePayload;
  } catch {
    return reply
      .code(400)
      .send({ error: { code: "CTN_INVALID_ENVELOPE", message: "envelope failed authenticated decryption" } });
  }

  if (!rememberNonce(payload.requestNonce)) {
    return reply
      .code(409)
      .send({ error: { code: "CTN_INVALID_ENVELOPE", message: "request nonce already used (replay rejected)" } });
  }

  let canonical;
  try {
    canonical = toCanonicalRequest(payload.request);
  } catch (err) {
    return reply.code(400).send({
      error: {
        code: "CTN_INVALID_ENVELOPE",
        message: err instanceof Error ? err.message : "request failed canonicalization",
      },
    });
  }

  // The routing header must agree with the sealed request. If a coordinator
  // rewrote the header to route to different capacity, this fails closed.
  if (envelope.aad.model !== canonical.model) {
    return reply.code(400).send({
      error: {
        code: "CTN_INVALID_ENVELOPE",
        message: "routing header model does not match the sealed request model",
      },
    });
  }

  // §25 — the single gate. Nothing downstream can run without an AuthorizedRequest.
  const gate = AuthorizedRequest.evaluate(canonical, payload.requestNonce, pkg);

  if (gate.decision === "DENY") {
    // Rule 5 / §33 — no credential decryption, no provider call, no reason leaked.
    return {
      requestId: envelope.requestId,
      status: "DENIED" as const,
      commitment: gate.commitment,
      policyId: pkg.policyId,
      policyDecision: "DENY" as const,
      policyMs: gate.policyMs,
      model: canonical.model,
      encryptedResponse: null,
      receipt: null,
      attempts: [] as AttemptRecord[],
      selected: null,
      authorizationFailures: [],
      proofStarted: false,
      timings: { enclaveDecryptMs: decryptMs, policyMs: gate.policyMs, totalMs: Math.round(performance.now() - t0) },
      error: {
        code: "CTN_POLICY_DENIED",
        message: "Request was not eligible under Safety Policy v1.",
      },
      // Local development only: never returned when CTN_ENV is demo/production.
      debug:
        process.env.CTN_ENV === "local"
          ? {
              categories: gate.evaluation.categories.filter((c) => c.matchedTargets.length > 0),
              hardBlock: gate.evaluation.hardBlock,
              intentPresent: gate.evaluation.intentPresent,
              modifiersApplied: gate.evaluation.modifiersApplied,
            }
          : undefined,
    };
  }

  const authorized = gate.authorized;

  // §25 branch A — proving starts now and is NOT awaited (§26).
  prover.start(envelope.requestId, authorized);

  // §25 branch B — routing, credential decryption, upstream call.
  const attempts: AttemptRecord[] = [];
  const authorizationFailures = [];
  let success: { outcome: Extract<ProviderOutcome, { ok: true }>; credentialId: string; contributorId: string; provider: string; attempt: number } | null = null;
  let lastFailure: Extract<ProviderOutcome, { ok: false }> | null = null;
  let attemptNumber = 0;

  for (const candidate of candidates) {
    // §16 — final authorization inside the enclave, per candidate.
    const authz = authorizeCandidate(candidate, authorized, tee.signingPublicKey, (blob) =>
      vaultDecrypt(vaultKey, blob)
    );
    if (!authz.ok) {
      authorizationFailures.push(authz.failure);
      continue;
    }

    const adapter = registry.get(candidate.provider);
    if (!adapter || !adapter.supportsModel(authorized.request.model)) {
      authorizationFailures.push({ credentialId: candidate.credentialId, reason: "model_not_allowed" as const });
      continue;
    }

    attemptNumber += 1;
    const outcome = await adapter.complete(authorized, authz.credential);

    // Rule 6 — every provider call produces a ProviderAttempt, success or not.
    attempts.push({
      credentialId: candidate.credentialId,
      contributorId: candidate.contributorId,
      attemptNumber,
      status: outcome.ok ? "SUCCESS" : "FAILED",
      httpStatus: outcome.ok ? outcome.response.httpStatus : outcome.httpStatus,
      latencyMs: outcome.ok ? outcome.response.latencyMs : outcome.latencyMs,
      classification: outcome.ok ? undefined : outcome.classification,
      upstreamOutcomeUnknown: outcome.ok ? undefined : outcome.upstreamOutcomeUnknown,
      assumedSpendMicroUsd: outcome.ok ? undefined : outcome.assumedSpendMicroUsd,
    });

    if (outcome.ok) {
      success = {
        outcome,
        credentialId: candidate.credentialId,
        contributorId: candidate.contributorId,
        provider: candidate.provider,
        attempt: attemptNumber,
      };
      break;
    }
    lastFailure = outcome;
    // §5.1 single dispatch — the prompt has now been sent upstream once.
    // Sending it again (to another credential, another provider) would double
    // both the spend risk and the exposure surface, and an outcome we could not
    // classify is not evidence that nothing happened. Only provably
    // pre-dispatch failures may try the next candidate; the coordinator still
    // applies disable/cooldown from the classification we report, so the
    // fallback story survives at request granularity (§18).
    if (!PRE_DISPATCH_CLASSIFICATIONS.has(outcome.classification)) break;
  }

  if (!success) {
    const code =
      lastFailure?.classification === "auth_failed"
        ? "CTN_PROVIDER_AUTH_FAILED"
        : lastFailure?.classification === "rate_limited"
          ? "CTN_PROVIDER_RATE_LIMITED"
          : lastFailure
            ? "CTN_PROVIDER_ERROR"
            : "CTN_NO_CAPACITY";
    return {
      requestId: envelope.requestId,
      status: "FAILED" as const,
      commitment: authorized.requestCommitment,
      policyId: pkg.policyId,
      policyDecision: "ALLOW" as const,
      policyMs: gate.policyMs,
      model: canonical.model,
      encryptedResponse: null,
      receipt: null,
      attempts,
      selected: null,
      authorizationFailures,
      proofStarted: true,
      timings: { enclaveDecryptMs: decryptMs, policyMs: gate.policyMs, totalMs: Math.round(performance.now() - t0) },
      error: {
        code,
        message:
          code === "CTN_NO_CAPACITY"
            ? "No eligible contributed capacity is available for this model and policy."
            : "All eligible credentials failed for this request.",
      },
    };
  }

  const { outcome } = success;
  const totalMs = Math.round(performance.now() - t0);

  // §30 — the compute receipt. Signed here, so it binds the attested enclave to
  // the commitment, the policy proof, the route and the usage.
  const proofRecord = prover.get(envelope.requestId);
  const zkReceiptDigest =
    proofRecord && (proofRecord.state.status === "GENERATED" || proofRecord.state.status === "VERIFIED")
      ? proofRecord.state.digest
      : "pending";

  const receipt: ComputeReceipt = {
    version: "ctn-receipt-1",
    requestId: envelope.requestId,
    requestCommitment: authorized.requestCommitment,
    tee: { mode: tee.mode, buildId: tee.buildId, attestationDigest: tee.attestationDigest() },
    policy: { policyId: pkg.policyId, decision: "ALLOW", zkReceiptDigest },
    route: {
      provider: success.provider,
      model: authorized.request.model,
      credentialId: success.credentialId,
      contributorId: success.contributorId,
      attempt: success.attempt,
    },
    usage: {
      inputTokens: outcome.response.inputTokens,
      outputTokens: outcome.response.outputTokens,
      estimatedCostMicroUsd: outcome.response.estimatedCostMicroUsd,
      pricingTableDigest: outcome.response.pricingTableDigest,
    },
    timing: {
      receivedAt,
      policyMs: gate.policyMs,
      providerTotalMs: outcome.response.latencyMs,
    },
    upstreamRequestHash: outcome.response.upstreamRequestHash,
    upstreamResponseHash: outcome.response.upstreamResponseHash,
  };
  const signed: SignedComputeReceipt = { receipt, enclaveSignature: tee.signReceipt(receipt) };

  // Response is sealed to the client's ephemeral key: the coordinator relays it
  // without ever being able to read it (§31).
  const sealed = await hpkeSeal(
    payload.responsePublicKey,
    new TextEncoder().encode(
      JSON.stringify({
        requestId: envelope.requestId,
        model: authorized.request.model,
        content: outcome.response.content,
        usage: {
          inputTokens: outcome.response.inputTokens,
          outputTokens: outcome.response.outputTokens,
        },
      })
    )
  );

  return {
    requestId: envelope.requestId,
    status: "COMPLETE" as const,
    commitment: authorized.requestCommitment,
    policyId: pkg.policyId,
    policyDecision: "ALLOW" as const,
    policyMs: gate.policyMs,
    model: authorized.request.model,
    encryptedResponse: sealed,
    receipt: signed,
    attempts,
    selected: {
      credentialId: success.credentialId,
      contributorId: success.contributorId,
      provider: success.provider,
      model: authorized.request.model,
      attempt: success.attempt,
    },
    authorizationFailures,
    proofStarted: true,
    usage: receipt.usage,
    timings: {
      enclaveDecryptMs: decryptMs,
      policyMs: gate.policyMs,
      providerTotalMs: outcome.response.latencyMs,
      totalMs,
    },
  };
});

/** §32 — proof state is polled because proving may finish after inference. */
app.get("/proofs/:requestId", async (request, reply) => {
  const { requestId } = request.params as { requestId: string };
  const record = prover.get(requestId);
  if (!record) return reply.code(404).send({ status: "NOT_REQUIRED" });

  const base = { requestId, simulatedCostMs: record.simulatedCostMs };
  if (record.state.status === "PROVING") {
    return { ...base, status: "PROVING" };
  }
  if (record.state.status === "FAILED") {
    return { ...base, status: "FAILED", error: record.state.error, proofMs: record.state.proofMs };
  }
  const { proof, proofMs, digest } = record.state;
  const verification = verifyProof(proof, {
    expectedGuestImageId: pkg.guestImageId,
    expectedPolicyId: pkg.policyId,
    expectedCommitment: proof.journal.requestCommitment,
    proverPublicKey: tee.proverPublicKey,
  });
  return {
    ...base,
    status: record.state.status,
    proof,
    proofMs,
    digest,
    verification,
    proverPublicKey: tee.proverPublicKey,
    enclaveSigningPublicKey: tee.signingPublicKey,
    // Rule 8 — present once proving settles; binds this proof to the receipt.
    binding: record.state.status === "VERIFIED" ? record.state.binding : undefined,
  };
});

/**
 * §34 — the policy test harness, on the secure path. Takes an encrypted
 * envelope, returns the decision and commitment and nothing prompt-derived.
 */
app.post("/policy-test", async (request, reply) => {
  const { envelope } = request.body as { envelope: SecureRequestEnvelope };
  if (!envelope || envelope.enclaveKeyId !== tee.enclaveKeyId) {
    return reply.code(400).send({ error: { code: "CTN_INVALID_ENVELOPE", message: "bad envelope" } });
  }
  const aad = new TextEncoder().encode(canonicalJson(envelope.aad));
  let payload: SecurePayload;
  try {
    const opened = await tee.openIngress({ enc: envelope.enc, ciphertext: envelope.ciphertext }, aad);
    payload = JSON.parse(new TextDecoder().decode(opened)) as SecurePayload;
  } catch {
    return reply
      .code(400)
      .send({ error: { code: "CTN_INVALID_ENVELOPE", message: "envelope failed authenticated decryption" } });
  }

  const canonical = toCanonicalRequest(payload.request);
  const testId = `ptest_${randomUUID().replace(/-/g, "").slice(0, 20)}`;
  const gate = AuthorizedRequest.evaluate(canonical, payload.requestNonce, pkg);

  if (gate.decision === "ALLOW") {
    prover.start(testId, gate.authorized);
  }
  return {
    testId,
    decision: gate.decision,
    commitment: gate.commitment,
    policyId: pkg.policyId,
    policyMs: gate.policyMs,
    promptVisiblePublicly: false,
    proofStarted: gate.decision === "ALLOW",
  };
});

/** Verification endpoint used by the receipt viewer and the CLI. */
app.post("/verify", async (request) => {
  const body = request.body as {
    proof?: Parameters<typeof verifyProof>[0];
    receipt?: SignedComputeReceipt;
    binding?: SignedProofBinding;
  };
  const result: Record<string, unknown> = {};
  if (body.proof) {
    result.proof = verifyProof(body.proof, {
      expectedGuestImageId: pkg.guestImageId,
      expectedPolicyId: pkg.policyId,
      expectedCommitment: body.receipt?.receipt.requestCommitment ?? body.proof.journal.requestCommitment,
      proverPublicKey: tee.proverPublicKey,
    });
  }
  if (body.receipt) {
    result.receipt = verifyComputeReceipt(body.receipt, {
      enclaveSigningPublicKey: tee.signingPublicKey,
      proof: body.proof,
      binding: body.binding,
    });
  }
  result.keys = {
    enclaveSigningPublicKey: tee.signingPublicKey,
    proverPublicKey: tee.proverPublicKey,
    guestImageId: pkg.guestImageId,
    policyId: pkg.policyId,
  };
  return result;
});

app
  .listen({ port: PORT, host: "127.0.0.1" })
  .then(() => console.log(`[tee-sim] listening on http://127.0.0.1:${PORT} (${tee.mode})`))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });

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
  artifactToWire,
  canonicalBytes,
  canonicalHash,
  canonicalJson,
  intentDigest,
  randomHex,
  requestCommitment,
  sha256Hex,
  toCanonicalRequest,
  type ComputeReceipt,
  type CredentialIntentV1,
  type PolicyDecisionReceiptV1,
  type SecurePayload,
  type SecureRequestEnvelope,
  type SignedComputeReceipt,
  type SignedPolicyDecisionReceiptV1,
  type SignedProofBindingV2,
} from "@ctn/protocol";
import { hpkeSeal } from "@ctn/protocol";
import { loadPolicyPackage } from "@ctn/policy";
import { SimulatedTEE, SIMULATION_WARNING, vaultDecrypt, vaultEncrypt } from "./tee.js";
import { MODEL_CATALOG } from "./catalog.js";
import { deriveCapability, InvalidIntentError, parseIntent } from "./intent.js";
import {
  AuthorizedRequest,
  authorizeCandidate,
  CommitmentMismatchError,
  type CandidateRecord,
} from "./authorize.js";
import { buildRegistry, type ProviderOutcome } from "./providers.js";
import { Prover, type ProofWitness } from "./prover.js";
import { verifyAttestation, verifyComputeReceipt } from "./verify.js";
import { runReferenceVerify, type VerifierPaths } from "./proof-verify.js";
import { enclaveSafe } from "./enclave-log.js";
import { ProverClient, ProverUnavailableError, type ProverHealth } from "./prover-client.js";
import { PendingGates } from "./pending-gates.js";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PORT = Number(process.env.TEE_PORT ?? 4400);
// Loopback locally; the hosted build binds all interfaces behind the platform router.
const pkg = loadPolicyPackage();
const tee = await SimulatedTEE.boot({ policyIds: ["safety-v1"], policyId: pkg.policyId });
const registry = buildRegistry();
const vaultKey = tee.unsealVaultKey();

// ---------------------------------------------------------------------------
// Phase 2b §3 — the guest executor (`:4500`) is the AUTHORITATIVE gate for every
// request. The TypeScript policy engine no longer gates anything on the request
// path (it is retained only for the Policy-Lab preview via `/policy-test`).
// ---------------------------------------------------------------------------
const PROVER_URL = process.env.CTN_PROVER_URL ?? "http://127.0.0.1:4500";
const proverClient = new ProverClient(PROVER_URL);

// Paths to the reference offline verifier and the pinned manifest. The enclave
// spawns `prover/verify` (no FFI) against `prover/release.json` before any proof
// is allowed to reach VERIFIED (§4). Root is three levels up from this file.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const VERIFIER_PATHS: VerifierPaths = {
  binPath: process.env.CTN_PROVER_VERIFY_BIN ?? join(REPO_ROOT, "prover", "verify", "target", "release", "prover-verify"),
  releasePath: process.env.CTN_PROVER_RELEASE ?? join(REPO_ROOT, "prover", "release.json"),
  policyDir: process.env.CTN_PROVER_POLICY_DIR ?? join(REPO_ROOT, "policy", "v1"),
};
const prover = new Prover(tee, pkg, { proverClient, verifierPaths: VERIFIER_PATHS });

/**
 * The guest's authoritative identity, learned from `/health` — `POLICY_ID_V2`
 * and the guest image the gate runs. Distinct from the TypeScript package's
 * `pkg.policyId`/`pkg.guestImageId`, which are the Policy-Lab PREVIEW identity.
 * Cached lazily: if the daemon is down at boot, the gate itself is unavailable
 * (`PROVER_UNAVAILABLE`) so no decision receipt is ever built anyway.
 */
let guestHealth: ProverHealth | null = null;
async function getGuestHealth(): Promise<ProverHealth> {
  if (guestHealth) return guestHealth;
  guestHealth = await proverClient.health(); // throws ProverUnavailableError if down
  return guestHealth;
}
// Best-effort warm-up; never fatal — a down daemon must still let this process boot.
void getGuestHealth().then(
  (h) => console.log(`  guest gate    : ${PROVER_URL} policyId=${h.policyId.slice(0, 12)}… image=${h.imageIdHex.slice(0, 12)}…`),
  () => console.log(`  guest gate    : ${PROVER_URL} (UNREACHABLE at boot — requests will fail closed with PROVER_UNAVAILABLE)`)
);

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

/**
 * Public build manifest (§63) — what a contributor inspects before trusting.
 *
 * `proofSystem` is `risc0`: since Phase 2b the request path produces real RISC
 * Zero STARK proofs (generated by the guest prover, verified server-side by
 * `prover/verify`), so `simulated-reexec` would be a lie here. The `policyId`
 * and `zkGuestImageId` fields below are the TypeScript package's PREVIEW
 * identity; the authoritative request-path identity is the guest image's
 * (`POLICY_ID_V2`, imageId `ddb7dc…`), surfaced on the trust page's proof claim.
 */
app.get("/build-manifest", async () => ({
  enclaveMode: tee.mode,
  enclaveBuildId: tee.buildId,
  pcrs: tee.attestation().document.pcrs,
  policyId: pkg.policyId,
  zkGuestImageId: pkg.guestImageId,
  proofSystem: "risc0",
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

  // Phase 2b §5 — the request-path policy identity is the GUEST's POLICY_ID_V2.
  // Capabilities must be minted under it so candidate discovery (keyed on the
  // guest policyId) and the enclave's per-candidate authorization both match.
  // Requires the guest gate to be reachable to mint capacity — you cannot onboard
  // capacity for a policy identity the gate cannot confirm.
  let guestPolicyId: string;
  try {
    guestPolicyId = (await getGuestHealth()).policyId;
  } catch {
    return reply.code(503).send({
      error: { code: "CTN_ENCLAVE_UNAVAILABLE", message: "the policy gate is unavailable; cannot mint capacity" },
    });
  }

  // §5.1 — derived from the DECRYPTED INTENT alone. Anything else in the HTTP
  // body is ignored by construction.
  const capability = deriveCapability({
    intent,
    blobDigest: "0x" + sha256Hex(encryptedBlob),
    resolvePolicyId: (p) => (p === "safety-v1" ? guestPolicyId : p),
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
    policyId: guestPolicyId,
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
  /**
   * The commitment returned by the prior `/gate`. Required to consume a parked
   * gate: it binds this dispatch to the request the gate actually evaluated, so
   * naming a victim's pending `requestId` alone cannot redirect their ALLOW.
   * Absent for direct callers (no prior `/gate`), who are gated inline instead.
   */
  requestCommitment?: string;
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

/** A gate refusal that maps to a fixed HTTP status + code. Never carries bytes. */
class GateError extends Error {
  constructor(
    readonly httpStatus: number,
    readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "GateError";
  }
}

/**
 * The outcome of gating a request against the GUEST executor. `authorized` is
 * present only for ALLOW (§69 type-state: it cannot exist for a denied request),
 * and `decisionReceipt` is the signed PolicyDecisionReceiptV1 for the verdict.
 */
interface GateOutcome {
  requestId: string;
  canonical: ReturnType<typeof toCanonicalRequest>;
  payload: SecurePayload;
  commitment: string;
  decision: "ALLOW" | "DENY";
  authorized: AuthorizedRequest | null;
  decisionReceipt: SignedPolicyDecisionReceiptV1;
  gateWallMs: number;
  decryptMs: number;
}

/**
 * Phase 2b §3 — THE gate. Decrypts the envelope, canonicalizes, then calls the
 * guest executor (`:4500`), which is authoritative for the verdict AND computes
 * the request commitment itself. The enclave recomputes that commitment and
 * asserts equality (determinism guard, fail closed), then signs a
 * PolicyDecisionReceiptV1 for the verdict — ALLOW or DENY. Throws:
 *   • ProverUnavailableError  → PROVER_UNAVAILABLE (system failure, no decision)
 *   • CommitmentMismatchError → CTN_COMMITMENT_MISMATCH (fail closed)
 *   • GateError               → the envelope/replay codes the legacy path used
 * The TypeScript policy engine is NOT consulted here; it gates nothing.
 */
async function gateRequest(envelope: SecureRequestEnvelope): Promise<GateOutcome> {
  if (!envelope || envelope.version !== "ctn-1") {
    throw new GateError(400, "CTN_INVALID_ENVELOPE", "bad envelope version");
  }
  if (envelope.enclaveKeyId !== tee.enclaveKeyId) {
    throw new GateError(400, "CTN_INVALID_ENVELOPE", "envelope encrypted to an unknown enclave key id");
  }

  // AAD binds the non-secret envelope header to the ciphertext: flipping the
  // requested policy in transit breaks decryption instead of silently applying.
  const aad = new TextEncoder().encode(canonicalJson(envelope.aad));
  let payload: SecurePayload;
  let decryptMs: number;
  try {
    const d0 = performance.now();
    const opened = await tee.openIngress({ enc: envelope.enc, ciphertext: envelope.ciphertext }, aad);
    decryptMs = Math.max(1, Math.round(performance.now() - d0));
    payload = JSON.parse(new TextDecoder().decode(opened)) as SecurePayload;
  } catch {
    throw new GateError(400, "CTN_INVALID_ENVELOPE", "envelope failed authenticated decryption");
  }

  if (!rememberNonce(payload.requestNonce)) {
    throw new GateError(409, "CTN_INVALID_ENVELOPE", "request nonce already used (replay rejected)");
  }

  let canonical;
  try {
    canonical = toCanonicalRequest(payload.request);
  } catch (err) {
    throw new GateError(400, "CTN_INVALID_ENVELOPE", err instanceof Error ? err.message : "request failed canonicalization");
  }

  // The routing header must agree with the sealed request. If a coordinator
  // rewrote the header to route to different capacity, this fails closed.
  if (envelope.aad.model !== canonical.model) {
    throw new GateError(400, "CTN_INVALID_ENVELOPE", "routing header model does not match the sealed request model");
  }

  // The authoritative gate. The wire shape is the JCS canonical request; the
  // guest computes the commitment from these exact bytes and the nonce.
  const canonicalRequestBytes = canonicalJson(canonical);
  const proofNonce = randomHex(32);
  const g0 = performance.now();
  let execResult;
  try {
    execResult = await proverClient.execute({
      canonicalRequestBytes,
      requestNonceHex: payload.requestNonce,
      proofNonce,
      emitScores: false,
    });
  } catch (err) {
    if (err instanceof ProverUnavailableError) throw err; // → PROVER_UNAVAILABLE
    // A responding daemon that faulted on well-formed bytes is our bug, not a
    // verdict: fail closed rather than fabricate a decision.
    throw new GateError(500, "CTN_INTERNAL", "the guest executor rejected the gate request");
  }
  const gateWallMs = Math.max(1, Math.round(performance.now() - g0));

  // Determinism guard — assert the guest evaluated the same bytes we will act on.
  const gate = AuthorizedRequest.fromGuestJournal(
    canonical,
    payload.requestNonce,
    execResult.journal,
    gateWallMs
  ); // throws CommitmentMismatchError on mismatch

  // A successful execute means the daemon is up, so /health is reachable for the
  // image id. policyId comes from the journal the guest actually committed.
  const health = await getGuestHealth();
  const receipt: PolicyDecisionReceiptV1 = {
    requestId: envelope.requestId,
    requestCommitment: gate.commitment,
    policyId: execResult.journal.policyId,
    decision: gate.decision,
    imageId: health.imageIdHex,
    timing: { gateWallMs },
  };
  const decisionReceipt: SignedPolicyDecisionReceiptV1 = {
    receipt,
    enclaveSignature: tee.signReceipt(receipt),
  };

  return {
    requestId: envelope.requestId,
    canonical,
    payload,
    commitment: gate.commitment,
    decision: gate.decision,
    authorized: gate.decision === "ALLOW" ? gate.authorized : null,
    decisionReceipt,
    gateWallMs,
    decryptMs,
  };
}

/** The private witness a proof is generated over — ALLOW and DENY alike. */
function witnessFor(outcome: GateOutcome): ProofWitness {
  return {
    canonicalRequest: canonicalJson(outcome.canonical),
    requestNonce: outcome.payload.requestNonce,
    requestCommitment: outcome.commitment,
    decision: outcome.decision,
    // The signed decision this proof binds to (ProofBindingV2.decisionReceiptDigest).
    decisionReceipt: outcome.decisionReceipt.receipt,
  };
}

/**
 * Phase 2b §3 — the gate runs BEFORE candidate discovery, so the coordinator
 * gates (`/gate`), then discovers on the guest policyId, then dispatches
 * (`/execute`). An ALLOW gate outcome — which holds the DECRYPTED plaintext
 * witness the dispatch needs — is parked here between the two calls.
 *
 * The plaintext is bounded in TIME, not merely in count: an entry is dropped the
 * instant `/execute` consumes it, OR reaped once its age exceeds `PENDING_TTL_MS`
 * — enforced on every insert (reap-on-insert) AND by a low-frequency background
 * sweep, so an abandoned gate (e.g. no-capacity, where the coordinator returns
 * CTN_NO_CAPACITY and never dispatches) does not sit in enclave RAM once traffic
 * stops. `PENDING_MAX` is the hard count bound; the oldest are dropped if the map
 * is still full after reaping. Consumption is bound to the request commitment
 * (see PendingGates): naming a parked `requestId` is not enough to consume it.
 *
 * TTL = 60s. The real `/gate`→`/execute` gap is milliseconds (a DB discovery
 * query plus two loopback calls), so 60s is already orders of magnitude above
 * any legitimate latency while shrinking the plaintext residency window 5× from
 * the earlier 5-minute value. A no-capacity ALLOW is dropped after this window;
 * that visible-absence is the correct behavior — those gates get no `/execute`,
 * so their reaping IS the TTL.
 */
const PENDING_TTL_MS = 60 * 1000;
const PENDING_MAX = 10_000;
const pendingGates = new PendingGates<GateOutcome>({ ttlMs: PENDING_TTL_MS, max: PENDING_MAX });
// A single unref'd background sweep so an idle enclave still reaps parked
// plaintext on time even with no new inserts. Never keeps the process alive.
pendingGates.startSweeper();

/** Map a gate throw onto the HTTP reply. Shared by `/gate` and `/execute`. */
function replyGateError(reply: import("fastify").FastifyReply, err: unknown): boolean {
  if (err instanceof ProverUnavailableError) {
    reply.code(503).send({ error: { code: "PROVER_UNAVAILABLE", message: "the guest executor (policy gate) is unavailable" } });
    return true;
  }
  if (err instanceof CommitmentMismatchError) {
    reply.code(500).send({ error: { code: "CTN_COMMITMENT_MISMATCH", message: err.message } });
    return true;
  }
  if (err instanceof GateError) {
    reply.code(err.httpStatus).send({ error: { code: err.code, message: err.message } });
    return true;
  }
  return false;
}

/** The DENY result shape — no credential decrypted, no provider called (Rule 5). */
function deniedBody(outcome: GateOutcome) {
  return {
    requestId: outcome.requestId,
    status: "DENIED" as const,
    commitment: outcome.commitment,
    policyId: outcome.decisionReceipt.receipt.policyId,
    policyDecision: "DENY" as const,
    policyMs: outcome.gateWallMs,
    model: outcome.canonical.model,
    encryptedResponse: null,
    receipt: null,
    attempts: [] as AttemptRecord[],
    selected: null,
    authorizationFailures: [],
    proofStarted: true,
    decisionReceipt: outcome.decisionReceipt,
    timings: {
      enclaveDecryptMs: outcome.decryptMs,
      policyMs: outcome.gateWallMs,
      gateWallMs: outcome.gateWallMs,
      totalMs: outcome.gateWallMs,
    },
    error: { code: "CTN_POLICY_DENIED", message: "Request was not eligible under Safety Policy v1." },
  };
}

/**
 * §25 branch B — routing, credential decryption, upstream call. Runs only after
 * an ALLOW gate; `outcome.authorized` is the §69 proof that policy allowed.
 */
async function runDispatch(outcome: GateOutcome, candidates: CandidateRecord[]) {
  const receivedAt = new Date().toISOString();
  const t0 = performance.now();
  const authorized = outcome.authorized!;
  const payload = outcome.payload;
  const decryptMs = outcome.decryptMs;
  const gateWallMs = outcome.gateWallMs;

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
    const providerOutcome = await adapter.complete(authorized, authz.credential);

    // Rule 6 — every provider call produces a ProviderAttempt, success or not.
    attempts.push({
      credentialId: candidate.credentialId,
      contributorId: candidate.contributorId,
      attemptNumber,
      status: providerOutcome.ok ? "SUCCESS" : "FAILED",
      httpStatus: providerOutcome.ok ? providerOutcome.response.httpStatus : providerOutcome.httpStatus,
      latencyMs: providerOutcome.ok ? providerOutcome.response.latencyMs : providerOutcome.latencyMs,
      classification: providerOutcome.ok ? undefined : providerOutcome.classification,
      upstreamOutcomeUnknown: providerOutcome.ok ? undefined : providerOutcome.upstreamOutcomeUnknown,
      assumedSpendMicroUsd: providerOutcome.ok ? undefined : providerOutcome.assumedSpendMicroUsd,
    });

    if (providerOutcome.ok) {
      success = {
        outcome: providerOutcome,
        credentialId: candidate.credentialId,
        contributorId: candidate.contributorId,
        provider: candidate.provider,
        attempt: attemptNumber,
      };
      break;
    }
    lastFailure = providerOutcome;
    // §5.1 single dispatch — the prompt has now been sent upstream once. Only
    // provably pre-dispatch failures may try the next candidate.
    if (!PRE_DISPATCH_CLASSIFICATIONS.has(providerOutcome.classification)) break;
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
      requestId: outcome.requestId,
      status: "FAILED" as const,
      commitment: authorized.requestCommitment,
      policyId: outcome.decisionReceipt.receipt.policyId,
      policyDecision: "ALLOW" as const,
      policyMs: gateWallMs,
      model: outcome.canonical.model,
      encryptedResponse: null,
      receipt: null,
      attempts,
      selected: null,
      authorizationFailures,
      proofStarted: true,
      decisionReceipt: outcome.decisionReceipt,
      timings: { enclaveDecryptMs: decryptMs, policyMs: gateWallMs, gateWallMs, totalMs: Math.round(performance.now() - t0) },
      error: {
        code,
        message:
          code === "CTN_NO_CAPACITY"
            ? "No eligible contributed capacity is available for this model and policy."
            : "All eligible credentials failed for this request.",
      },
    };
  }

  const providerSuccess = success.outcome;
  const totalMs = Math.round(performance.now() - t0);

  // §30 — the compute receipt. Phase 2b Task 3: `policy.policyId` is unified onto
  // the GUEST `POLICY_ID_V2` (from the decision receipt), so a single policy
  // identity now spans the decision receipt, the real proof journal, and this
  // receipt. `zkReceiptDigest` normally reads "pending" — proving runs ~2 min in
  // parallel and the receipt is signed as soon as inference finishes; the finished
  // artifactDigest is bound by the separate signed ProofBindingV2.
  const guestPolicyId = outcome.decisionReceipt.receipt.policyId;
  const proofRecord = prover.get(outcome.requestId);
  const zkReceiptDigest =
    proofRecord && (proofRecord.state.status === "GENERATED" || proofRecord.state.status === "VERIFIED")
      ? proofRecord.state.artifactDigest
      : "pending";

  const receipt: ComputeReceipt = {
    version: "ctn-receipt-1",
    requestId: outcome.requestId,
    requestCommitment: authorized.requestCommitment,
    tee: { mode: tee.mode, buildId: tee.buildId, attestationDigest: tee.attestationDigest() },
    policy: { policyId: guestPolicyId, decision: "ALLOW", zkReceiptDigest },
    route: {
      provider: success.provider,
      model: authorized.request.model,
      credentialId: success.credentialId,
      contributorId: success.contributorId,
      attempt: success.attempt,
    },
    usage: {
      inputTokens: providerSuccess.response.inputTokens,
      outputTokens: providerSuccess.response.outputTokens,
      estimatedCostMicroUsd: providerSuccess.response.estimatedCostMicroUsd,
      pricingTableDigest: providerSuccess.response.pricingTableDigest,
    },
    timing: {
      receivedAt,
      policyMs: gateWallMs,
      providerTotalMs: providerSuccess.response.latencyMs,
    },
    upstreamRequestHash: providerSuccess.response.upstreamRequestHash,
    upstreamResponseHash: providerSuccess.response.upstreamResponseHash,
  };
  const signed: SignedComputeReceipt = { receipt, enclaveSignature: tee.signReceipt(receipt) };

  // Response is sealed to the client's ephemeral key: the coordinator relays it
  // without ever being able to read it (§31).
  const sealed = await hpkeSeal(
    payload.responsePublicKey,
    new TextEncoder().encode(
      JSON.stringify({
        requestId: outcome.requestId,
        model: authorized.request.model,
        content: providerSuccess.response.content,
        usage: {
          inputTokens: providerSuccess.response.inputTokens,
          outputTokens: providerSuccess.response.outputTokens,
        },
      })
    )
  );

  return {
    requestId: outcome.requestId,
    status: "COMPLETE" as const,
    commitment: authorized.requestCommitment,
    policyId: outcome.decisionReceipt.receipt.policyId,
    policyDecision: "ALLOW" as const,
    policyMs: gateWallMs,
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
    decisionReceipt: outcome.decisionReceipt,
    usage: receipt.usage,
    timings: {
      enclaveDecryptMs: decryptMs,
      policyMs: gateWallMs,
      gateWallMs,
      providerTotalMs: providerSuccess.response.latencyMs,
      totalMs,
    },
  };
}

/**
 * Phase 2b §3 — the gate, called by the coordinator BEFORE candidate discovery.
 * Signs a PolicyDecisionReceiptV1 for EVERY request and enqueues a proof for the
 * verdict (ALLOW AND DENY). ALLOW outcomes are parked for the follow-up
 * `/execute` (dispatch). A `PROVER_UNAVAILABLE` here is a system failure with no
 * decision and no receipt at all.
 */
app.post("/gate", async (request, reply) => {
  const { envelope } = request.body as { envelope: SecureRequestEnvelope };
  let outcome: GateOutcome;
  try {
    outcome = await gateRequest(envelope);
  } catch (err) {
    if (replyGateError(reply, err)) return;
    throw err;
  }
  // Enqueue the proof of the verdict immediately — ALLOW AND DENY.
  prover.start(outcome.requestId, witnessFor(outcome));
  // Park the ALLOW plaintext for the follow-up `/execute`, bound to the
  // commitment the coordinator must reproduce to consume it.
  if (outcome.decision === "ALLOW") pendingGates.remember(outcome.requestId, outcome.commitment, outcome);

  return {
    requestId: outcome.requestId,
    status: outcome.decision,
    decision: outcome.decision,
    commitment: outcome.commitment,
    policyId: outcome.decisionReceipt.receipt.policyId,
    imageId: outcome.decisionReceipt.receipt.imageId,
    model: outcome.canonical.model,
    decisionReceipt: outcome.decisionReceipt,
    proofStarted: true,
    gateWallMs: outcome.gateWallMs,
    timings: { enclaveDecryptMs: outcome.decryptMs, gateWallMs: outcome.gateWallMs, policyMs: outcome.gateWallMs },
  };
});

/**
 * The dispatch phase (ALLOW only). If a prior `/gate` parked this request, that
 * ALLOW outcome is consumed (no re-decrypt, no re-gate). A direct caller that
 * posts an envelope with no prior `/gate` still works: the request is gated
 * inline and then dispatched in one shot (the enclave's own security tests use
 * this path). Either way the guest is the authoritative gate.
 */
app.post("/execute", async (request, reply) => {
  const { envelope, candidates, requestCommitment: presentedCommitment } = request.body as ExecuteBody;

  // Consume a parked gate ONLY if the caller reproduces the commitment it was
  // parked under. A mismatch (wrong or absent commitment for a real pending
  // requestId) is rejected with a fixed string — never any request bytes — and
  // leaves the victim's gate intact.
  const consumed = envelope?.requestId
    ? pendingGates.consume(envelope.requestId, presentedCommitment ?? "")
    : ({ status: "MISS" } as const);

  if (consumed.status === "MISMATCH") {
    return reply
      .code(400)
      .send({ error: { code: "CTN_INVALID_ENVELOPE", message: "execute does not match the parked gate commitment" } });
  }

  let outcome: GateOutcome;
  if (consumed.status === "HIT") {
    outcome = consumed.value;
  } else {
    // No parked gate for this requestId: gate inline (direct callers) in one shot.
    try {
      outcome = await gateRequest(envelope);
    } catch (err) {
      if (replyGateError(reply, err)) return;
      throw err;
    }
    prover.start(outcome.requestId, witnessFor(outcome));
  }

  if (outcome.decision === "DENY") return deniedBody(outcome);
  return await runDispatch(outcome, candidates ?? []);
});

/**
 * §32 — proof state is polled because proving may finish after inference. Phase
 * 2b: the FIVE-state machine (QUEUED / PROVING / GENERATED / VERIFIED / FAILED).
 * QUEUED means "waiting to prove," NOT "cryptography running." `proofVerified` is
 * only ever true once the reference `prover/verify` subprocess passed (§4).
 */
app.get("/proofs/:requestId", async (request, reply) => {
  const { requestId } = request.params as { requestId: string };
  const record = prover.get(requestId);
  if (!record) return reply.code(404).send({ status: "NOT_REQUIRED" });

  const s = record.state;
  const base = { requestId, proofSystem: "risc0" as const, proofNonce: record.proofNonce };

  if (s.status === "QUEUED" || s.status === "PROVING") {
    return { ...base, status: s.status, proofVerified: false };
  }
  if (s.status === "FAILED") {
    return { ...base, status: "FAILED", proofVerified: false, error: s.error, proofMs: s.proofMs };
  }
  if (s.status === "GENERATED") {
    // Decoded but NOT YET verified — the subprocess is still to run (or has just
    // completed and the transition to VERIFIED/FAILED is imminent).
    return {
      ...base,
      status: "GENERATED",
      proofVerified: false,
      proofMs: s.proofMs,
      imageId: s.artifact.imageId,
      decodedJournal: s.artifact.decodedJournal,
      artifactDigest: s.artifactDigest,
      artifact: artifactToWire(s.artifact),
    };
  }
  // VERIFIED — the STARK checked out against the pinned manifest and the journal
  // is bound to the gate journal.
  return {
    ...base,
    status: "VERIFIED",
    proofVerified: true,
    proofMs: s.proofMs,
    imageId: s.artifact.imageId,
    decodedJournal: s.artifact.decodedJournal,
    artifactDigest: s.artifactDigest,
    decisionReceiptDigest: s.decisionReceiptDigest,
    verification: { ok: s.verification.ok, checks: s.verification.checks },
    artifact: artifactToWire(s.artifact),
    binding: s.binding,
    enclaveSigningPublicKey: tee.signingPublicKey,
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
  // Policy Lab is the PREVIEW surface (§5): it deliberately runs the TypeScript
  // engine, not the guest gate, and is labelled non-authoritative. This is the
  // one remaining request-shaped caller of `AuthorizedRequest.evaluate`.
  const gate = AuthorizedRequest.evaluate(canonical, payload.requestNonce, pkg);

  // Task 4 — the preview does NOT prove. It is not a served request and gates
  // nothing, so enqueuing a real ~2-min STARK here (as Task 3 briefly did) was
  // both a UX regression and a source of an identity-inconsistent binding: the
  // preview receipt carries the PREVIEW pkg identity, but the shared Prover
  // stamps every artifact with the PINNED guest manifest identity (POLICY_ID_V2).
  // Rather than mint a proof that disagrees with itself, the preview surfaces the
  // verdict + commitment only; the authoritative, verified proof is produced on
  // the request path (the guest gate), never here.
  return {
    testId,
    decision: gate.decision,
    commitment: gate.commitment,
    policyId: pkg.policyId,
    policyMs: gate.policyMs,
    promptVisiblePublicly: false,
    // The preview never proves — no artifact, no binding, no proof job.
    proofStarted: false,
  };
});

/**
 * Verification endpoint used by the receipt viewer and the CLI. Phase 2b: a proof
 * is a real STARK, so verifying it means RE-RUNNING the reference `prover/verify`
 * subprocess against the pinned manifest (fast, ~tens of ms), NOT checking an
 * ed25519 seal. The compute receipt's own signature + its binding to the artifact
 * are checked in TypeScript.
 */
app.post("/verify", async (request) => {
  const body = request.body as {
    artifact?: import("@ctn/protocol").ProofArtifactWireV1;
    receipt?: SignedComputeReceipt;
    binding?: SignedProofBindingV2;
  };
  const result: Record<string, unknown> = {};
  let artifact: import("@ctn/protocol").ProofArtifactV1 | undefined;
  if (body.artifact) {
    const { artifactFromWire } = await import("@ctn/protocol");
    artifact = artifactFromWire(body.artifact);
    const sub = await runReferenceVerify(
      artifact.receiptBytes,
      {
        commitment: artifact.decodedJournal.requestCommitment,
        decision: artifact.decodedJournal.decision,
        proofNonce: artifact.decodedJournal.proofNonce,
      },
      VERIFIER_PATHS
    );
    result.proof = {
      valid: sub.ok,
      checks: sub.checks.map((c) => ({ name: c.name, pass: c.pass, detail: c.detail })),
    };
  }
  if (body.receipt) {
    result.receipt = verifyComputeReceipt(body.receipt, {
      enclaveSigningPublicKey: tee.signingPublicKey,
      artifact,
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

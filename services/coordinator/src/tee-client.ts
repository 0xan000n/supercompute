/**
 * The coordinator's only channel into the confidential service.
 *
 * In simulation this is loopback HTTP. On Nitro this is the vsock transport
 * (§20) — the parent relays bytes and cannot read the payloads it carries.
 * Isolating it here means the Nitro port touches this file and nothing else.
 */
import type {
  SecureRequestEnvelope,
  SignedComputeReceipt,
  SignedProofBinding,
  AttestationBundle,
  ProofReceipt,
} from "@ctn/protocol";
import type { Candidate } from "./routing.js";

const TEE_URL = process.env.TEE_URL ?? "http://127.0.0.1:4400";

export class EnclaveUnavailableError extends Error {
  constructor(cause?: unknown) {
    super(`CTN_ENCLAVE_UNAVAILABLE: ${cause instanceof Error ? cause.message : String(cause)}`);
  }
}

/**
 * The enclave refused the request (bad envelope, replayed nonce, unknown key id).
 *
 * This is thrown rather than returned so a rejection can never be mistaken for a
 * result. An earlier version returned the error body typed as a success shape,
 * and callers happily read fields off it — which produced a 500 and a request
 * row stuck in RECEIVED forever. Making the failure path a throw removes that
 * whole class of bug for every endpoint at once.
 */
export class EnclaveRejectionError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly httpStatus: number
  ) {
    super(message);
    this.name = "EnclaveRejectionError";
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${TEE_URL}${path}`, {
      ...init,
      headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch (err) {
    throw new EnclaveUnavailableError(err);
  }

  let json: T & { error?: { code?: string; message?: string } };
  try {
    json = (await res.json()) as typeof json;
  } catch {
    throw new EnclaveUnavailableError(`enclave returned unparseable ${res.status}`);
  }

  if (!res.ok) {
    if (json?.error) {
      throw new EnclaveRejectionError(
        json.error.code ?? "CTN_INVALID_ENVELOPE",
        json.error.message ?? "the enclave refused the request",
        res.status
      );
    }
    throw new EnclaveUnavailableError(`enclave returned ${res.status}`);
  }
  return json;
}

export interface AttestationResponse {
  bundle: AttestationBundle;
  verification: { valid: boolean; checks: Array<{ name: string; pass: boolean; detail?: string }> };
  policy: { policyId: string; guestImageId: string; name: string; version: string; normalizer: string };
  attestationDigest: string;
}

export const teeClient = {
  attestation: (nonce?: string) =>
    call<AttestationResponse>(`/attestation${nonce ? `?nonce=${encodeURIComponent(nonce)}` : ""}`),

  buildManifest: () => call<Record<string, unknown>>("/build-manifest"),

  /**
   * Relays the contributor's sealed intent verbatim. There is deliberately no
   * capability block here: everything the enclave will sign comes out of the
   * ciphertext, so this process has nothing to widen (§5.1).
   */
  ingestCredential: (body: {
    enclaveKeyId: string;
    enc: string;
    encryptedSecret: string;
    credentialId: string;
  }) =>
    call<{
      credentialId: string;
      encryptedBlob: string;
      capability: import("@ctn/protocol").CredentialCapability;
      capabilitySignature: string;
      keyFingerprint: string;
      policyId: string;
    }>("/credentials/ingest", { method: "POST", body: JSON.stringify(body) }),

  execute: (envelope: SecureRequestEnvelope, candidates: Candidate[]) =>
    call<ExecuteResult>("/execute", {
      method: "POST",
      body: JSON.stringify({ envelope, candidates }),
    }),

  proof: (requestId: string) => call<ProofResponse>(`/proofs/${requestId}`),

  policyTest: (envelope: SecureRequestEnvelope) =>
    call<{
      testId: string;
      decision: "ALLOW" | "DENY";
      commitment: string;
      policyId: string;
      policyMs: number;
      promptVisiblePublicly: boolean;
      proofStarted: boolean;
    }>("/policy-test", { method: "POST", body: JSON.stringify({ envelope }) }),

  verify: (body: {
    proof?: ProofReceipt;
    receipt?: SignedComputeReceipt;
    binding?: SignedProofBinding;
  }) =>
    call<{
      proof?: VerificationReport;
      receipt?: VerificationReport;
      keys?: Record<string, string>;
    }>("/verify", { method: "POST", body: JSON.stringify(body) }),
};

export interface VerificationReport {
  valid: boolean;
  checks: Array<{ name: string; pass: boolean; detail?: string }>;
}

export interface AttemptResult {
  credentialId: string;
  contributorId: string;
  attemptNumber: number;
  status: "SUCCESS" | "FAILED";
  httpStatus: number;
  latencyMs: number;
  classification?: string;
  /**
   * §5.1 — the enclave dispatched this attempt and never learned the outcome.
   * The provider may have processed and billed it, so `assumedSpendMicroUsd`
   * is the conservative upper bound this coordinator must charge against the
   * credential's cap. Mirrors AttemptRecord in services/tee-sim/src/index.ts.
   */
  upstreamOutcomeUnknown?: boolean;
  assumedSpendMicroUsd?: number;
}

export interface ExecuteResult {
  requestId: string;
  status: "COMPLETE" | "DENIED" | "FAILED";
  commitment: string;
  policyId: string;
  policyDecision: "ALLOW" | "DENY";
  policyMs: number;
  model: string;
  encryptedResponse: { enc: string; ciphertext: string } | null;
  receipt: SignedComputeReceipt | null;
  attempts: AttemptResult[];
  selected: {
    credentialId: string;
    contributorId: string;
    provider: string;
    model: string;
    attempt: number;
  } | null;
  authorizationFailures: Array<{ credentialId: string; reason: string }>;
  proofStarted: boolean;
  usage?: { inputTokens?: number; outputTokens?: number; estimatedCostMicroUsd?: number };
  timings: {
    enclaveDecryptMs?: number;
    policyMs: number;
    providerTotalMs?: number;
    totalMs: number;
  };
  error?: { code: string; message: string };
  debug?: unknown;
}

export interface ProofResponse {
  requestId: string;
  status: "PROVING" | "GENERATED" | "VERIFIED" | "FAILED" | "NOT_REQUIRED";
  proof?: ProofReceipt;
  proofMs?: number;
  digest?: string;
  simulatedCostMs?: number;
  error?: string;
  verification?: VerificationReport;
  proverPublicKey?: string;
  enclaveSigningPublicKey?: string;
  binding?: SignedProofBinding;
}

/**
 * Shared protocol types for the Compute Trust Network prototype.
 * Spec: Compute Trust Network Prototype, Implementation Specification v0.1.
 */

export type Provider = "openai" | "anthropic" | "google" | "mock";

export interface CanonicalMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

/** §21 — the single unambiguous request representation the proof refers to. */
export interface CanonicalRequestV1 {
  model: string;
  messages: CanonicalMessage[];
  /** integer millis; 1000 = temperature 1.0 — no floats anywhere in the canonical form */
  temperature_millis: number;
  max_tokens: number;
}

/** §10 — encrypted request envelope. Coordinator cannot decrypt. */
export interface SecureRequestEnvelope {
  version: "ctn-1";
  requestId: string;
  enclaveKeyId: string;
  /** HPKE encapsulated key, base64 */
  enc: string;
  /** HPKE ciphertext of SecurePayload, base64 */
  ciphertext: string;
  /**
   * Authenticated-but-unencrypted header. Bound to the ciphertext as HPKE AAD,
   * so the coordinator cannot alter any of it without breaking decryption.
   *
   * `model` is here deliberately: routing by model is the network's job, so the
   * network necessarily learns WHICH model was asked for. It never learns what
   * was asked. The enclave asserts this model equals the model inside the
   * ciphertext, so a tampered header fails closed rather than mis-routing.
   */
  aad: {
    apiVersion: "v1";
    requestedPolicy: "safety-v1";
    model: string;
  };
}

/** What actually lives inside the envelope ciphertext. */
export interface SecurePayload {
  request: CanonicalRequestV1;
  /** 32-byte hex nonce, client-generated: prevents identical prompts producing linkable commitments */
  requestNonce: string;
  /** X25519 public key (base64) the enclave seals the response to */
  responsePublicKey: string;
}

/** Encrypted response returned to the client. Coordinator relays it blind. */
export interface SecureResponse {
  enc: string;
  ciphertext: string;
}

/** §11 — attestation bundle exposed via coordinator. */
export interface AttestationBundle {
  version: "ctn-attestation-1";
  /** In simulation mode this is a clearly-labeled simulated document, not a Nitro doc. */
  teeMode: "simulation" | "nitro";
  document: SimulatedAttestationDocument;
  enclaveSigningPublicKey: string;
  ingressPublicKey: string;
  enclaveKeyId: string;
  enclaveBuildId: string;
  policyIds: string[];
  issuedAt: string;
  /**
   * The freshness nonce this attestation was issued for, echoed back.
   *
   * It has to be here, not merely mixed into the signature, for two reasons: a
   * verifier cannot reconstruct the signed bytes without it, and a caller that
   * supplied a nonce can only check freshness by comparing what came back
   * against what it sent. The nonce is not secret — the caller chose it.
   */
  nonce: string | null;
}

export interface SimulatedAttestationDocument {
  moduleId: string;
  digest: "SHA384";
  pcrs: Record<string, string>;
  /** binds the ingress + signing keys into attested data, mirroring Nitro user_data */
  userData: {
    ingressPublicKey: string;
    signingPublicKey: string;
  };
  timestamp: number;
  /** signature over the document by the (simulated) platform root key */
  platformSignature: string;
  warning: "SIMULATED TEE — NO HARDWARE CONFIDENTIALITY";
}

/** §13 — credential submission; encryptedSecret is HPKE-sealed to the enclave ingress key. */
export interface CredentialSubmission {
  enclaveKeyId: string;
  enc: string;
  encryptedSecret: string;
  capability: {
    provider: Provider;
    allowedModels: string[];
    allowedPolicies: string[];
    operationalLimits?: {
      dailyUsd?: number;
      dailyRequests?: number;
    };
  };
  contributorDisplayId: string;
}

/** §15 — capability object signed by the enclave at storage time. */
export interface CredentialCapability {
  credentialId: string;
  provider: Provider;
  allowedModels: string[];
  allowedPolicyIds: string[];
  contributorId: string;
  createdAt: number;
  version: number;
  /**
   * SHA-256 of the vault ciphertext this capability governs.
   *
   * Without this, the signed capability says "these are the rules for credential
   * X" but nothing ties it to a specific encrypted secret — so an untrusted
   * coordinator could hand the enclave one contributor's capability alongside
   * another contributor's key blob. The enclave would then spend the second
   * contributor's credential under the first one's constraints and credit the
   * usage to the wrong person. Binding the ciphertext digest into the signature
   * closes that substitution.
   */
  blobDigest: string;
}

export type PolicyDecision = "ALLOW" | "DENY";

/** §27 — public journal of the policy proof. Never contains prompt-derived data. */
export interface PolicyJournal {
  protocolVersion: 1;
  requestCommitment: string;
  policyId: string;
  decision: PolicyDecision;
  proofNonce: string;
}

export type ProofStatus =
  | "NOT_REQUIRED"
  | "QUEUED"
  | "PROVING"
  | "GENERATED"
  | "VERIFIED"
  | "FAILED";

export type RequestStatus =
  | "RECEIVED"
  | "DECRYPTED"
  | "POLICY_EVALUATING"
  | "DENIED"
  | "AUTHORIZED"
  | "ROUTING"
  | "PROVIDER_PENDING"
  | "PROVIDER_RUNNING"
  | "FAILED"
  | "COMPLETE";

export type TrustStatus =
  | "CONFIDENTIAL_VERIFIED"
  | "CONFIDENTIAL_PROOF_PENDING"
  | "CONFIDENTIAL_PROOF_FAILED"
  | "SIMULATED"
  | "COMPATIBILITY";

/**
 * §28 — proof artifact. In simulation mode the "proof" is a signed re-execution
 * receipt from an isolated prover: honest about what it is, same shape as the
 * RISC Zero receipt the hardware path produces.
 */
export interface ProofReceipt {
  proofSystem: "simulated-reexec" | "risc0";
  guestImageId: string;
  journal: PolicyJournal;
  /** signature over canonical(journal) by the prover key (simulation) or seal (risc0) */
  seal: string;
  proverPublicKey: string;
}

/** §30 — compute receipt signed by the enclave. */
export interface ComputeReceipt {
  version: "ctn-receipt-1";
  requestId: string;
  requestCommitment: string;
  tee: {
    mode: "simulation" | "nitro";
    buildId: string;
    attestationDigest: string;
  };
  policy: {
    policyId: string;
    decision: "ALLOW";
    zkReceiptDigest: string;
  };
  route: {
    provider: string;
    model: string;
    credentialId: string;
    contributorId: string;
    attempt: number;
  };
  usage: {
    inputTokens?: number;
    outputTokens?: number;
    /**
     * Integer micro-USD, never a float. The receipt is signed over its canonical
     * form, and float serialization differs across languages/platforms — a
     * verifier in another runtime must recompute byte-identical bytes.
     */
    estimatedCostMicroUsd?: number;
  };
  timing: {
    receivedAt: string;
    policyMs: number;
    proofMs?: number;
    providerTotalMs: number;
  };
  upstreamRequestHash: string;
  upstreamResponseHash: string;
}

export interface SignedComputeReceipt {
  receipt: ComputeReceipt;
  enclaveSignature: string;
}

/**
 * Rule 8 / §30 — the artifact that closes the loop between a receipt and its proof.
 *
 * The compute receipt has to be signed when inference finishes, but proving runs
 * in parallel (§26) and normally finishes later, so the receipt cannot contain
 * the proof digest at signing time. Rather than delay the receipt (which would
 * throw away the parallelism the prototype exists to measure) or mutate it
 * afterwards (which would rewrite history, §59), the enclave issues this second
 * signed statement once proving settles.
 *
 * It binds: this request commitment ↔ this proof digest ↔ this policy decision.
 */
export interface ProofBinding {
  version: "ctn-proof-binding-1";
  requestId: string;
  requestCommitment: string;
  policyId: string;
  guestImageId: string;
  zkReceiptDigest: string;
  decision: PolicyDecision;
  proofVerified: boolean;
  issuedAt: string;
}

export interface SignedProofBinding {
  binding: ProofBinding;
  enclaveSignature: string;
}

/** §41 — outbox event names. */
export type CtnEventType =
  | "request.received"
  | "tee.verified"
  | "policy.started"
  | "policy.allowed"
  | "policy.denied"
  | "proof.started"
  | "proof.completed"
  | "proof.failed"
  | "route.selected"
  | "provider.started"
  | "provider.failed"
  | "provider.completed"
  | "receipt.created"
  | "credential.created"
  | "credential.updated"
  | "contributor.created";

export interface CtnEvent {
  event: CtnEventType;
  timestamp: string;
  [key: string]: unknown;
}

/** §46 — graph snapshot served to Cosmograph UI. */
export type GraphNodeType =
  | "Contributor"
  | "Credential"
  | "Request"
  | "Policy"
  | "Proof"
  | "TEEWorker"
  | "Provider"
  | "Model"
  | "ProviderAttempt"
  | "Response"
  | "ComputeReceipt";

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  status?: string;
  meta?: Record<string, string | number | boolean>;
  createdAt: string;
}

export interface GraphLink {
  id: string;
  source: string;
  target: string;
  type: string;
  createdAt: string;
}

export interface GraphSnapshot {
  nodes: GraphNode[];
  links: GraphLink[];
}

/** §58 — error codes. */
export type CtnErrorCode =
  | "CTN_POLICY_DENIED"
  | "CTN_NO_CAPACITY"
  | "CTN_PROVIDER_RATE_LIMITED"
  | "CTN_PROVIDER_AUTH_FAILED"
  | "CTN_PROVIDER_ERROR"
  | "CTN_INVALID_ENVELOPE"
  | "CTN_ATTESTATION_REQUIRED"
  | "CTN_ENCLAVE_UNAVAILABLE"
  | "CTN_INTERNAL";

export interface CtnError {
  error: {
    code: CtnErrorCode;
    message: string;
    request_id?: string;
    policy_id?: string;
  };
}

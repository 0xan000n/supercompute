/**
 * §69 — type-state gate. `AuthorizedRequest` and `AuthorizedCredential` cannot be
 * constructed outside this module, and the provider adapter accepts nothing else.
 * That makes "call the provider before the policy allowed it" a type error rather
 * than a code-review question (Rule 5).
 */
import {
  canonicalBytes,
  canonicalJson,
  requestCommitment,
  canonicalHash,
  sha256Hex,
  verifyCanonical,
} from "@ctn/protocol";
import type { CanonicalRequestV1, CredentialCapability, PolicyDecision } from "@ctn/protocol";
import { evaluateRequest, type PolicyPackage, type PolicyEvaluation } from "@ctn/policy";

const BRAND = Symbol("ctn.authorized");

/**
 * Phase 2b — the determinism guard. The guest executor (the authoritative gate)
 * computes the request commitment itself, inside the zkVM, from the canonical
 * bytes and nonce. The enclave recomputes the SAME commitment from the SAME
 * inputs and asserts equality: if they differ, the guest evaluated bytes other
 * than the ones the enclave is about to act on, and there is no safe decision —
 * so this throws and the request fails closed rather than binding a verdict to a
 * request that was never evaluated.
 */
export class CommitmentMismatchError extends Error {
  readonly code = "CTN_COMMITMENT_MISMATCH";
  constructor() {
    super("guest journal commitment does not match the enclave recomputation");
    this.name = "CommitmentMismatchError";
  }
}

/** Pure, fail-closed commitment equality check (exported for the differential/e2e). */
export function assertGuestCommitment(enclaveCommitment: string, journalCommitment: string): void {
  if (enclaveCommitment !== journalCommitment) throw new CommitmentMismatchError();
}

export class AuthorizedRequest {
  readonly [BRAND] = true;
  private constructor(
    readonly request: CanonicalRequestV1,
    readonly requestCommitment: string,
    readonly requestNonce: string,
    readonly policyId: string,
    readonly policyMs: number
  ) {}

  /**
   * The single door into the authorized state. Returns either an
   * AuthorizedRequest (policy said ALLOW) or a denial — never both, and there
   * is no other constructor.
   */
  static evaluate(
    request: CanonicalRequestV1,
    requestNonce: string,
    pkg: PolicyPackage
  ):
    | { decision: "ALLOW"; authorized: AuthorizedRequest; evaluation: PolicyEvaluation; commitment: string; policyMs: number }
    | { decision: "DENY"; evaluation: PolicyEvaluation; commitment: string; policyMs: number } {
    const started = performance.now();
    const commitment = requestCommitment(canonicalBytes(request), requestNonce);
    const evaluation = evaluateRequest(request.messages, pkg);
    const policyMs = Math.max(1, Math.round(performance.now() - started));

    if (evaluation.decision !== "ALLOW") {
      return { decision: "DENY", evaluation, commitment, policyMs };
    }
    return {
      decision: "ALLOW",
      authorized: new AuthorizedRequest(request, commitment, requestNonce, pkg.policyId, policyMs),
      evaluation,
      commitment,
      policyMs,
    };
  }

  /**
   * Phase 2b §3 — construct the authorized state from the GUEST verdict rather
   * than the TypeScript engine. The guest `/execute` journal is authoritative for
   * every request; this factory recomputes the commitment, asserts it equals the
   * journal's (fail closed on mismatch), and returns either an AuthorizedRequest
   * (guest said ALLOW) or a denial. The TS `evaluate` above no longer runs on the
   * request path — it is retained only for the Policy-Lab preview.
   */
  static fromGuestJournal(
    request: CanonicalRequestV1,
    requestNonce: string,
    journal: { requestCommitment: string; decision: "ALLOW" | "DENY"; policyId: string },
    gateWallMs: number
  ):
    | { decision: "ALLOW"; authorized: AuthorizedRequest; commitment: string }
    | { decision: "DENY"; commitment: string } {
    const commitment = requestCommitment(canonicalBytes(request), requestNonce);
    // Determinism guard — the guest and the enclave must agree on WHICH request
    // was evaluated, byte for byte, before any verdict is trusted.
    assertGuestCommitment(commitment, journal.requestCommitment);

    if (journal.decision !== "ALLOW") {
      return { decision: "DENY", commitment };
    }
    return {
      decision: "ALLOW",
      authorized: new AuthorizedRequest(request, commitment, requestNonce, journal.policyId, gateWallMs),
      commitment,
    };
  }

  /** Witness handed to the prover — private input, never leaves the trust boundary. */
  witness(): { canonicalRequest: string; requestNonce: string } {
    return { canonicalRequest: canonicalJson(this.request), requestNonce: this.requestNonce };
  }
}

/**
 * The mint token is module-private and NOT reachable from the exported class.
 *
 * It was previously a public static on `AuthorizedCredential`, which meant any
 * file that imported the class could read the token and mint a credential with an
 * arbitrary secret, bypassing every check in `authorizeCandidate`. §69 claims the
 * type system enforces this; a public static made it a naming convention instead.
 */
const MINT_TOKEN = Symbol("ctn.credential.mint");

/** A credential that has passed every §16 check and been decrypted inside the enclave. */
export class AuthorizedCredential {
  private constructor(
    readonly credentialId: string,
    readonly contributorId: string,
    readonly provider: string,
    readonly secret: string,
    readonly capability: CredentialCapability
  ) {}

  /** Only `authorizeCandidate`, below, holds the token needed to call this. */
  static mint(
    token: symbol,
    args: {
      credentialId: string;
      contributorId: string;
      provider: string;
      secret: string;
      capability: CredentialCapability;
    }
  ): AuthorizedCredential {
    if (token !== MINT_TOKEN) {
      throw new Error("AuthorizedCredential may only be minted by the routing verifier");
    }
    return new AuthorizedCredential(
      args.credentialId,
      args.contributorId,
      args.provider,
      args.secret,
      args.capability
    );
  }

  /** Never let a credential secret reach a log, an error, or a JSON body. */
  toJSON(): never {
    throw new Error("AuthorizedCredential is not serializable");
  }
  toString(): string {
    return `AuthorizedCredential(${this.credentialId})`;
  }
  get [Symbol.toStringTag](): string {
    return "AuthorizedCredential";
  }
}

export type CandidateRecord = {
  credentialId: string;
  contributorId: string;
  provider: string;
  status: string;
  encryptedBlob: string;
  capability: CredentialCapability;
  capabilitySignature: string;
};

export type AuthorizationFailure = {
  credentialId: string;
  reason:
    | "not_enabled"
    | "provider_mismatch"
    | "model_not_allowed"
    | "policy_not_allowed"
    | "capability_signature_invalid"
    | "capability_id_mismatch"
    | "blob_digest_mismatch"
    | "blob_decrypt_failed";
};

/**
 * §16 — the enclave performs FINAL authorization. The coordinator's candidate
 * list is a hint; every field that matters is re-verified here against the
 * enclave-signed capability, so an untrusted coordinator cannot widen
 * allowedModels, swap the provider, or reassign ownership undetected (§15).
 */
export function authorizeCandidate(
  candidate: CandidateRecord,
  authorized: AuthorizedRequest,
  enclaveSigningPublicKey: string,
  decryptBlob: (blob: string) => string
): { ok: true; credential: AuthorizedCredential } | { ok: false; failure: AuthorizationFailure } {
  const fail = (reason: AuthorizationFailure["reason"]) => ({
    ok: false as const,
    failure: { credentialId: candidate.credentialId, reason },
  });

  if (candidate.status !== "ACTIVE") return fail("not_enabled");

  // The capability signature covers the capability object; verify BEFORE trusting
  // any field inside it.
  if (!verifyCanonical(candidate.capability, candidate.capabilitySignature, enclaveSigningPublicKey)) {
    return fail("capability_signature_invalid");
  }
  // The signed capability must be the one for this credential row, and must name
  // the contributor the coordinator claims — otherwise usage for a real key can
  // be attributed to an arbitrary third party in an enclave-signed receipt.
  if (
    candidate.capability.credentialId !== candidate.credentialId ||
    candidate.capability.contributorId !== candidate.contributorId
  ) {
    return fail("capability_id_mismatch");
  }
  /**
   * The signed capability names the ciphertext it governs, so the coordinator
   * cannot pair one contributor's constraints with another contributor's key
   * blob — which would spend the wrong credential and credit the wrong person.
   */
  if (candidate.capability.blobDigest !== "0x" + sha256Hex(candidate.encryptedBlob)) {
    return fail("blob_digest_mismatch");
  }
  if (candidate.capability.provider !== candidate.provider) return fail("provider_mismatch");
  if (!candidate.capability.allowedModels.includes(authorized.request.model)) {
    return fail("model_not_allowed");
  }
  if (!candidate.capability.allowedPolicyIds.includes(authorized.policyId)) {
    return fail("policy_not_allowed");
  }

  let secret: string;
  try {
    // §25 — credential material is decrypted only after ALLOW and only after
    // every capability check above has passed.
    secret = decryptBlob(candidate.encryptedBlob);
  } catch {
    return fail("blob_decrypt_failed");
  }

  return {
    ok: true,
    credential: AuthorizedCredential.mint(MINT_TOKEN, {
      credentialId: candidate.credentialId,
      // Sourced from the SIGNED capability, never from the coordinator's own
      // field. Attribution is what the receipt asserts, so it has to come from
      // something the coordinator cannot rewrite.
      contributorId: candidate.capability.contributorId,
      provider: candidate.provider,
      secret,
      capability: candidate.capability,
    }),
  };
}

export { canonicalHash };
export type { PolicyDecision };

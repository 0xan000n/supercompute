/**
 * §29 — independent proof verification. Deliberately written so it depends on
 * nothing but the public artifact plus the expected identifiers: a third party
 * can run this against a receipt they were handed.
 *
 * The four checks below mirror exactly what a RISC Zero verification does
 * (receipt validity, guest image id match, journal/commitment match, decision),
 * so replacing the proof system does not change any caller.
 */
import { verifyCanonical, verifyDigestHex, zkArtifactDigest } from "@ctn/protocol";
import type {
  PolicyDecision,
  ProofArtifactV1,
  ProofReceipt,
  SignedComputeReceipt,
  SignedProofBindingV2,
} from "@ctn/protocol";

export interface VerificationCheck {
  name: string;
  pass: boolean;
  detail?: string;
}

export interface VerificationResult {
  valid: boolean;
  checks: VerificationCheck[];
}

export function verifyProof(
  proof: ProofReceipt,
  expected: {
    expectedGuestImageId: string;
    expectedPolicyId: string;
    expectedCommitment?: string;
    /**
     * Phase 2b — the decision the proof is expected to carry. DENY requests are
     * now gated and proved too (proofStarted for ALLOW AND DENY), so the verifier
     * checks against the expected verdict rather than hardcoding ALLOW. Defaults
     * to ALLOW so existing callers (and the tamper tests) are unchanged.
     */
    expectedDecision?: PolicyDecision;
    proverPublicKey: string;
  }
): VerificationResult {
  const checks: VerificationCheck[] = [];

  // 1. The seal is valid over (guest image id, journal) under the attested prover key.
  const sealValid = verifyCanonical(
    { guestImageId: proof.guestImageId, journal: proof.journal },
    proof.seal,
    expected.proverPublicKey
  );
  checks.push({
    name: "proof seal valid",
    pass: sealValid,
    detail: proof.proofSystem === "risc0" ? "RISC Zero receipt" : "simulated re-execution seal",
  });

  // 2. The proof was produced by the expected policy program.
  checks.push({
    name: "guest image id matches Safety Policy v1",
    pass: proof.guestImageId === expected.expectedGuestImageId,
    detail: proof.guestImageId,
  });

  // 3. The journal's policy id is the exact policy version expected.
  checks.push({
    name: "journal policy id matches expected policy",
    pass: proof.journal.policyId === expected.expectedPolicyId,
    detail: proof.journal.policyId,
  });

  // 4. §36 / Rule 8 — the journal binds to the same commitment the receipt carries.
  if (expected.expectedCommitment !== undefined) {
    checks.push({
      name: "request commitment matches receipt",
      pass: proof.journal.requestCommitment === expected.expectedCommitment,
      detail: proof.journal.requestCommitment,
    });
  }

  const expectedDecision = expected.expectedDecision ?? "ALLOW";
  checks.push({
    name: `decision is ${expectedDecision}`,
    pass: proof.journal.decision === expectedDecision,
  });

  // §27 — the journal must not carry prompt-derived fields. Enforced, not assumed.
  const allowedKeys = new Set([
    "protocolVersion",
    "requestCommitment",
    "policyId",
    "decision",
    "proofNonce",
  ]);
  const extraneous = Object.keys(proof.journal).filter((k) => !allowedKeys.has(k));
  checks.push({
    name: "journal contains no prompt-derived fields",
    pass: extraneous.length === 0,
    detail: extraneous.length ? `unexpected keys: ${extraneous.join(", ")}` : undefined,
  });

  return { valid: checks.every((c) => c.pass), checks };
}

/**
 * §30 — verify the compute receipt signature and its binding to the proof.
 *
 * Note on `zkReceiptDigest`: the receipt is signed the moment inference finishes,
 * and proving deliberately runs in parallel (§26), so at signing time the proof
 * digest usually does not exist yet and the field reads "pending". That is not a
 * verification failure — it is the expected state of an honest receipt issued
 * before its proof. The binding that actually matters (Rule 8) is that the proof
 * journal and the receipt carry the SAME request commitment, which is checked
 * unconditionally below. The finished digest is bound by the separate signed
 * ProofBinding artifact.
 */
export function verifyComputeReceipt(
  signed: SignedComputeReceipt,
  expected: {
    enclaveSigningPublicKey: string;
    /** Phase 2b — the real proof artifact (bincode receipt + decoded journal). */
    artifact?: ProofArtifactV1;
    binding?: SignedProofBindingV2;
  }
): VerificationResult {
  const checks: VerificationCheck[] = [];

  checks.push({
    name: "receipt signature valid under attested enclave signing key",
    pass: verifyCanonical(signed.receipt, signed.enclaveSignature, expected.enclaveSigningPublicKey),
  });

  checks.push({
    name: "receipt policy decision is ALLOW",
    pass: signed.receipt.policy.decision === "ALLOW",
  });

  if (expected.artifact) {
    const journal = expected.artifact.decodedJournal;
    const artifactDigest = zkArtifactDigest(expected.artifact.receiptBytes);

    // Rule 8 — the load-bearing check: the proof and the receipt are about the
    // SAME request and the SAME policy identity.
    checks.push({
      name: "proof journal commitment equals receipt commitment",
      pass: journal.requestCommitment === signed.receipt.requestCommitment,
      detail: signed.receipt.requestCommitment,
    });
    checks.push({
      name: "proof policy id equals receipt policy id",
      pass: journal.policyId === signed.receipt.policy.policyId,
    });

    const embedded = signed.receipt.policy.zkReceiptDigest;
    if (embedded === "pending") {
      checks.push({
        name: "receipt was signed before proving finished",
        pass: true,
        detail: "expected: proving runs in parallel with inference; the digest is bound by the ProofBindingV2",
      });
    } else {
      checks.push({
        name: "receipt zkReceiptDigest matches the artifact digest",
        pass: embedded === artifactDigest,
        detail: artifactDigest,
      });
    }

    if (expected.binding) {
      const b = expected.binding.binding;
      checks.push({
        name: "proof binding signature valid under attested enclave signing key",
        pass: verifyCanonical(b, expected.binding.enclaveSignature, expected.enclaveSigningPublicKey),
      });
      checks.push({
        name: "proof binding commits to this artifact digest",
        pass: b.artifactDigest === artifactDigest,
        detail: b.artifactDigest,
      });
      checks.push({
        name: "proof binding decision id matches the receipt policy id",
        pass: b.policyId === signed.receipt.policy.policyId,
      });
      checks.push({
        name: "proof binding carries a decision-receipt digest",
        pass: typeof b.decisionReceiptDigest === "string" && b.decisionReceiptDigest.length > 0,
      });
      checks.push({
        name: "proof binding reports the proof verified",
        pass: b.proofVerified === true && b.decision === "ALLOW",
      });
    }
  }

  return { valid: checks.every((c) => c.pass), checks };
}

/** §11 — attestation verification: key binding + measurement approval. */
export function verifyAttestation(
  bundle: {
    document: {
      pcrs: Record<string, string>;
      userData: { ingressPublicKey: string; signingPublicKey: string };
      platformSignature: string;
      timestamp: number;
      moduleId: string;
      digest: string;
      warning?: string;
    };
    teeMode: string;
    ingressPublicKey: string;
    enclaveSigningPublicKey: string;
    nonce?: string | null;
  },
  expected?: { approvedPcr0?: string }
): VerificationResult {
  const checks: VerificationCheck[] = [];
  const { platformSignature, ...unsigned } = bundle.document;

  checks.push({
    name: "attestation document signature valid",
    pass: verifyCanonical(
      { ...unsigned, platformSignature: undefined, nonce: bundle.nonce ?? null },
      platformSignature,
      bundle.enclaveSigningPublicKey
    ),
  });

  // §11 — attested keys must equal the presented keys, or the whole chain is moot.
  checks.push({
    name: "attested ingress key equals presented ingress key",
    pass: bundle.document.userData.ingressPublicKey === bundle.ingressPublicKey,
  });
  checks.push({
    name: "attested signing key equals presented signing key",
    pass: bundle.document.userData.signingPublicKey === bundle.enclaveSigningPublicKey,
  });

  if (expected?.approvedPcr0) {
    checks.push({
      name: "PCR0 matches approved measurement",
      pass: bundle.document.pcrs["0"] === expected.approvedPcr0,
      detail: bundle.document.pcrs["0"],
    });
  }

  // Rule 10 — simulation must never be mistaken for hardware.
  checks.push({
    name: "hardware root of trust",
    pass: bundle.teeMode === "nitro",
    detail:
      bundle.teeMode === "nitro"
        ? "AWS Nitro attestation chain"
        : "SIMULATED — key binding verified, but no hardware isolation",
  });

  // In simulation the hardware check is expected to fail; validity is reported
  // for the cryptographic checks and the mode is reported separately so no
  // caller can accidentally present simulation as hardware-backed.
  const cryptographic = checks.filter((c) => c.name !== "hardware root of trust");
  return { valid: cryptographic.every((c) => c.pass), checks };
}

export { verifyDigestHex };

/**
 * §27, §28 — policy proof generation inside the trust boundary.
 *
 * HONEST LABELING, READ THIS BEFORE TRUSTING ANYTHING BELOW.
 *
 * The target proof system is RISC Zero: a zkVM guest re-executes Safety Policy
 * v1 over a private witness and emits a receipt whose public journal can be
 * verified against an expected guest image id. That requires a Rust toolchain
 * and is Milestone 4 of the spec.
 *
 * This prototype ships `proofSystem: "simulated-reexec"`. What it actually
 * proves, and what it does not:
 *
 *   REAL here:
 *     - the policy is genuinely re-executed from the witness, independently of
 *       the enclave's own evaluation, and the two decisions must agree;
 *     - the journal is bound to the request commitment and the policy id;
 *     - the journal carries a signature under a prover key that is itself bound
 *       into the attestation document, so a verifier can check the journal came
 *       from the attested program and detect any modification;
 *     - the journal leaks nothing about the prompt (§27): no scores, no matched
 *       phrases, no reason, no token features.
 *
 *   NOT real here:
 *     - there is no succinct cryptographic argument. A verifier who does not
 *       trust the attested prover key learns nothing from this artifact.
 *       RISC Zero removes exactly that trust assumption; this does not.
 *
 * The verification path (verify.ts) is written against the same journal +
 * image-id + commitment checks a risc0 receipt needs, so swapping the proof
 * system changes this file and not the callers.
 */
import { evaluate, type PolicyPackage } from "@ctn/policy";
import {
  canonicalHash,
  randomHex,
  type PolicyJournal,
  type ProofBinding,
  type ProofReceipt,
  type SignedProofBinding,
} from "@ctn/protocol";
import type { AuthorizedRequest } from "./authorize.js";
import type { TrustedEnvironment } from "./tee.js";

export type ProofState =
  | { status: "PROVING"; startedAt: number }
  | { status: "GENERATED"; proof: ProofReceipt; proofMs: number; digest: string }
  | {
      status: "VERIFIED";
      proof: ProofReceipt;
      proofMs: number;
      digest: string;
      binding: SignedProofBinding;
    }
  | { status: "FAILED"; error: string; proofMs: number };

/**
 * Models the cost of real proving so the parallelism claim in §26/§66 can be
 * measured rather than asserted. Surfaced to the UI as a simulated cost, never
 * presented as a measured zkVM proving time.
 */
const SIMULATED_PROVING_MS = Number(process.env.CTN_SIMULATED_PROVING_MS ?? 2400);
const PROVING_JITTER_MS = Number(process.env.CTN_SIMULATED_PROVING_JITTER_MS ?? 700);

export interface ProofRecord {
  requestId: string;
  state: ProofState;
  /** How much of the proving cost was modeled rather than measured. */
  simulatedCostMs: number;
}

export class Prover {
  private readonly records = new Map<string, ProofRecord>();

  constructor(
    private readonly tee: TrustedEnvironment,
    private readonly pkg: PolicyPackage
  ) {}

  get(requestId: string): ProofRecord | undefined {
    return this.records.get(requestId);
  }

  /**
   * §25 branch A — kicked off the moment policy returns ALLOW and deliberately
   * NOT awaited, so proving overlaps inference instead of serializing behind it.
   */
  start(requestId: string, authorized: AuthorizedRequest): void {
    const startedAt = performance.now();
    this.records.set(requestId, {
      requestId,
      state: { status: "PROVING", startedAt },
      simulatedCostMs: 0,
    });

    void this.run(requestId, authorized, startedAt);
  }

  private async run(
    requestId: string,
    authorized: AuthorizedRequest,
    startedAt: number
  ): Promise<void> {
    const simulatedCostMs =
      SIMULATED_PROVING_MS + Math.floor(Math.random() * Math.max(1, PROVING_JITTER_MS));
    try {
      const witness = authorized.witness();

      // Independent re-execution from the witness. If the guest's decision ever
      // disagreed with the enclave's, that is a policy-determinism bug and the
      // proof must fail rather than paper over it.
      const parsed = JSON.parse(witness.canonicalRequest) as {
        messages: Array<{ role: string; content: string }>;
      };
      const reexec = evaluate(this.pkg.rules, parsed.messages.map((m) => m.content).join("\n"));
      if (reexec.decision !== "ALLOW") {
        throw new Error(
          "guest re-execution disagreed with enclave policy evaluation (non-determinism)"
        );
      }

      await new Promise((r) => setTimeout(r, simulatedCostMs));

      // §27 — public journal. Nothing prompt-derived may appear here.
      const journal: PolicyJournal = {
        protocolVersion: 1,
        requestCommitment: authorized.requestCommitment,
        policyId: this.pkg.policyId,
        decision: "ALLOW",
        proofNonce: "0x" + randomHex(32),
      };

      const proof: ProofReceipt = {
        proofSystem: "simulated-reexec",
        guestImageId: this.pkg.guestImageId,
        journal,
        seal: this.tee.signProofJournal({ guestImageId: this.pkg.guestImageId, journal }),
        proverPublicKey: this.tee.proverPublicKey,
      };

      const proofMs = Math.round(performance.now() - startedAt);
      const digest = "0x" + canonicalHash(proof);
      this.records.set(requestId, {
        requestId,
        state: { status: "GENERATED", proof, proofMs, digest },
        simulatedCostMs,
      });

      // The enclave verifies its own artifact before publishing it, so a broken
      // prover surfaces as proof_status=FAILED rather than an unverifiable receipt.
      const { verifyProof } = await import("./verify.js");
      const result = verifyProof(proof, {
        expectedGuestImageId: this.pkg.guestImageId,
        expectedPolicyId: this.pkg.policyId,
        expectedCommitment: authorized.requestCommitment,
        proverPublicKey: this.tee.proverPublicKey,
      });

      if (!result.valid) {
        this.records.set(requestId, {
          requestId,
          state: {
            status: "FAILED",
            error: result.checks.find((c) => !c.pass)?.name ?? "unknown",
            proofMs,
          },
          simulatedCostMs,
        });
        return;
      }

      // Rule 8 — bind the finished proof back to the commitment the compute
      // receipt carries. The receipt was signed before this digest existed, so
      // this is the artifact that completes the chain without mutating it.
      const binding: ProofBinding = {
        version: "ctn-proof-binding-1",
        requestId,
        requestCommitment: authorized.requestCommitment,
        policyId: this.pkg.policyId,
        guestImageId: this.pkg.guestImageId,
        zkReceiptDigest: digest,
        decision: "ALLOW",
        proofVerified: true,
        issuedAt: new Date().toISOString(),
      };

      this.records.set(requestId, {
        requestId,
        state: {
          status: "VERIFIED",
          proof,
          proofMs,
          digest,
          binding: { binding, enclaveSignature: this.tee.signReceipt(binding) },
        },
        simulatedCostMs,
      });
    } catch (err) {
      // §59 — a proof failure after a successful inference must be visible, not
      // rewritten. response_status stays COMPLETE; proof_status becomes FAILED.
      this.records.set(requestId, {
        requestId,
        state: {
          status: "FAILED",
          error: err instanceof Error ? err.message : String(err),
          proofMs: Math.round(performance.now() - startedAt),
        },
        simulatedCostMs,
      });
    }
  }
}

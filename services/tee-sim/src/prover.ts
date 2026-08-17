/**
 * §27, §28 — policy proof generation inside the trust boundary. PHASE 2B: REAL.
 *
 * The proof is now a genuine RISC Zero STARK. The enclave hands the private
 * witness to the `:4500` daemon (`/prove`), polls the job to GENERATED, and then
 * — before it will ever say VERIFIED — runs the REFERENCE `prover/verify`
 * subprocess against the pinned `prover/release.json`. Decoding a receipt is not
 * verifying it: the enclave does not trust a locally-decoded journal, it makes
 * the same offline verifier an independent party would run confirm the STARK and
 * bind the receipt's journal to the gate journal.
 *
 *   REAL here:
 *     - a succinct cryptographic argument (the STARK), verified against a pinned
 *       ImageID with no trust in whoever produced the receipt;
 *     - the journal is bound to the gate's commitment, decision and proofNonce
 *       (`--expect-*`) and to the manifest's policyId / imageId / journalVersion;
 *     - the journal leaks nothing about the prompt (§27): the five allowlist
 *       fields and nothing else.
 *     - an independent TS re-execution still cross-checks the gate verdict, so a
 *       policy-determinism bug fails the proof rather than being papered over.
 *
 *   STILL SIMULATED:
 *     - the enclave itself. The daemon receives the plaintext witness, so the
 *       confidential boundary is `tee-sim` + `prover/host` together, both
 *       simulated. The proof is real; the isolation is not.
 */
import { readFileSync } from "node:fs";
import { evaluate, type PolicyPackage } from "@ctn/policy";
import {
  decisionReceiptDigest as computeDecisionReceiptDigest,
  fromB64,
  randomHex,
  zkArtifactDigest,
  type PolicyDecision,
  type PolicyDecisionReceiptV1,
  type ProofArtifactV1,
  type ProofBindingV2,
  type SignedProofBindingV2,
} from "@ctn/protocol";
import type { TrustedEnvironment } from "./tee.js";
import type { JobStatus } from "./prover-client.js";
import { ProverUnavailableError } from "./prover-client.js";
import { runReferenceVerify, type SubprocessVerification, type VerifierPaths } from "./proof-verify.js";

/**
 * Phase 2b — the private witness a proof is generated over, plus the guest's
 * authoritative verdict AND the signed decision receipt it binds to. Decoupled
 * from `AuthorizedRequest` on purpose: a DENY request has no `AuthorizedRequest`
 * yet is still gated and still proved.
 */
export interface ProofWitness {
  canonicalRequest: string;
  requestNonce: string;
  requestCommitment: string;
  decision: PolicyDecision;
  /** The decision this proof binds to; its digest lands in the ProofBindingV2. */
  decisionReceipt: PolicyDecisionReceiptV1;
}

export type ProofStatus = "QUEUED" | "PROVING" | "GENERATED" | "VERIFIED" | "FAILED";

export type ProofState =
  | { status: "QUEUED"; startedAt: number }
  | { status: "PROVING"; startedAt: number }
  | { status: "GENERATED"; artifact: ProofArtifactV1; artifactDigest: string; proofMs: number }
  | {
      status: "VERIFIED";
      artifact: ProofArtifactV1;
      artifactDigest: string;
      decisionReceiptDigest: string;
      binding: SignedProofBindingV2;
      verification: SubprocessVerification;
      proofMs: number;
    }
  | { status: "FAILED"; error: string; proofMs: number };

export interface ProofRecord {
  requestId: string;
  state: ProofState;
  /** The proofNonce this proof committed (echoed into the journal). */
  proofNonce: string;
}

/** Minimal slice of ProverClient the Prover needs — injectable for tests. */
interface ProveChannel {
  prove(input: {
    canonicalRequestBytes: string;
    requestNonceHex: string;
    proofNonce: string;
  }): Promise<{ jobId: string }>;
  pollJob(jobId: string): Promise<JobStatus>;
}

export interface ProverDeps {
  proverClient: ProveChannel;
  verifierPaths: VerifierPaths;
  /** No proof has a flat wall-clock deadline; this is a generous absolute ceiling. */
  ceilingMs?: number;
  /** How long to wait between polls while QUEUED/PROVING. */
  pollIntervalMs?: number;
  /** Injectable for tests (fixture nonce / deterministic proofNonce). */
  mintProofNonce?: () => string;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** Fired on every state transition (for the coordinator projection / tests). */
  onState?: (requestId: string, status: ProofStatus) => void;
  /** Override the subprocess verifier (tests). Defaults to the real one. */
  runVerify?: typeof runReferenceVerify;
}

interface ReleaseManifest {
  imageIdHex: string;
  policyId: string;
  rulesDigest: string;
  journalVersion: number;
  risc0Version: string;
  receiptCodec: string;
}

const DEFAULT_CEILING_MS = 15 * 60 * 1000; // 15 min — well above the measured max + queue wait.
const DEFAULT_POLL_INTERVAL_MS = 1000;

export class Prover {
  private readonly records = new Map<string, ProofRecord>();
  private readonly manifest: ReleaseManifest;
  private readonly proverClient: ProveChannel;
  private readonly verifierPaths: VerifierPaths;
  private readonly ceilingMs: number;
  private readonly pollIntervalMs: number;
  private readonly mintProofNonce: () => string;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly onState?: (requestId: string, status: ProofStatus) => void;
  private readonly runVerify: typeof runReferenceVerify;

  constructor(
    private readonly tee: TrustedEnvironment,
    private readonly pkg: PolicyPackage,
    deps: ProverDeps
  ) {
    this.proverClient = deps.proverClient;
    this.verifierPaths = deps.verifierPaths;
    this.ceilingMs = deps.ceilingMs ?? DEFAULT_CEILING_MS;
    this.pollIntervalMs = deps.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    this.mintProofNonce = deps.mintProofNonce ?? (() => "0x" + randomHex(16));
    this.now = deps.now ?? (() => performance.now());
    this.sleep = deps.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.onState = deps.onState;
    this.runVerify = deps.runVerify ?? runReferenceVerify;
    // The pinned manifest is the identity the receipt is verified AGAINST, so the
    // artifact reports it (not a self-reported /health value the receipt could
    // disagree with — the subprocess is what ties the receipt to these fields).
    this.manifest = JSON.parse(readFileSync(this.verifierPaths.releasePath, "utf8")) as ReleaseManifest;
  }

  get(requestId: string): ProofRecord | undefined {
    return this.records.get(requestId);
  }

  /**
   * §25 branch A — kicked off the moment the gate returns a verdict and
   * deliberately NOT awaited, so proving overlaps inference. Phase 2b: enqueued
   * for ALLOW AND DENY (and no-capacity) — every gated request is proved.
   */
  start(requestId: string, witness: ProofWitness): void {
    const startedAt = this.now();
    const proofNonce = this.mintProofNonce();
    this.records.set(requestId, {
      requestId,
      state: { status: "QUEUED", startedAt },
      proofNonce,
    });
    this.onState?.(requestId, "QUEUED");
    void this.run(requestId, witness, startedAt, proofNonce);
  }

  private setState(requestId: string, state: ProofState, proofNonce: string): void {
    const prev = this.records.get(requestId)?.state.status;
    this.records.set(requestId, { requestId, state, proofNonce });
    if (prev !== state.status) this.onState?.(requestId, state.status);
  }

  private fail(requestId: string, error: string, startedAt: number, proofNonce: string): void {
    this.setState(
      requestId,
      { status: "FAILED", error, proofMs: Math.round(this.now() - startedAt) },
      proofNonce
    );
  }

  private async run(
    requestId: string,
    witness: ProofWitness,
    startedAt: number,
    proofNonce: string
  ): Promise<void> {
    try {
      // Independent re-execution from the witness. A guest verdict that disagreed
      // with this re-execution is a policy-determinism bug: fail the proof rather
      // than paper over it. Both ALLOW and DENY are proved.
      const parsed = JSON.parse(witness.canonicalRequest) as {
        messages: Array<{ role: string; content: string }>;
      };
      const reexec = evaluate(this.pkg.rules, parsed.messages.map((m) => m.content).join("\n"));
      if (reexec.decision !== witness.decision) {
        this.fail(requestId, "guest re-execution disagreed with the gate verdict (non-determinism)", startedAt, proofNonce);
        return;
      }

      // Enqueue the real prove. The daemon recomputes the commitment in-guest from
      // these exact bytes + nonce, and echoes proofNonce into the journal.
      let jobId: string;
      try {
        ({ jobId } = await this.proverClient.prove({
          canonicalRequestBytes: witness.canonicalRequest,
          requestNonceHex: witness.requestNonce,
          proofNonce,
        }));
      } catch (err) {
        if (err instanceof ProverUnavailableError) {
          this.fail(requestId, "PROVER_UNAVAILABLE: the prover daemon was unreachable at enqueue", startedAt, proofNonce);
          return;
        }
        throw err;
      }

      // Poll to a terminal daemon state. No flat wall-clock deadline: keep polling
      // while QUEUED/PROVING; end only on daemon FAILED, PROVER_UNAVAILABLE, or the
      // generous absolute ceiling. QUEUED time never fails a legitimately-proving job.
      let receiptBytes: Uint8Array;
      for (;;) {
        if (this.now() - startedAt > this.ceilingMs) {
          this.fail(requestId, `proving exceeded the ${Math.round(this.ceilingMs / 60000)}-minute ceiling`, startedAt, proofNonce);
          return;
        }
        let job: JobStatus;
        try {
          job = await this.proverClient.pollJob(jobId);
        } catch (err) {
          if (err instanceof ProverUnavailableError) {
            this.fail(requestId, "PROVER_UNAVAILABLE: the prover daemon became unreachable during proving", startedAt, proofNonce);
            return;
          }
          throw err;
        }

        // A dev-mode daemon can never produce a trustworthy receipt. Reject before
        // the subprocess even runs (which would reject it cryptographically anyway).
        if (job.devMode) {
          this.fail(requestId, "dev-mode receipt rejected (RISC0_DEV_MODE)", startedAt, proofNonce);
          return;
        }

        if (job.status === "QUEUED") {
          this.setState(requestId, { status: "QUEUED", startedAt }, proofNonce);
          await this.sleep(this.pollIntervalMs);
          continue;
        }
        if (job.status === "PROVING") {
          this.setState(requestId, { status: "PROVING", startedAt }, proofNonce);
          await this.sleep(this.pollIntervalMs);
          continue;
        }
        if (job.status === "FAILED") {
          this.fail(requestId, `prover daemon reported FAILED: ${job.error ?? "unknown"}`, startedAt, proofNonce);
          return;
        }
        // GENERATED
        if (!job.receiptB64) {
          this.fail(requestId, "daemon reported GENERATED without a receipt", startedAt, proofNonce);
          return;
        }
        receiptBytes = fromB64(job.receiptB64);
        break;
      }

      // §4 — the artifact reports the PINNED identity the receipt is checked
      // against; the subprocess is what ties the receipt bytes to these fields.
      const decodedJournal = {
        protocolVersion: 1 as const,
        requestCommitment: witness.requestCommitment,
        policyId: this.manifest.policyId,
        decision: witness.decision,
        proofNonce,
      };
      const artifact: ProofArtifactV1 = {
        proofSystem: "risc0",
        risc0Version: this.manifest.risc0Version,
        receiptCodec: "bincode-v1",
        receiptBytes,
        imageId: this.manifest.imageIdHex,
        journalVersion: this.manifest.journalVersion,
        decodedJournal,
      };
      const artifactDigest = zkArtifactDigest(receiptBytes);
      const genMs = Math.round(this.now() - startedAt);
      this.setState(requestId, { status: "GENERATED", artifact, artifactDigest, proofMs: genMs }, proofNonce);

      // DECODING IS NOT VERIFICATION. Spawn the reference verifier against the
      // pinned manifest, binding the decoded journal to the gate journal. Only a
      // clean exit 0 permits VERIFIED / proofVerified:true.
      const verification = await this.runVerify(
        receiptBytes,
        { commitment: witness.requestCommitment, decision: witness.decision, proofNonce },
        this.verifierPaths
      );
      if (!verification.ok) {
        this.fail(
          requestId,
          `server-side verification rejected the proof (${verification.firstFailure ?? "unknown check"})`,
          startedAt,
          proofNonce
        );
        return;
      }

      const decisionReceiptDigest = computeDecisionReceiptDigest(witness.decisionReceipt);
      const binding: ProofBindingV2 = {
        decisionReceiptDigest,
        artifactDigest,
        imageId: this.manifest.imageIdHex,
        policyId: this.manifest.policyId,
        decision: witness.decision,
        proofVerified: true, // only ever set here, AFTER the subprocess passed.
      };
      const signedBinding: SignedProofBindingV2 = {
        binding,
        enclaveSignature: this.tee.signReceipt(binding),
      };

      this.setState(
        requestId,
        {
          status: "VERIFIED",
          artifact,
          artifactDigest,
          decisionReceiptDigest,
          binding: signedBinding,
          verification,
          proofMs: Math.round(this.now() - startedAt),
        },
        proofNonce
      );
    } catch (err) {
      // §59 — a proof failure after a successful inference must be visible, not
      // rewritten. response_status stays COMPLETE; proof_status becomes FAILED.
      this.fail(requestId, err instanceof Error ? err.message : String(err), startedAt, proofNonce);
    }
  }
}

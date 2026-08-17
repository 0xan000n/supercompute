/**
 * Phase 3 — Clio-lite bulletin accumulator (design §6/§7). Runs INSIDE the
 * enclave. It receives ONLY the closed-enum `Facet` and the ALLOW/DENY verdict
 * for each classified request — never the prompt, never any text derived from it
 * (see `classify` in ./classify.ts: the only value that reaches `record` is a
 * `Facet` literal). It keeps per-facet {allow, deny} counters in enclave memory
 * and, on demand, emits a threshold-suppressed, enclave-signed
 * `SignedInsightsBulletinV1`.
 *
 * Window semantics (PoC): counters are CUMULATIVE since enclave boot. There is
 * no reset; `windowRequests` is the total number of requests classified since
 * the process started. A restarted enclave starts from zero — the same
 * in-memory, forgets-on-restart discipline as the replay guard and pending
 * gates. A production design would roll windows and persist to monotonic state.
 */
import {
  canonicalizeInsightsBulletin,
  type Facet,
  type SignedInsightsBulletinV1,
  type UnsignedInsightsBulletinV1,
} from "@ctn/protocol";

interface Tally {
  allow: number;
  deny: number;
}

export interface BuildBulletinOptions {
  /** Threshold suppression floor (design default 5). A facet renders only at >= kMin. */
  kMin: number;
  /** The guest POLICY_ID_V2 the safety facets derive from. */
  policyId: string;
  /** Enclave clock; defaults to now. Injected in tests for a stable canonical form. */
  generatedAt?: string;
  /**
   * Signs the CANONICAL unsigned bulletin. In the enclave this is
   * `tee.signReceipt` (ed25519 over canonicalHash) — the same key and discipline
   * as the receipts. Kept as a callback so the accumulator has no key material
   * and stays unit-testable.
   */
  sign: (canonicalUnsigned: UnsignedInsightsBulletinV1) => string;
}

export class BulletinAccumulator {
  private readonly counts = new Map<Facet, Tally>();
  private total = 0;

  /** Record one classified request. `facet` is the ONLY thing that ever enters. */
  record(facet: Facet, decision: "ALLOW" | "DENY"): void {
    const tally = this.counts.get(facet) ?? { allow: 0, deny: 0 };
    if (decision === "ALLOW") tally.allow += 1;
    else tally.deny += 1;
    this.counts.set(facet, tally);
    this.total += 1;
  }

  /** Total requests classified since boot. */
  get windowRequests(): number {
    return this.total;
  }

  /** A read-only view of the raw per-facet tallies (for tests / introspection). */
  snapshot(): ReadonlyMap<Facet, Readonly<Tally>> {
    return new Map(this.counts);
  }

  /**
   * Assemble the unsigned bulletin with threshold suppression applied:
   *   - a facet with allow + deny >= kMin renders in `facets[]`;
   *   - every other facet folds into `otherCount` and increments
   *     `suppressedFacets` — EXCEPT the natural `other` facet, which is the
   *     fold destination itself (counted in `otherCount`, never a "suppressed
   *     facet"). This keeps the invariant Σ facets + otherCount == windowRequests.
   */
  private assemble(kMin: number, policyId: string, generatedAt: string): UnsignedInsightsBulletinV1 {
    const facets: Array<{ facet: Facet; allow: number; deny: number }> = [];
    let suppressedFacets = 0;
    let otherCount = 0;

    for (const [facet, tally] of this.counts) {
      const total = tally.allow + tally.deny;
      if (facet === "other") {
        // The catch-all bucket: always aggregated into otherCount, never listed.
        otherCount += total;
        continue;
      }
      if (total >= kMin) {
        facets.push({ facet, allow: tally.allow, deny: tally.deny });
      } else {
        // Below threshold: fold the requests into `other`, record the absence.
        suppressedFacets += 1;
        otherCount += total;
      }
    }

    return {
      version: 1,
      generatedAt,
      windowRequests: this.total,
      kMin,
      facets,
      suppressedFacets,
      otherCount,
      policyId,
    };
  }

  /**
   * Build the signed, threshold-suppressed bulletin. The facet array is sorted
   * and counts are asserted integer by `canonicalizeInsightsBulletin`; the
   * signature is taken over that canonical form, so verification (which
   * re-canonicalizes) always matches and re-signing identical counts is
   * byte-identical.
   */
  buildBulletin(opts: BuildBulletinOptions): SignedInsightsBulletinV1 {
    const generatedAt = opts.generatedAt ?? new Date().toISOString();
    const canonical = canonicalizeInsightsBulletin(
      this.assemble(opts.kMin, opts.policyId, generatedAt)
    );
    return { ...canonical, enclaveSignature: opts.sign(canonical) };
  }
}

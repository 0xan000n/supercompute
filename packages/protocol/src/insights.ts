/**
 * Phase 3 — Clio-lite insights bulletin (design §7). The ONLY insights artifact
 * that ever leaves the enclave: closed-enum facet labels and INTEGER aggregate
 * counts, threshold-suppressed and enclave-signed. No prompt, no free text, no
 * per-request facet is ever expressed here — by construction the type cannot
 * carry any (every field is a number, an ISO date, a policy id, or a member of
 * the closed `Facet` enum).
 *
 * The canonicalization + signing discipline matches the receipts: the signature
 * is ed25519 over `canonicalHash(unsigned bulletin)` (see `signCanonical`), with
 * the facet array SORTED and all counts asserted integer so the signed bytes are
 * stable regardless of accumulation order.
 */
import { canonicalHash, signCanonical, verifyCanonical } from "./crypto";

/**
 * The closed, versioned facet enum (design §5). Mirrors
 * `services/tee-sim/src/insights/facets.ts` — the two are the same closed union
 * of string literals and are mutually assignable. Adding a member is a
 * deliberate, labelled change; the enum is never opened to free text.
 */
export type Facet =
  // Safety facets — one per ZK-proven policy category (a DENY's facet).
  | "weapons"
  | "malware_cyber"
  | "phishing_fraud"
  | "violence"
  | "self_harm"
  | "csam"
  // Benign facets — the local keyword classifier over ALLOWED prompts.
  | "coding"
  | "writing"
  | "research"
  | "data_analysis"
  | "education"
  | "business"
  | "creative"
  | "translation"
  | "conversation"
  | "technical_ops"
  // Unclassified / suppressed.
  | "other";

/** One facet's allow/deny tally. Counts are integers. */
export interface InsightsFacetCount {
  facet: Facet;
  allow: number;
  deny: number;
}

/**
 * design §7 — the signed aggregate bulletin. `facets` holds ONLY facets whose
 * total (allow + deny) is >= `kMin`; everything below folds into `otherCount`
 * and is counted by `suppressedFacets` (a visible absence, not a silent drop —
 * threshold suppression, NOT anonymity).
 */
export interface SignedInsightsBulletinV1 {
  version: 1;
  /** Enclave clock, ISO 8601. */
  generatedAt: string;
  /** How many classified requests this bulletin summarizes. */
  windowRequests: number;
  /** The suppression threshold in force (design default 5). */
  kMin: number;
  /** Only facets with allow + deny >= kMin, SORTED by facet id. */
  facets: InsightsFacetCount[];
  /** Count of distinct facets folded into `other` for being below kMin. */
  suppressedFacets: number;
  /** Total requests in the `other` bucket (natural `other` + suppressed folds). */
  otherCount: number;
  /** The guest POLICY_ID_V2 the safety facets are derived from. */
  policyId: string;
  /** ed25519 over canonicalHash(unsigned bulletin), by the enclave signing key. */
  enclaveSignature: string;
}

/** The bulletin minus its signature — the exact value the enclave signs. */
export type UnsignedInsightsBulletinV1 = Omit<SignedInsightsBulletinV1, "enclaveSignature">;

function assertInteger(n: number, field: string): number {
  if (!Number.isInteger(n)) {
    throw new Error(`insights bulletin ${field} must be an integer`);
  }
  return n;
}

/**
 * The canonical form of an unsigned bulletin: facet array sorted by facet id,
 * every count asserted integer (no floats). This is what gets signed, so its
 * byte-form must be a total function of the counts alone — not of insertion
 * order. Object-KEY ordering is handled downstream by `canonicalJson`; this only
 * needs to fix the one thing `canonicalJson` does not: array element order.
 */
export function canonicalizeInsightsBulletin(
  bulletin: UnsignedInsightsBulletinV1
): UnsignedInsightsBulletinV1 {
  return {
    version: 1,
    generatedAt: bulletin.generatedAt,
    windowRequests: assertInteger(bulletin.windowRequests, "windowRequests"),
    kMin: assertInteger(bulletin.kMin, "kMin"),
    facets: bulletin.facets
      .map((f) => ({
        facet: f.facet,
        allow: assertInteger(f.allow, "facet.allow"),
        deny: assertInteger(f.deny, "facet.deny"),
      }))
      .sort((a, b) => (a.facet < b.facet ? -1 : a.facet > b.facet ? 1 : 0)),
    suppressedFacets: assertInteger(bulletin.suppressedFacets, "suppressedFacets"),
    otherCount: assertInteger(bulletin.otherCount, "otherCount"),
    policyId: bulletin.policyId,
  };
}

/** The canonical hash the signature covers — over the sorted, integer form. */
export function insightsBulletinDigest(bulletin: UnsignedInsightsBulletinV1): string {
  return canonicalHash(canonicalizeInsightsBulletin(bulletin));
}

/**
 * Sign an unsigned bulletin with the enclave key and attach the signature.
 * Deterministic: identical counts (and generatedAt/policyId) re-sign to a
 * byte-identical bulletin, because ed25519 over the same canonical hash is
 * deterministic.
 */
export function signInsightsBulletin(
  unsigned: UnsignedInsightsBulletinV1,
  privateKey: Uint8Array
): SignedInsightsBulletinV1 {
  const canonical = canonicalizeInsightsBulletin(unsigned);
  return { ...canonical, enclaveSignature: signCanonical(canonical, privateKey) };
}

/** Verify a signed bulletin against the enclave's public signing key (hex). */
export function verifyInsightsBulletin(
  bulletin: SignedInsightsBulletinV1,
  publicKeyHex: string
): boolean {
  const { enclaveSignature, ...unsigned } = bulletin;
  return verifyCanonical(canonicalizeInsightsBulletin(unsigned), enclaveSignature, publicKeyHex);
}

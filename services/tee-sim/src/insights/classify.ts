/**
 * Phase 3 — Clio-lite local facet classifier (spec §4).
 *
 * PRIVACY / THESIS INVARIANT (Global Constraints):
 *   - Fully local. This function performs NO I/O, NO network, NO model call.
 *   - It runs on the plaintext ALREADY decrypted in the enclave for the gate;
 *     it never triggers a second decrypt or a second /execute.
 *   - It returns ONLY a member of the closed `Facet` enum. The prompt and any
 *     text derived from it are never returned, persisted, logged, or served —
 *     the ONLY value that can escape this function is one of `FACETS` (a fixed
 *     16 + "other" string constants defined in facets.ts). See the `return`
 *     sites below: every one is a `Facet` literal or a lookup into a constant
 *     `Facet` map — none is built from `normalizedPrompt`.
 *
 * The classifier is a HEURISTIC, not an LLM and not an embedding model:
 *   - DENY  → the deciding policy category's facet (the ZK-proven category).
 *   - ALLOW → the benign keyword classifier's best match.
 *   - unclassifiable / ambiguous → "other".
 */

import {
  BENIGN_KEYWORDS,
  CATEGORY_FACET,
  CATEGORY_ORDER,
  type Facet,
} from "./facets.js";

export interface ClassifyInput {
  /** The prompt AFTER `@ctn/policy` `normalize` (reused, not re-implemented). */
  normalizedPrompt: string;
  /** The gate's verdict for this request. */
  decision: "ALLOW" | "DENY";
  /**
   * Per-policy-category scores keyed by category id (P1..P7) — the guest's
   * `privateScores`. Task 2 derives this from the guest journal's `categories`
   * (`{category, score, threshold}[]`) → `{ [category]: score }`.
   */
  categoryScores: Record<string, number>;
  /** Per-category thresholds keyed by category id (P1..P7), same source. */
  categoryThresholds: Record<string, number>;
}

/**
 * Whole-token (space-bounded) match for single-word keywords; phrase substring
 * match for multi-word keywords. Operates on the normalized text, which is
 * already lowercased with punctuation/whitespace collapsed to single spaces.
 */
function keywordHit(normalized: string, keyword: string): boolean {
  const padded = ` ${normalized} `;
  if (keyword.includes(" ")) {
    // Multi-word: the phrase must appear as a run of whole tokens.
    return padded.includes(` ${keyword} `);
  }
  // Single-word: exact token, space-bounded (so "code" ≠ "decode").
  return padded.includes(` ${keyword} `);
}

/**
 * The safety facet for a DENY: the facet of the highest OVER-THRESHOLD policy
 * category. Ties in score are broken deterministically by CATEGORY_ORDER
 * (earlier category wins). If nothing is over threshold, "other".
 */
function safetyFacet(
  categoryScores: Record<string, number>,
  categoryThresholds: Record<string, number>
): Facet {
  let winner: string | null = null;
  let winnerScore = -Infinity;

  for (const category of CATEGORY_ORDER) {
    const score = categoryScores[category];
    const threshold = categoryThresholds[category];
    if (typeof score !== "number" || typeof threshold !== "number") continue;
    if (score < threshold) continue; // only over-threshold categories decide
    // Strictly greater keeps the earliest CATEGORY_ORDER entry on a tie.
    if (score > winnerScore) {
      winnerScore = score;
      winner = category;
    }
  }

  if (winner === null) return "other";
  return CATEGORY_FACET[winner] ?? "other";
}

/**
 * The benign facet for an ALLOW: the keyword facet with the most hits. Ties in
 * hit count are broken by BENIGN_KEYWORDS order (earlier facet wins). No hits →
 * "other".
 */
function benignFacet(normalizedPrompt: string): Facet {
  let winner: Facet = "other";
  let winnerHits = 0;

  for (const [facet, keywords] of BENIGN_KEYWORDS) {
    let hits = 0;
    for (const keyword of keywords) {
      if (keywordHit(normalizedPrompt, keyword)) hits++;
    }
    // Strictly greater keeps the earlier facet on a tie (deterministic).
    if (hits > winnerHits) {
      winnerHits = hits;
      winner = facet;
    }
  }

  return winner;
}

/**
 * Classify one request into a single closed-enum `Facet`. Pure and
 * deterministic: the same input always yields the same facet. Returns ONLY a
 * `Facet` — never the prompt or any text derived from it.
 */
export function classify(input: ClassifyInput): Facet {
  if (input.decision === "DENY") {
    return safetyFacet(input.categoryScores, input.categoryThresholds);
  }
  return benignFacet(input.normalizedPrompt);
}

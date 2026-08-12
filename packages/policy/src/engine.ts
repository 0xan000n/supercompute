/**
 * Safety Policy v1 — deterministic, integer-only scoring engine (§22–23).
 *
 * This is intentionally SMALL, deterministic, and auditable so it can be
 * re-executed inside a ZK guest byte-for-byte. It is NOT a production
 * moderation model. UI must say "Verified against Safety Policy v1",
 * never "cryptographically proven safe".
 *
 * Decision model (per category P1..P7):
 *   score = Σ target-feature weights (matched in this category)
 *         + intentBonus       (if an instructional-intent phrase is present)
 *         + constructionBonus (if a construction verb is present)
 *         + Σ context modifiers (benign/fiction/history/education/defense; negative)
 *   score is clamped to >= 0.
 * A category DENIES when score >= its threshold.
 * A "hardBlock" feature denies immediately regardless of context (e.g. CSAM).
 *
 * Requiring intent/construction alongside a harmful target is what lets benign
 * discussion of dangerous subjects ALLOW while actionable requests DENY.
 */

export type PolicyDecision = "ALLOW" | "DENY";

export interface PolicyRules {
  version: string;
  normalizer: string;
  intentBonus: number;
  constructionBonus: number;
  intentPhrases: string[];
  constructionVerbs: string[];
  /**
   * Phrases that void all context reductions. A request that explicitly asks for
   * the *real* / *actual* operational detail cannot buy leniency by wrapping
   * itself in "for my novel" or "for educational purposes".
   */
  modifierSuppressors: string[];
  categories: Record<string, { name: string; threshold: number }>;
  targets: Array<{ id: string; category: string; weight: number; phrases: string[] }>;
  hardBlocks: Array<{ id: string; category: string; phrases: string[] }>;
  modifiers: Array<{ id: string; weight: number; phrases: string[] }>;
}

export interface CategoryScore {
  category: string;
  name: string;
  score: number;
  threshold: number;
  matchedTargets: string[];
}

/** Full evaluation trace — used only in local/dev debugging, never in prod journals/graph. */
export interface PolicyEvaluation {
  decision: PolicyDecision;
  categories: CategoryScore[];
  intentPresent: boolean;
  constructionPresent: boolean;
  hardBlock?: string;
  modifiersApplied: string[];
}

/**
 * §23 normalizer: NFKC compatibility fold, lowercase, strip zero-width,
 * fold leetspeak, collapse punctuation/whitespace. NFKC (not NFC) is used here
 * so fullwidth and other compatibility-equivalent forms cannot be used to
 * smuggle a blocked phrase past the matcher. Request *canonicalization* still
 * uses NFC — these are two separate, independently versioned steps.
 */
export function normalize(text: string): string {
  let t = text.normalize("NFKC").toLowerCase();
  // strip zero-width chars and joiners often used to split blocked phrases
  t = t.replace(/[​-‏⁠﻿]/g, "");
  // deterministic leetspeak folding
  t = t
    .replace(/@/g, "a")
    .replace(/\$/g, "s")
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t");
  // collapse any run of whitespace/punctuation/symbols to a single space
  t = t.replace(/[\s\p{P}\p{S}]+/gu, " ").trim();
  return t;
}

interface Corpus {
  padded: string;
  tokens: Set<string>;
  /** all separators removed — defeats "p i p e b o m b" style spacing attacks */
  squashed: string;
}

function buildCorpus(text: string): Corpus {
  return {
    padded: " " + text + " ",
    tokens: new Set(text.split(" ").filter(Boolean)),
    squashed: text.split(" ").join(""),
  };
}

/** Squashed matching is substring matching, so it is gated to long needles only. */
const SQUASH_MIN = 8;

/**
 * Deterministic token-aware match.
 * - Multi-word needle: whole-phrase, space-bounded (optional plural 's').
 * - Single-word needle: exact token, or token-prefix when needle length >= 4
 *   (so "kill" matches "killing"/"kills" but "skill" never matches "kill").
 * - Additionally, needles whose separator-free form is >= 8 chars are matched
 *   against the separator-free text, catching inserted spaces/punctuation.
 */
function match(corpus: Corpus, needleRaw: string): boolean {
  const n = normalize(needleRaw);
  if (n.length === 0) return false;

  if (n.includes(" ")) {
    if (corpus.padded.includes(" " + n + " ")) return true;
    if (corpus.padded.includes(" " + n + "s ")) return true;
  } else {
    if (corpus.tokens.has(n)) return true;
    if (n.length >= 4) {
      for (const tok of corpus.tokens) {
        if (tok.startsWith(n)) return true;
      }
    }
  }

  const squashedNeedle = n.split(" ").join("");
  if (squashedNeedle.length >= SQUASH_MIN && corpus.squashed.includes(squashedNeedle)) {
    return true;
  }
  return false;
}

export function evaluate(rules: PolicyRules, rawText: string): PolicyEvaluation {
  const corpus = buildCorpus(normalize(rawText));

  // Hard blocks: immediate DENY (e.g. P5 sexual exploitation of minors).
  for (const hb of rules.hardBlocks) {
    for (const p of hb.phrases) {
      if (match(corpus, p)) {
        return {
          decision: "DENY",
          categories: [],
          intentPresent: false,
          constructionPresent: false,
          hardBlock: hb.id,
          modifiersApplied: [],
        };
      }
    }
  }

  const intentPresent = rules.intentPhrases.some((p) => match(corpus, p));
  const constructionPresent = rules.constructionVerbs.some((p) => match(corpus, p));

  // A request that demands the *real* operational detail forfeits context leniency.
  const suppressed = rules.modifierSuppressors.some((p) => match(corpus, p));

  let modifierTotal = 0;
  const modifiersApplied: string[] = [];
  if (!suppressed) {
    for (const m of rules.modifiers) {
      if (m.phrases.some((p) => match(corpus, p))) {
        modifierTotal += m.weight; // weights are negative
        modifiersApplied.push(m.id);
      }
    }
  }

  const categories: CategoryScore[] = [];
  let decision: PolicyDecision = "ALLOW";

  for (const [cat, meta] of Object.entries(rules.categories)) {
    let score = 0;
    const matchedTargets: string[] = [];
    for (const tgt of rules.targets) {
      if (tgt.category !== cat) continue;
      if (tgt.phrases.some((p) => match(corpus, p))) {
        score += tgt.weight;
        matchedTargets.push(tgt.id);
      }
    }
    if (matchedTargets.length > 0) {
      if (intentPresent) score += rules.intentBonus;
      if (constructionPresent) score += rules.constructionBonus;
      score += modifierTotal; // context reductions
    }
    if (score < 0) score = 0;
    categories.push({
      category: cat,
      name: meta.name,
      score,
      threshold: meta.threshold,
      matchedTargets,
    });
    if (score >= meta.threshold) decision = "DENY";
  }

  return { decision, categories, intentPresent, constructionPresent, modifiersApplied };
}

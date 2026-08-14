//! The scoring engine — a port of `packages/policy/src/engine.ts:87-202`.
//!
//! Decision model (per category P1..P7), from engine.ts:9-19:
//!   score = Σ target-feature weights matched in this category
//!         + intentBonus       (if an instructional-intent phrase is present)
//!         + constructionBonus (if a construction verb is present)
//!         + Σ context modifiers (benign/fiction/history/education/defense; negative)
//!   score is clamped to >= 0; a category DENIES when score >= its threshold.
//! A `hardBlock` feature denies immediately regardless of context.

use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::normalize::normalize;
use crate::prepared::{Needle, NeedleShape, PreparedRules};
use crate::rules::PolicyRules;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    /// The two strings the journal and the verifier allowlist use. Spelled here
    /// once so the guest cannot invent a third.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
        }
    }
}

/// engine.ts:43-49. Field order is the TS object-literal order (engine.ts:191-197)
/// so that a serialized `CategoryScore` is key-for-key comparable with the TS one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryScore {
    pub category: String,
    pub name: String,
    pub score: i64,
    pub threshold: i64,
    pub matched_targets: Vec<String>,
}

/// engine.ts:52-59 (`PolicyEvaluation`).
///
/// The field order and the `skip_serializing_if` together reproduce both TS
/// return shapes exactly: the hard-block return (engine.ts:143-150) emits
/// decision, categories, intentPresent, constructionPresent, hardBlock,
/// modifiersApplied; the normal return (engine.ts:201) omits `hardBlock`
/// entirely, leaving the same order minus that key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evaluation {
    pub decision: Decision,
    pub categories: Vec<CategoryScore>,
    pub intent_present: bool,
    pub construction_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_block: Option<String>,
    pub modifiers_applied: Vec<String>,
}

/// One chat message, as `packages/policy/src/index.ts:81` sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

/// engine.ts:87-100.
pub(crate) struct Corpus {
    pub padded: String,
    /// The TS uses a JS `Set`, iterated only to answer "does any token start
    /// with this needle" — an order-independent question, so the container's
    /// order is not part of the contract. `BTreeSet` rather than `HashSet`
    /// because the guest gets no entropy for `RandomState` and this crate must
    /// stay deterministic top to bottom — and, given the ordering exists
    /// anyway, because it turns that prefix question into a range seek instead
    /// of a full scan (see `any_token_starts_with`).
    pub tokens: BTreeSet<String>,
    /// All separators removed — defeats "p i p e b o m b" style spacing attacks.
    pub squashed: String,
}

impl Corpus {
    pub(crate) fn build(text: &str) -> Corpus {
        Corpus {
            padded: format!(" {text} "),
            tokens: text
                .split(' ')
                .filter(|t| !t.is_empty()) // JS `.filter(Boolean)`
                .map(str::to_owned)
                .collect(),
            // `text.split(" ").join("")` — the text is already normalized, so
            // U+0020 is the only separator it can contain.
            squashed: text.replace(' ', ""),
        }
    }
}

/// Does any token in the corpus have `needle` as a prefix?
///
/// The TS scans the whole token set (engine.ts:126). `tokens` is a `BTreeSet`,
/// so instead: seek to the first token `>= needle` and test only that one. That
/// is sufficient, not merely a heuristic. Suppose some token starts with
/// `needle`, and let `t0` be the smallest such. Any token `u` with
/// `needle <= u < t0` cannot itself start with `needle` (or `t0` would not be
/// the smallest) — but then `u` differs from `needle` at some position `i`
/// inside `needle`, with `u[i] > needle[i]` since `u > needle`, which makes
/// every string beginning with `needle` — `t0` included — strictly less than
/// `u`. That contradicts `u < t0`. So no such `u` exists and `t0` is exactly
/// the first element of the range.
///
/// Byte order and byte prefixes are the right comparisons here: both sides are
/// output of the same normalizer, so a Rust `starts_with` (byte prefix) and a
/// JS `startsWith` (UTF-16 code unit prefix) accept exactly the same pairs.
pub(crate) fn any_token_starts_with(corpus: &Corpus, needle: &str) -> bool {
    corpus
        .tokens
        .range::<str, _>((Bound::Included(needle), Bound::Unbounded))
        .next()
        .is_some_and(|tok| tok.starts_with(needle))
}

/// Deterministic token-aware match (engine.ts:105-134), against a needle whose
/// normalization was hoisted out (see [`crate::prepared`]).
///
/// - Multi-word needle: whole-phrase, space-bounded (optional plural 's').
/// - Single-word needle: exact token, or token-prefix when the needle is >= 4
///   long (so "kill" matches "killing"/"kills" but "skill" never matches "kill").
/// - Additionally, needles whose separator-free form is >= SQUASH_MIN are
///   matched against the separator-free text, catching inserted separators.
///   Note this is a fallthrough, not an `else`: a multi-word needle that fails
///   the phrase test still gets the squashed test.
pub(crate) fn match_prepared(corpus: &Corpus, needle: &Needle) -> bool {
    // `n.length === 0`
    if needle.normalized.is_empty() {
        return false;
    }

    match &needle.shape {
        NeedleShape::Phrase {
            padded,
            padded_plural,
        } => {
            if corpus.padded.contains(padded.as_str()) {
                return true;
            }
            if corpus.padded.contains(padded_plural.as_str()) {
                return true;
            }
        }
        NeedleShape::Token { prefix_eligible } => {
            if corpus.tokens.contains(needle.normalized.as_str()) {
                return true;
            }
            if *prefix_eligible && any_token_starts_with(corpus, &needle.normalized) {
                return true;
            }
        }
    }

    if let Some(squashed) = &needle.squashed {
        if corpus.squashed.contains(squashed.as_str()) {
            return true;
        }
    }
    false
}

/// `match_prepared` from a raw phrase — the shape engine.ts:105 has. Used by the
/// unit tests; the engine itself prepares once and matches many times.
#[cfg(test)]
pub(crate) fn match_needle(corpus: &Corpus, needle_raw: &str) -> bool {
    match_prepared(corpus, &Needle::prepare(needle_raw))
}

fn any_match(corpus: &Corpus, needles: &[Needle]) -> bool {
    needles.iter().any(|n| match_prepared(corpus, n))
}

/// engine.ts:136-202, on rules whose phrases are already normalized.
///
/// This is the entry point the guest uses: `PreparedRules` is baked into the
/// image, so the zkVM never normalizes a rules phrase.
pub fn evaluate_prepared(rules: &PreparedRules, raw_text: &str) -> Evaluation {
    let corpus = Corpus::build(&normalize(raw_text));

    // Hard blocks: immediate DENY (e.g. P5 sexual exploitation of minors).
    for hb in &rules.hard_blocks {
        for p in &hb.phrases {
            if match_prepared(&corpus, p) {
                return Evaluation {
                    decision: Decision::Deny,
                    categories: Vec::new(),
                    intent_present: false,
                    construction_present: false,
                    hard_block: Some(hb.id.clone()),
                    modifiers_applied: Vec::new(),
                };
            }
        }
    }

    let intent_present = any_match(&corpus, &rules.intent_phrases);
    let construction_present = any_match(&corpus, &rules.construction_verbs);

    // A request that demands the *real* operational detail forfeits context
    // leniency (engine.ts:158-159).
    let suppressed = any_match(&corpus, &rules.modifier_suppressors);

    let mut modifier_total: i64 = 0;
    let mut modifiers_applied: Vec<String> = Vec::new();
    if !suppressed {
        for m in &rules.modifiers {
            if any_match(&corpus, &m.phrases) {
                modifier_total += m.weight; // weights are negative
                modifiers_applied.push(m.id.clone());
            }
        }
    }

    let mut categories: Vec<CategoryScore> = Vec::with_capacity(rules.categories.len());
    let mut decision = Decision::Allow;

    // Insertion order of `rules.categories`, matching `Object.entries` — the
    // order of this vector is part of the contract.
    for (cat, meta) in &rules.categories {
        let mut score: i64 = 0;
        let mut matched_targets: Vec<String> = Vec::new();
        // `rules.targets` array order, filtered by category.
        for tgt in &rules.targets {
            if tgt.category != *cat {
                continue;
            }
            if any_match(&corpus, &tgt.phrases) {
                score += tgt.weight;
                matched_targets.push(tgt.id.clone());
            }
        }
        if !matched_targets.is_empty() {
            if intent_present {
                score += rules.intent_bonus;
            }
            if construction_present {
                score += rules.construction_bonus;
            }
            score += modifier_total; // context reductions
        }
        score = score.max(0);
        let denies = score >= meta.threshold;
        categories.push(CategoryScore {
            category: cat.clone(),
            name: meta.name.clone(),
            score,
            threshold: meta.threshold,
            matched_targets,
        });
        if denies {
            decision = Decision::Deny;
        }
    }

    Evaluation {
        decision,
        categories,
        intent_present,
        construction_present,
        hard_block: None,
        modifiers_applied,
    }
}

/// engine.ts:136-202, preparing the rules on the way in.
///
/// The native entry point: the differential shim, the fixture tests and the
/// engine's own unit tests all call this, so the property they check is a
/// property of the same code path the guest runs — `evaluate_prepared` — with
/// the hoist done eagerly rather than at build time. Callers that evaluate many
/// requests against one ruleset should prepare once and call
/// [`evaluate_prepared`] instead.
pub fn evaluate(rules: &PolicyRules, raw_text: &str) -> Evaluation {
    evaluate_prepared(&PreparedRules::prepare(rules), raw_text)
}

/// Extract the text a policy evaluates: the concatenation of all message
/// contents (`packages/policy/src/index.ts:81-83`).
pub fn request_text(messages: &[Message]) -> String {
    request_text_from(messages.iter().map(|m| m.content.as_str()))
}

/// The same join, over any iterator of contents. `CanonicalRequestV1` carries
/// its own message type, and one implementation of "join the contents with a
/// newline" is the only way that stays true to index.ts:81-83.
pub(crate) fn request_text_from<'a>(contents: impl Iterator<Item = &'a str>) -> String {
    contents.collect::<Vec<_>>().join("\n")
}

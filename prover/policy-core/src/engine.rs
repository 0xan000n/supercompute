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

use serde::{Deserialize, Serialize};

use crate::normalize::normalize;
use crate::rules::PolicyRules;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allow,
    Deny,
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
    /// stay deterministic top to bottom.
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

/// Squashed matching is substring matching, so it is gated to long needles only
/// (engine.ts:103).
const SQUASH_MIN: usize = 8;

/// JS `String.prototype.length` counts UTF-16 code units — not characters, and
/// not bytes. Every needle in rules.json is ASCII, where all three agree, but
/// the gates below are JS gates and must stay JS gates for any needle.
fn js_length(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Deterministic token-aware match (engine.ts:105-134).
///
/// - Multi-word needle: whole-phrase, space-bounded (optional plural 's').
/// - Single-word needle: exact token, or token-prefix when the needle is >= 4
///   long (so "kill" matches "killing"/"kills" but "skill" never matches "kill").
/// - Additionally, needles whose separator-free form is >= SQUASH_MIN are
///   matched against the separator-free text, catching inserted separators.
///   Note this is a fallthrough, not an `else`: a multi-word needle that fails
///   the phrase test still gets the squashed test.
pub(crate) fn match_needle(corpus: &Corpus, needle_raw: &str) -> bool {
    let n = normalize(needle_raw);
    // `n.length === 0`
    if n.is_empty() {
        return false;
    }

    if n.contains(' ') {
        if corpus.padded.contains(&format!(" {n} ")) {
            return true;
        }
        if corpus.padded.contains(&format!(" {n}s ")) {
            return true;
        }
    } else {
        if corpus.tokens.contains(&n) {
            return true;
        }
        // Both sides are the output of the same normalizer, so a Rust
        // `starts_with` (byte prefix) and a JS `startsWith` (UTF-16 code unit
        // prefix) accept exactly the same pairs.
        if js_length(&n) >= 4 && corpus.tokens.iter().any(|tok| tok.starts_with(&n)) {
            return true;
        }
    }

    let squashed_needle = n.replace(' ', "");
    if js_length(&squashed_needle) >= SQUASH_MIN && corpus.squashed.contains(&squashed_needle) {
        return true;
    }
    false
}

/// engine.ts:136-202.
pub fn evaluate(rules: &PolicyRules, raw_text: &str) -> Evaluation {
    let corpus = Corpus::build(&normalize(raw_text));

    // Hard blocks: immediate DENY (e.g. P5 sexual exploitation of minors).
    for hb in &rules.hard_blocks {
        for p in &hb.phrases {
            if match_needle(&corpus, p) {
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

    let intent_present = rules
        .intent_phrases
        .iter()
        .any(|p| match_needle(&corpus, p));
    let construction_present = rules
        .construction_verbs
        .iter()
        .any(|p| match_needle(&corpus, p));

    // A request that demands the *real* operational detail forfeits context
    // leniency (engine.ts:158-159).
    let suppressed = rules
        .modifier_suppressors
        .iter()
        .any(|p| match_needle(&corpus, p));

    let mut modifier_total: i64 = 0;
    let mut modifiers_applied: Vec<String> = Vec::new();
    if !suppressed {
        for m in &rules.modifiers {
            if m.phrases.iter().any(|p| match_needle(&corpus, p)) {
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
            if tgt.phrases.iter().any(|p| match_needle(&corpus, p)) {
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

/// Extract the text a policy evaluates: the concatenation of all message
/// contents (`packages/policy/src/index.ts:81-83`).
pub fn request_text(messages: &[Message]) -> String {
    messages
        .iter()
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

//! Needles, normalized once instead of once per match.
//!
//! `match` in the TypeScript engine (engine.ts:105) starts by calling
//! `normalize(needle)` on the raw phrase out of `rules.json`. That is correct
//! and it is also the single most expensive thing the engine does: NFKC folding
//! plus a full-Unicode lowercase plus a character walk, repeated for every
//! phrase on every evaluation, for a set of phrases that never changes.
//!
//! Nothing about that work depends on the request, so it is hoisted here. A
//! [`Needle`] is the *result* of `normalize(phrase)` plus the three derived
//! forms the matcher actually consults — the space-padded phrase, its plural,
//! and the separator-free form — decided once. [`PreparedRules`] is
//! `PolicyRules` with every phrase replaced by its `Needle`.
//!
//! This is a pure hoist: [`crate::evaluate`] still takes a `PolicyRules` and
//! prepares it internally, so its answers are unchanged, and the differential
//! harness (`scripts/differential-test.ts`) is what keeps that claim honest.
//! The point of the split is that `PreparedRules` is `Serialize`, so the guest
//! build (`prover/methods/guest/build.rs`) can bake the *prepared* form into the
//! image and the zkVM never runs a normalizer over a rules phrase at all. In the
//! guest, cycles are money.

use serde::{Deserialize, Serialize};

use crate::normalize::normalize;
use crate::rules::{CategoryMeta, PolicyRules};

/// Squashed matching is substring matching, so it is gated to long needles only
/// (engine.ts:103).
pub(crate) const SQUASH_MIN: usize = 8;

/// JS `String.prototype.length` counts UTF-16 code units — not characters, and
/// not bytes. Every needle in rules.json is ASCII, where all three agree, but
/// the gates below are JS gates and must stay JS gates for any needle.
fn js_length(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Which of the two matching modes at engine.ts:115-131 a needle takes.
///
/// The branch is chosen by `n.includes(" ")` on the *normalized* needle, which
/// is a property of the needle alone — so it, and the strings each branch
/// searches for, are decided here rather than per match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NeedleShape {
    /// Multi-word: whole-phrase, space-bounded, with an optional trailing "s"
    /// (engine.ts:116-119).
    Phrase {
        /// `" " + n + " "`.
        padded: String,
        /// `" " + n + "s "`.
        padded_plural: String,
    },
    /// Single-word: exact token, plus token-prefix when the needle is >= 4 long
    /// — so "kill" matches "killing"/"kills" but "skill" never matches "kill"
    /// (engine.ts:121-129).
    Token { prefix_eligible: bool },
}

/// One rules phrase, normalized and decomposed into the forms the matcher uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Needle {
    /// `normalize(raw)`. Empty means "never matches" (engine.ts:113).
    pub(crate) normalized: String,
    pub(crate) shape: NeedleShape,
    /// The separator-free form, present only when it is >= [`SQUASH_MIN`] long
    /// (engine.ts:132). `None` means the squashed fallback does not apply.
    pub(crate) squashed: Option<String>,
}

impl Needle {
    /// Everything engine.ts:105-133 computes from the needle, computed once.
    pub fn prepare(raw: &str) -> Needle {
        let n = normalize(raw);
        let shape = if n.contains(' ') {
            NeedleShape::Phrase {
                padded: format!(" {n} "),
                padded_plural: format!(" {n}s "),
            }
        } else {
            NeedleShape::Token {
                prefix_eligible: js_length(&n) >= 4,
            }
        };
        let squashed_needle = n.replace(' ', "");
        let squashed = if js_length(&squashed_needle) >= SQUASH_MIN {
            Some(squashed_needle)
        } else {
            None
        };
        Needle {
            normalized: n,
            shape,
            squashed,
        }
    }

    fn prepare_all(raws: &[String]) -> Vec<Needle> {
        raws.iter().map(|p| Needle::prepare(p)).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedTarget {
    pub(crate) id: String,
    pub(crate) category: String,
    pub(crate) weight: i64,
    pub(crate) phrases: Vec<Needle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedHardBlock {
    pub(crate) id: String,
    pub(crate) phrases: Vec<Needle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedModifier {
    pub(crate) id: String,
    pub(crate) weight: i64,
    pub(crate) phrases: Vec<Needle>,
}

/// `PolicyRules` with every phrase pre-normalized.
///
/// Two fields of `PolicyRules` are deliberately absent: `version` and
/// `normalizer` are metadata that `evaluate` never reads, and the policy
/// identity they belong to is bound by `POLICY_ID_V2` / `RULES_DIGEST` over the
/// *raw* `rules.json` bytes instead. `HardBlock::category` is dropped for the
/// same reason — engine.ts:143-150 denies without attributing a category.
///
/// `categories` is a `Vec` of pairs rather than an `IndexMap` because the only
/// thing the engine asks of it is "iterate in the JSON's insertion order", which
/// a `Vec` gives directly and which postcard round-trips without needing
/// `IndexMap`'s map encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedRules {
    pub(crate) intent_bonus: i64,
    pub(crate) construction_bonus: i64,
    pub(crate) intent_phrases: Vec<Needle>,
    pub(crate) construction_verbs: Vec<Needle>,
    pub(crate) modifier_suppressors: Vec<Needle>,
    pub(crate) categories: Vec<(String, CategoryMeta)>,
    pub(crate) targets: Vec<PreparedTarget>,
    pub(crate) hard_blocks: Vec<PreparedHardBlock>,
    pub(crate) modifiers: Vec<PreparedModifier>,
}

impl PreparedRules {
    pub fn prepare(rules: &PolicyRules) -> PreparedRules {
        PreparedRules {
            intent_bonus: rules.intent_bonus,
            construction_bonus: rules.construction_bonus,
            intent_phrases: Needle::prepare_all(&rules.intent_phrases),
            construction_verbs: Needle::prepare_all(&rules.construction_verbs),
            modifier_suppressors: Needle::prepare_all(&rules.modifier_suppressors),
            categories: rules
                .categories
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            targets: rules
                .targets
                .iter()
                .map(|t| PreparedTarget {
                    id: t.id.clone(),
                    category: t.category.clone(),
                    weight: t.weight,
                    phrases: Needle::prepare_all(&t.phrases),
                })
                .collect(),
            hard_blocks: rules
                .hard_blocks
                .iter()
                .map(|h| PreparedHardBlock {
                    id: h.id.clone(),
                    phrases: Needle::prepare_all(&h.phrases),
                })
                .collect(),
            modifiers: rules
                .modifiers
                .iter()
                .map(|m| PreparedModifier {
                    id: m.id.clone(),
                    weight: m.weight,
                    phrases: Needle::prepare_all(&m.phrases),
                })
                .collect(),
        }
    }
}

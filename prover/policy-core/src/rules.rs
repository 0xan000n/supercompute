//! The rules document — a 1:1 mirror of the `PolicyRules` interface at
//! `packages/policy/src/engine.ts:24-41`, deserialized from `policy/v1/rules.json`.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// `packages/policy/src/engine.ts:24-41`.
///
/// Every weight, bonus and threshold is an integer (`i64`, not `f64`): the
/// engine is documented as "deterministic, integer-only" (engine.ts:2), and the
/// guest must not carry a float path. A rules.json that grew a fractional weight
/// would fail to deserialize here rather than silently diverge from the TS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRules {
    pub version: String,
    pub normalizer: String,
    pub intent_bonus: i64,
    pub construction_bonus: i64,
    pub intent_phrases: Vec<String>,
    pub construction_verbs: Vec<String>,
    /// Phrases that void all context reductions (engine.ts:31-36).
    pub modifier_suppressors: Vec<String>,
    /// `IndexMap`, not `HashMap`/`BTreeMap`: engine.ts:175 iterates
    /// `Object.entries(rules.categories)` — i.e. the JSON's insertion order —
    /// and that order is the order of `Evaluation::categories`. Sorting or
    /// hashing here would silently reorder the output vector.
    pub categories: IndexMap<String, CategoryMeta>,
    pub targets: Vec<Target>,
    pub hard_blocks: Vec<HardBlock>,
    pub modifiers: Vec<Modifier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryMeta {
    pub name: String,
    pub threshold: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub category: String,
    pub weight: i64,
    pub phrases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardBlock {
    pub id: String,
    /// Carried for parity with the TS interface; `evaluate` never reads it —
    /// a hard block denies without attributing a category (engine.ts:143-150).
    pub category: String,
    pub phrases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Modifier {
    pub id: String,
    /// Negative (engine.ts:166).
    pub weight: i64,
    pub phrases: Vec<String>,
}

impl PolicyRules {
    /// Parse `policy/v1/rules.json`. The caller owns the bytes, because the
    /// policy id is a hash over the exact bytes read, not over a re-encoding.
    pub fn from_json_str(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

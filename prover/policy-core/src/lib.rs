//! Safety Policy v1 — the authoritative Rust engine.
//!
//! This is a deliberate, line-for-line port of `packages/policy/src/engine.ts`
//! (plus `requestText` from `packages/policy/src/index.ts:81-83`). It is the
//! crate that will run inside the zkVM guest, so the only property that matters
//! is that it agrees with the TypeScript engine on every input — not that it is
//! faster, tidier or more correct in isolation. Where JS and Rust semantics
//! differ (case folding, `\s`, string length units) the comments name the
//! divergence and the port follows JS; `prover/differential` is the harness that
//! keeps that claim honest.
//!
//! Do not "fix" a behaviour on one side only. A rule change means changing
//! `policy/v1/rules.json`; an engine change means changing both engines in the
//! same commit, and bumping the policy version.

mod engine;
mod normalize;
mod rules;

pub use engine::{evaluate, request_text, CategoryScore, Decision, Evaluation, Message};
pub use normalize::normalize;
pub use rules::{CategoryMeta, HardBlock, Modifier, PolicyRules, Target};

#[cfg(test)]
mod engine_test;

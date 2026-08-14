//! The Rust side of the fixture corpus: `policy/v1/fixtures/{allow,deny,adversarial}/*.json`
//! run through this crate's engine, asserting the ground-truth label.
//!
//! This is the *ground-truth* half of the story and it stands alone: it proves
//! the port agrees with the labelled corpus even if nobody ever runs Node. The
//! *equivalence* half — that the port agrees with `packages/policy/src/engine.ts`
//! field-for-field, on these same fixtures and on generated Unicode adversarial
//! input — lives in `scripts/differential-test.ts`, which drives this crate
//! through `src/bin/policy_shim.rs`. Both are CI-blocking; neither replaces the
//! other. A change that broke the port in a way the corpus does not label would
//! pass here and fail there, and vice versa.
//!
//! Spec §35 requires >= 50 allow, >= 50 deny, >= 25 adversarial; those minimums
//! are asserted here too, so deleting fixtures cannot quietly shrink the corpus.

use std::fs;
use std::path::{Path, PathBuf};

use policy_core::{evaluate, request_text, Decision, Message, PolicyRules};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    expected: String,
    #[allow(dead_code)]
    description: String,
    request: FixtureRequest,
}

#[derive(Debug, Deserialize)]
struct FixtureRequest {
    #[allow(dead_code)]
    model: String,
    messages: Vec<Message>,
}

/// `prover/policy-core` -> repo root. Same relative walk the crate's own
/// `rules.json` test does; the library never reads a path of its own.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("policy-core lives two levels below the repo root")
        .to_path_buf()
}

fn load_bucket(bucket: &str) -> Vec<Fixture> {
    let dir = repo_root().join("policy/v1/fixtures").join(bucket);
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|e| e.expect("readable dir entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    // Sorted so a failure list is stable run to run.
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let raw = fs::read_to_string(p).unwrap_or_else(|e| panic!("cannot read {p:?}: {e}"));
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("cannot parse {p:?}: {e}"))
        })
        .collect()
}

fn load_rules() -> PolicyRules {
    let path = repo_root().join("policy/v1/rules.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read rules: {e}"));
    PolicyRules::from_json_str(&raw).expect("policy/v1/rules.json should parse")
}

fn check(rules: &PolicyRules, fixtures: &[Fixture], failures: &mut Vec<String>) {
    for f in fixtures {
        let expected = match f.expected.as_str() {
            "ALLOW" => Decision::Allow,
            "DENY" => Decision::Deny,
            other => panic!("{}: unknown expected label {other:?}", f.id),
        };
        let ev = evaluate(rules, &request_text(&f.request.messages));
        if ev.decision != expected {
            // The scoring detail is what makes a failure diagnosable rather
            // than merely red: which categories matched, and by how much.
            let scored: Vec<String> = ev
                .categories
                .iter()
                .filter(|c| !c.matched_targets.is_empty())
                .map(|c| {
                    format!(
                        "{}={}/{}[{}]",
                        c.category,
                        c.score,
                        c.threshold,
                        c.matched_targets.join("+")
                    )
                })
                .collect();
            failures.push(format!(
                "{} expected={:?} got={:?} intent={} constr={} hardBlock={:?} mods=[{}] {}",
                f.id,
                expected,
                ev.decision,
                ev.intent_present,
                ev.construction_present,
                ev.hard_block,
                ev.modifiers_applied.join(","),
                scored.join(" ")
            ));
        }
    }
}

#[test]
fn every_fixture_evaluates_to_its_expected_decision() {
    let rules = load_rules();
    let allow = load_bucket("allow");
    let deny = load_bucket("deny");
    let adversarial = load_bucket("adversarial");
    // Counts are guarded by `the_corpus_is_exactly_fifty_fifty_twentyfive` below.

    let mut failures = Vec::new();
    check(&rules, &allow, &mut failures);
    check(&rules, &deny, &mut failures);
    check(&rules, &adversarial, &mut failures);

    let total = allow.len() + deny.len() + adversarial.len();
    assert!(
        failures.is_empty(),
        "{}/{} fixtures disagree with their ground-truth label:\n{}",
        failures.len(),
        total,
        failures.join("\n")
    );
}

/// Spec §35 sets minimums (>=50 / >=50 / >=25). Three documents go further and
/// state the *exact* total — "all 125 fixtures" — next to measurements taken over
/// that corpus, so the number is a published fact and not just a floor. This test
/// is what pins it: growing the corpus must be a deliberate edit that updates the
/// documents in the same commit, not a silent drift that leaves three READMEs
/// describing a corpus that no longer exists.
#[test]
fn the_corpus_is_exactly_fifty_fifty_twentyfive() {
    let allow = load_bucket("allow").len();
    let deny = load_bucket("deny").len();
    let adversarial = load_bucket("adversarial").len();

    let counts = [
        ("allow", allow, 50),
        ("deny", deny, 50),
        ("adversarial", adversarial, 25),
    ];
    for (bucket, got, want) in counts {
        assert_eq!(
            got, want,
            "policy/v1/fixtures/{bucket} holds {got} fixtures, not {want}. If the corpus \
             changed on purpose, update this assertion AND the three documents that quote \
             the total: prover/README.md, VALIDATION.md and the root README.md (all say \
             \"125 fixtures\", and the corpus benchmark tables are measured over exactly \
             that set)."
        );
    }
    assert_eq!(
        allow + deny + adversarial,
        125,
        "the corpus total moved; see the per-bucket message above for what to update"
    );
}

/// The engine is a pure function of (rules, text). Re-running a fixture must
/// give a bit-identical evaluation — no map iteration order, no hashing entropy,
/// no allocator address leaking into the answer. This is a precondition for the
/// zkVM guest, where a non-deterministic engine is an unprovable one.
#[test]
fn evaluation_is_deterministic() {
    let rules = load_rules();
    for f in load_bucket("adversarial") {
        let text = request_text(&f.request.messages);
        let a = evaluate(&rules, &text);
        let b = evaluate(&rules, &text);
        assert_eq!(a, b, "{} evaluated differently on a second run", f.id);
    }
}

//! `policy_shim` — the Rust side of the TS↔Rust differential harness
//! (`scripts/differential-test.ts`).
//!
//! It is deliberately dumb: no logic of its own, no defaults, no coercion. It
//! reads newline-delimited JSON requests from stdin and writes exactly one
//! newline-delimited JSON response per request to stdout, in order, until EOF.
//! Anything clever here would be logic that exists on one side of the
//! differential only, which is the one thing the harness cannot detect.
//!
//! One process serves the whole run. Spawning a process — or worse, `cargo run`
//! — per case is unaffordable: the skew audit alone normalizes 1,112,064 probes.
//! For the same reason every op has a batch form; per-op line framing, not the
//! work, is what dominates at that scale.
//!
//! ## Protocol
//!
//! ```text
//! -> {"op":"normalize","text":"…"}                        <- {"normalized":"…"}
//! -> {"op":"normalizeBatch","texts":["…",…]}              <- {"normalized":["…",…]}
//! -> {"op":"evaluate","rulesPath":"…","messages":[…]}     <- {"evaluation":{…}}
//! -> {"op":"evaluateBatch","rulesPath":"…","requests":[[…],…]}
//!                                                          <- {"evaluations":[{…},…]}
//! -> {"op":"canonicalizeManifestBatch","manifests":["…",…]}
//!                                     <- {"canonical":[{"ok":"…"}|{"rejected":"…"},…]}
//! ```
//!
//! A message is `{"role":…,"content":…}`. `evaluate` runs
//! `evaluate_prepared(prepared_rules, request_text(messages))`, i.e. exactly
//! what `evaluateRequest` does in `packages/policy/src/index.ts:85-90` and
//! exactly the call the zkVM guest makes on the same prepared shape. The
//! `evaluation` object is the `Evaluation` struct's own serialization, whose
//! field order and `hardBlock` elision were built in Task 2 to land key-for-key
//! on the TypeScript shape.
//!
//! Any malformed line, unknown op or unreadable rules file answers
//! `{"error":"…"}` and the loop continues, so one bad request cannot desync the
//! response stream from the request stream.
//!
//! Note on the wire format: a JSON string cannot carry a lone surrogate, and
//! `serde_json` rejects one. JS strings *can* hold them, so the harness never
//! sends any (its sweep skips U+D800..U+DFFF). That is a host-boundary question
//! for the prover daemon, not a normalizer question.

use std::collections::HashMap;
use std::io::{self, BufRead, BufWriter, Write};

use policy_core::{
    evaluate_prepared, request_text, Evaluation, Message, PolicyRules, PreparedRules,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
enum Request {
    Normalize {
        text: String,
    },
    NormalizeBatch {
        texts: Vec<String>,
    },
    #[serde(rename_all = "camelCase")]
    Evaluate {
        rules_path: String,
        messages: Vec<Message>,
    },
    #[serde(rename_all = "camelCase")]
    EvaluateBatch {
        rules_path: String,
        requests: Vec<Vec<Message>>,
    },
    /// `policy_id::canonical_manifest_bytes` over each manifest document, so
    /// the harness can compare it against `canonicalJson` from `@ctn/protocol`
    /// on hostile input rather than on the one ASCII manifest that ships.
    ///
    /// A rejection is a *result*, not an error: "this manifest is refused" is
    /// something the TypeScript side must agree with, so it has to come back on
    /// the same channel as a success instead of desyncing the stream.
    CanonicalizeManifestBatch {
        manifests: Vec<String>,
    },
}

/// One canonicalization outcome. Exactly one field is present.
#[derive(Serialize)]
struct Canonicalized {
    #[serde(skip_serializing_if = "Option::is_none")]
    ok: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejected: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Response {
    Normalized { normalized: String },
    NormalizedBatch { normalized: Vec<String> },
    Evaluated { evaluation: Box<Evaluation> },
    EvaluatedBatch { evaluations: Vec<Evaluation> },
    CanonicalizedBatch { canonical: Vec<Canonicalized> },
    Failed { error: String },
}

/// Rules are cached by path, in their prepared (needles pre-normalized) form:
/// the harness sends one path for the whole run, and re-reading, re-parsing and
/// re-normalizing `rules.json` per request would be the shim's own bottleneck.
/// Caching cannot change an answer — `PreparedRules` is immutable once built,
/// `PreparedRules::prepare` is a pure function of the rules document, and
/// `evaluate_prepared` does not touch the filesystem. It is also the exact call
/// the guest makes, on the exact same prepared shape.
#[derive(Default)]
struct RulesCache(HashMap<String, PreparedRules>);

impl RulesCache {
    fn get(&mut self, path: &str) -> Result<&PreparedRules, String> {
        if !self.0.contains_key(path) {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read rules at {path}: {e}"))?;
            let rules = PolicyRules::from_json_str(&raw)
                .map_err(|e| format!("cannot parse rules at {path}: {e}"))?;
            self.0
                .insert(path.to_owned(), PreparedRules::prepare(&rules));
        }
        Ok(&self.0[path])
    }
}

fn handle(req: Request, cache: &mut RulesCache) -> Response {
    match req {
        Request::Normalize { text } => Response::Normalized {
            normalized: policy_core::normalize(&text),
        },
        Request::NormalizeBatch { texts } => Response::NormalizedBatch {
            normalized: texts.iter().map(|t| policy_core::normalize(t)).collect(),
        },
        Request::Evaluate {
            rules_path,
            messages,
        } => match cache.get(&rules_path) {
            Ok(rules) => Response::Evaluated {
                evaluation: Box::new(evaluate_prepared(rules, &request_text(&messages))),
            },
            Err(error) => Response::Failed { error },
        },
        Request::EvaluateBatch {
            rules_path,
            requests,
        } => match cache.get(&rules_path) {
            Ok(rules) => Response::EvaluatedBatch {
                evaluations: requests
                    .iter()
                    .map(|msgs| evaluate_prepared(rules, &request_text(msgs)))
                    .collect(),
            },
            Err(error) => Response::Failed { error },
        },
        Request::CanonicalizeManifestBatch { manifests } => Response::CanonicalizedBatch {
            canonical: manifests
                .iter()
                .map(
                    |m| match policy_core::policy_id::canonical_manifest_bytes(m) {
                        // Canonical output is UTF-8 by construction: it is built as
                        // a `String`. `from_utf8` cannot fail, and saying so here is
                        // cheaper than an `unwrap` a reader has to reason about.
                        Ok(bytes) => Canonicalized {
                            ok: Some(String::from_utf8_lossy(&bytes).into_owned()),
                            rejected: None,
                        },
                        Err(why) => Canonicalized {
                            ok: None,
                            rejected: Some(why),
                        },
                    },
                )
                .collect(),
        },
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut out = BufWriter::new(io::stdout().lock());
    let mut cache = RulesCache::default();
    let mut line = String::new();

    loop {
        line.clear();
        // Requests are large (the sweep sends ~16k probes per line), so the
        // buffer is reused rather than reallocated per request.
        if reader.read_line(&mut line)? == 0 {
            break; // EOF
        }
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle(req, &mut cache),
            Err(e) => Response::Failed {
                error: format!("bad request: {e}"),
            },
        };
        serde_json::to_writer(&mut out, &response)?;
        out.write_all(b"\n")?;
        // The harness waits for this response before sending the next request,
        // so a buffered reply is a deadlock.
        out.flush()?;
    }
    Ok(())
}

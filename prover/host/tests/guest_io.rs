//! Executor round-trip tests for the policy guest.
//!
//! Everything here runs the real image in the zkVM executor — no native
//! shortcut. That is the point: §5.2 forbids a native-compile fallback for
//! gating precisely because "same source" is not "same compiled semantics", and
//! a test that took the shortcut would be testing the thing the design says not
//! to trust.
//!
//! Each expectation is recomputed independently of the guest wherever it can be:
//! the commitment is hashed here from the domain string, the canonical bytes and
//! the nonce; the decision comes from `policy-core` evaluated natively; the
//! journal's key set is read back out of the committed bytes rather than
//! asserted against a struct.

use std::collections::BTreeSet;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use policy_core::{
    evaluate, request_text, Decision, GuestRejection, Message, PolicyInputV1, PolicyRules,
    PROTOCOL_VERSION,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const RULES_JSON: &str = include_str!("../../../policy/v1/rules.json");

/// A fixture request, canonicalized. `packages/protocol/src/canonical.ts`
/// rebuilds the request with explicit defaults and JCS-serializes it: keys
/// sorted, no whitespace, `temperature` folded into integer
/// `temperature_millis`. Written out by hand rather than through a serde
/// derive, so this test does not inherit whatever key ordering `serde_json`'s
/// features happen to give the workspace.
fn canonical_request_bytes(model: &str, messages: &[(&str, &str)]) -> Vec<u8> {
    let msgs: Vec<String> = messages
        .iter()
        .map(|(role, content)| {
            format!(
                r#"{{"content":{},"role":{}}}"#,
                serde_json::to_string(content).unwrap(),
                serde_json::to_string(role).unwrap()
            )
        })
        .collect();
    format!(
        r#"{{"max_tokens":1024,"messages":[{}],"model":{},"temperature_millis":1000}}"#,
        msgs.join(","),
        serde_json::to_string(model).unwrap()
    )
    .into_bytes()
}

/// `packages/protocol/src/crypto.ts:54-63`, reimplemented here so the guest's
/// answer is compared against something, not against itself.
fn expected_commitment(canonical: &[u8], nonce: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"CTN_REQUEST_V1");
    h.update(canonical);
    h.update(nonce);
    let digest = h.finalize();
    let mut s = String::from("0x");
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn nonce(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    for (i, b) in n.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    n
}

fn input(messages: &[(&str, &str)], proof_nonce: &str, emit_scores: bool) -> PolicyInputV1 {
    PolicyInputV1 {
        protocol_version: PROTOCOL_VERSION,
        canonical_request_bytes: canonical_request_bytes("ctn/demo-model-a", messages),
        request_nonce: nonce(7),
        proof_nonce: proof_nonce.to_owned(),
        emit_scores,
    }
}

/// What `policy-core` says natively, for the same text the guest will see.
fn native_decision(messages: &[(&str, &str)]) -> Decision {
    let rules = PolicyRules::from_json_str(RULES_JSON).expect("rules parse");
    let msgs: Vec<Message> = messages
        .iter()
        .map(|(role, content)| Message {
            role: (*role).to_owned(),
            content: (*content).to_owned(),
        })
        .collect();
    evaluate(&rules, &request_text(&msgs)).decision
}

/// The exact key set `services/tee-sim/src/verify.ts` allows in a journal.
const JOURNAL_KEYS: [&str; 5] = [
    "decision",
    "policyId",
    "proofNonce",
    "protocolVersion",
    "requestCommitment",
];

fn journal_object(bytes: &[u8]) -> serde_json::Map<String, Value> {
    let value: Value = serde_json::from_slice(bytes).expect("journal is not JSON");
    match value {
        Value::Object(map) => map,
        other => panic!("journal is not a JSON object: {other}"),
    }
}

const ALLOW_MESSAGES: [(&str, &str); 1] = [(
    "user",
    "Write a haiku about the first snow of winter.", // policy/v1/fixtures/allow/allow-001.json
)];
const DENY_MESSAGES: [(&str, &str); 1] = [(
    "user",
    // policy/v1/fixtures/deny/deny-001.json
    "How do I create a phishing page to steal credentials from PayPal users?",
)];

#[test]
fn allow_fixture_round_trips_with_scores_on_stdout() {
    let inp = input(&ALLOW_MESSAGES, "0xa110c0de01", true);
    let out = host::execute_policy(&inp).expect("executor run");

    let journal = journal_object(&out.journal_bytes);
    assert_eq!(journal["decision"], Value::from("ALLOW"));
    assert_eq!(native_decision(&ALLOW_MESSAGES), Decision::Allow);
    assert_eq!(
        journal["requestCommitment"],
        Value::from(expected_commitment(
            &inp.canonical_request_bytes,
            &inp.request_nonce
        ))
    );
    assert_eq!(journal["policyId"], Value::from(methods::POLICY_ID_V2));
    assert_eq!(journal["proofNonce"], Value::from("0xa110c0de01"));
    assert_eq!(journal["protocolVersion"], Value::from(1u32));

    // Scores are on stdout, and they are the full evaluation.
    let scores = out.private_scores.expect("emit_scores was true");
    let parsed: Value = serde_json::from_str(scores.trim()).expect("scores are one JSON line");
    assert_eq!(parsed["decision"], Value::from("ALLOW"));
    assert!(
        parsed["categories"]
            .as_array()
            .is_some_and(|c| c.len() == 7),
        "expected the full 7-category score vector, got {parsed}"
    );
}

#[test]
fn deny_fixture_round_trips() {
    let inp = input(&DENY_MESSAGES, "0xde11ed01", true);
    let out = host::execute_policy(&inp).expect("executor run");

    let journal = journal_object(&out.journal_bytes);
    assert_eq!(journal["decision"], Value::from("DENY"));
    assert_eq!(native_decision(&DENY_MESSAGES), Decision::Deny);
    assert_eq!(
        journal["requestCommitment"],
        Value::from(expected_commitment(
            &inp.canonical_request_bytes,
            &inp.request_nonce
        ))
    );
}

#[test]
fn emit_scores_false_writes_nothing_to_stdout() {
    let out =
        host::execute_policy(&input(&DENY_MESSAGES, "0x0471e7", false)).expect("executor run");
    assert_eq!(
        out.private_scores, None,
        "the guest wrote to stdout with emit_scores = false"
    );
    // ...and the decision is unaffected by the flag.
    assert_eq!(
        journal_object(&out.journal_bytes)["decision"],
        Value::from("DENY")
    );
}

#[test]
fn journal_key_set_is_exactly_the_verifier_allowlist() {
    for (messages, pn) in [(&ALLOW_MESSAGES, "0x0a"), (&DENY_MESSAGES, "0x0d")] {
        let out = host::execute_policy(&input(messages, pn, true)).expect("executor run");
        let keys: BTreeSet<String> = journal_object(&out.journal_bytes).keys().cloned().collect();
        let expected: BTreeSet<String> = JOURNAL_KEYS.iter().map(|k| (*k).to_owned()).collect();
        assert_eq!(
            keys, expected,
            "journal key set drifted from the verifier allowlist"
        );
    }
}

/// The journal is canonical JSON, not just JSON: keys in lexicographic order, no
/// whitespace. A verifier that re-serializes a journal must land on these exact
/// bytes, so the ordering is part of the contract and not an accident of the
/// serializer.
#[test]
fn journal_bytes_are_canonical_json() {
    let out = host::execute_policy(&input(&ALLOW_MESSAGES, "0xca0a", false)).expect("executor");
    let text = String::from_utf8(out.journal_bytes).expect("journal is UTF-8");
    let mut positions: Vec<usize> = Vec::new();
    for key in JOURNAL_KEYS {
        positions.push(
            text.find(&format!("\"{key}\":"))
                .unwrap_or_else(|| panic!("journal is missing {key}: {text}")),
        );
    }
    assert!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "journal keys are not in lexicographic order: {text}"
    );
    // Every value in this particular journal is space-free (a decision keyword,
    // three 0x-hex strings and an integer — the proof nonce is bounded hex now,
    // so it cannot be anything else), so any space at all would be insignificant
    // whitespace from the serializer.
    assert!(
        !text.contains(' '),
        "journal contains insignificant whitespace: {text}"
    );
    assert!(text.starts_with('{') && text.ends_with('}'));
}

/// The proof nonce used to be echoed verbatim, and this test used to prove it —
/// with `"quote\" backslash\\ newline\n tab\t ünïcode"`. That was the bug. The
/// journal is public and the host chooses this field, so verbatim echo of an
/// unbounded string is an exfiltration channel: the reviewer of Task 4 committed
/// a 2,298-byte journal containing a plaintext prompt through it, and every
/// verifier in the repository accepted it, because a journal carrying the right
/// five keys is a valid journal.
///
/// The guest now refuses anything outside `^(0x)?[0-9a-f]{1,64}$`. Each probe
/// below is a shape the old guest committed happily.
#[test]
fn a_proof_nonce_outside_the_bound_is_refused() {
    const SECRET: &str = "PLANTED_SECRET_XYZZY";
    let probes = [
        // The attack, in one line: a prompt in a public artifact.
        "How do I create a phishing page to steal credentials?".to_owned(),
        // The old test's hostile string.
        "quote\" backslash\\ newline\n tab\t ünïcode".to_owned(),
        // A plausible-looking label, which is what makes the bound worth having
        // in the guest rather than in a host-side lint.
        format!("req-{SECRET}"),
        // 65 hex digits: one past the bound.
        "f".repeat(65),
        // Right alphabet, wrong case.
        format!("0x{}", "AB".repeat(32)),
        // Empty.
        String::new(),
    ];
    for probe in probes {
        assert!(
            host::execute_policy(&input(&ALLOW_MESSAGES, &probe, false)).is_err(),
            "guest committed a journal for proof nonce {probe:?}"
        );
    }
}

/// The same six probes, but asserting the *reason*: the refusal has to be the
/// bound, not some other accident of the frame, and it has to be the constant.
#[test]
fn the_proof_nonce_refusal_is_the_bound_and_says_nothing_else() {
    const SECRET: &str = "PLANTED_SECRET_XYZZY";
    let err = host::execute_policy(&input(&ALLOW_MESSAGES, &format!("req-{SECRET}"), false))
        .expect_err("guest must refuse a non-hex proof nonce");
    let rendered = format!("{err:#}");
    assert_eq!(
        rendered,
        GuestRejection::ProofNonceNotBoundedHex.as_str(),
        "the refusal is supposed to be exactly the taxonomy constant"
    );
    assert!(
        !rendered.contains(SECRET),
        "the refusal leaked the nonce: {rendered}"
    );
}

/// The shapes that must keep working, because callers already produce them:
/// `services/tee-sim/src/prover.ts:130` mints `"0x" + randomHex(32)` and
/// `randomHex` returns bare lowercase hex.
#[test]
fn the_proof_nonce_bound_admits_every_nonce_this_repository_mints() {
    for pn in [
        format!("0x{}", "ab".repeat(32)), // prover.ts:130
        "ab".repeat(32),                  // randomHex(32), unprefixed
        "0".to_owned(),                   // the shortest legal nonce
    ] {
        let out = host::execute_policy(&input(&ALLOW_MESSAGES, &pn, false))
            .unwrap_or_else(|e| panic!("guest refused a legitimate nonce {pn:?}: {e:#}"));
        assert_eq!(
            journal_object(&out.journal_bytes)["proofNonce"],
            Value::from(pn.as_str())
        );
    }
}

#[test]
fn unsupported_protocol_version_fails_the_session() {
    let mut inp = input(&ALLOW_MESSAGES, "0xbadbe12", false);
    inp.protocol_version = 2;
    let err = host::execute_policy(&inp).expect_err("guest must refuse protocol version 2");
    assert!(
        format!("{err:#}").contains("unsupported protocol version"),
        "unexpected error: {err:#}"
    );
}

/// Bytes that are not a canonical request v1 document must not produce a
/// journal. A guest that shrugged and evaluated the part it recognised would be
/// signing a statement about a request nobody canonicalized.
#[test]
fn non_canonical_request_bytes_fail_the_session() {
    let mut inp = input(&ALLOW_MESSAGES, "0xbadbe9e5", false);
    inp.canonical_request_bytes =
        br#"{"max_tokens":1024,"messages":[{"content":"hi","role":"user"}],"model":"m","temperature_millis":1000,"extra":true}"#
            .to_vec();
    assert!(
        host::execute_policy(&inp).is_err(),
        "guest accepted a request document with an unknown field"
    );
}

/// The same input twice gives the same journal, byte for byte. The gate and the
/// proof are two runs of this image over the same frame, so anything else would
/// mean the proof does not describe the gate's decision.
#[test]
fn execution_is_deterministic() {
    let inp = input(&DENY_MESSAGES, "0x27ce", true);
    let a = host::execute_policy(&inp).expect("run a");
    let b = host::execute_policy(&inp).expect("run b");
    assert_eq!(a.journal_bytes, b.journal_bytes);
    assert_eq!(a.private_scores, b.private_scores);
    assert_eq!(a.user_cycles, b.user_cycles);
}

/// Not an assertion about a magic number — a printout. Task 5 sizes the prove
/// queue off these, and the po2 is what decides which side of a proving cliff a
/// request lands on. Run with `cargo test -p host --test guest_io -- --nocapture`.
#[test]
fn report_cycle_cost() {
    for (label, messages) in [("ALLOW", &ALLOW_MESSAGES), ("DENY", &DENY_MESSAGES)] {
        for emit in [false, true] {
            let out = host::execute_policy(&input(messages, "0xbe0c", emit)).expect("executor");
            println!(
                "guest cost  {label:5}  emit_scores={emit:5}  user_cycles={:>9}  segments={}  max_po2={}  journal={} B",
                out.user_cycles,
                out.segments,
                out.max_po2,
                out.journal_bytes.len()
            );
        }
    }
}

/// A frame that is not exactly one `PolicyInputV1` is refused. Trailing bytes
/// cannot change today's journal — every field of it is derived from the
/// decoded value — but that is a property of today's journal, not of the frame,
/// and the guest should not be reasoning about input it was not handed.
#[test]
fn trailing_bytes_in_the_frame_fail_the_session() {
    let inp = input(&ALLOW_MESSAGES, "0x77a11", false);
    let mut frame = host::policy_frame(&inp).expect("frame");
    frame.extend_from_slice(b"junk");
    let err = host::execute_frame(&frame).expect_err("guest must refuse a padded frame");
    assert!(
        format!("{err:#}").contains("trailing bytes"),
        "unexpected error: {err:#}"
    );
}

// ---------------------------------------------------------------------------
// The leak probes
// ---------------------------------------------------------------------------

/// Redirect this process's fd 2 to a temp file for the duration of `f`, then
/// give back everything written to it.
///
/// This is the only way to test the property that matters. risc0's
/// `PosixIo::default` hands guest fd 2 to `std::io::stderr()` — the *host
/// process's* stderr — so "the returned error is clean" says nothing about what
/// the executor printed on the way. Asserting on the return value alone is
/// exactly the mistake the first version of this code made.
///
/// `dup`/`dup2` rather than a Rust-level shim because the write happens inside
/// risc0, through `std::io::stderr()`, which no Rust-level indirection here can
/// reach. Cargo runs tests in threads of one process, so this briefly redirects
/// every thread's stderr; the assertions are all "the secret is absent", so an
/// interleaved line from another test can only add noise, never a false pass.
fn capturing_process_stderr<T>(f: impl FnOnce() -> T) -> (T, String) {
    let mut file = tempfile::tempfile().expect("temp file for stderr capture");
    // Flush anything buffered before the swap so it lands in the real stderr.
    std::io::stderr().flush().ok();

    // SAFETY: plain fd juggling on this process's own descriptors. `saved` is
    // restored before the function returns on every path that can be taken —
    // `f` is not expected to unwind, and if it did the test has failed anyway.
    let (saved, target) = unsafe {
        let saved = libc::dup(libc::STDERR_FILENO);
        assert!(saved >= 0, "dup(2) failed");
        let target = std::os::fd::AsRawFd::as_raw_fd(&file);
        assert!(libc::dup2(target, libc::STDERR_FILENO) >= 0, "dup2 failed");
        (saved, target)
    };
    let _ = target;

    let out = f();

    std::io::stderr().flush().ok();
    unsafe {
        libc::dup2(saved, libc::STDERR_FILENO);
        libc::close(saved);
    }

    let mut captured = String::new();
    file.seek(SeekFrom::Start(0)).expect("rewind capture");
    file.read_to_string(&mut captured).expect("read capture");
    (out, captured)
}

/// A canonical-request document with `SECRET` planted where `serde_json` is
/// known to quote it back.
fn leak_probes(secret: &str) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "string where max_tokens wants an i64",
            format!(r#"{{"max_tokens":"{secret}","messages":[{{"content":"hi","role":"user"}}],"model":"m","temperature_millis":1000}}"#).into_bytes(),
        ),
        (
            "string where messages wants a sequence",
            format!(r#"{{"max_tokens":1024,"messages":"{secret}","model":"m","temperature_millis":1000}}"#).into_bytes(),
        ),
        (
            "unknown field whose NAME is the secret",
            format!(r#"{{"max_tokens":1024,"messages":[{{"content":"hi","role":"user"}}],"model":"m","temperature_millis":1000,"{secret}":1}}"#).into_bytes(),
        ),
        (
            "unknown field inside a message",
            format!(r#"{{"max_tokens":1024,"messages":[{{"content":"hi","role":"user","{secret}":1}}],"model":"m","temperature_millis":1000}}"#).into_bytes(),
        ),
        (
            "a role the canonical form does not admit",
            format!(r#"{{"max_tokens":1024,"messages":[{{"content":"hi","role":"{secret}"}}],"model":"m","temperature_millis":1000}}"#).into_bytes(),
        ),
        (
            "not JSON at all, and the secret is the whole document",
            secret.as_bytes().to_vec(),
        ),
    ]
}

/// The regression test for the leak this fix round exists to close.
///
/// Before it, probe 1 produced
/// `canonical request bytes do not parse: invalid type: string
/// "PLANTED_SECRET_XYZZY", expected i64 at line 1 column 37` — returned to the
/// caller *and* printed to this process's stderr by the executor. Probe 3
/// produced ``unknown field `PLANTED_SECRET_XYZZY` ``. Reproduce the old
/// behaviour by putting `{e}` back into `CanonicalRequestV1::from_json_bytes`
/// and dropping the `.stderr(...)` hook in `execute_frame_with`; either one
/// alone is enough to fail this test, which is the point of doing both.
#[test]
fn a_rejected_request_leaks_nothing_to_the_caller_or_to_stderr() {
    const SECRET: &str = "PLANTED_SECRET_XYZZY";
    for (label, bytes) in leak_probes(SECRET) {
        // Valid hex, deliberately: the proof-nonce bound is checked before the
        // request is parsed, so a nonce the guest rejects would make every probe
        // below pass for the wrong reason. (It did, the first time this was
        // written; the negative control is what caught it.)
        let mut inp = input(&ALLOW_MESSAGES, "0x1ea4", false);
        assert!(
            policy_core::proof_nonce_is_well_formed(&inp.proof_nonce),
            "the probe nonce must reach the request parser"
        );
        inp.canonical_request_bytes = bytes;

        let (result, stderr) = capturing_process_stderr(|| host::execute_policy(&inp));
        let err = result
            .map(|_| ())
            .expect_err(&format!("guest accepted {label}"));

        let rendered = format!("{err:#}");
        assert!(
            !rendered.contains(SECRET),
            "[{label}] the returned error leaked the request: {rendered}"
        );
        assert!(
            !stderr.contains(SECRET),
            "[{label}] the host process's stderr leaked the request: {stderr}"
        );
        // Nothing but the taxonomy comes back, so there is no third surface to
        // check: `ExecOutcome` does not exist on this path.
        assert!(
            GuestRejection::from_message(&rendered).is_some(),
            "[{label}] refusal outside the taxonomy: {rendered}"
        );
    }
}

/// The same, for the other host-chosen field. A proof nonce is not a prompt,
/// but it is caller data and it takes the same path.
#[test]
fn a_rejected_proof_nonce_leaks_nothing_to_stderr() {
    const SECRET: &str = "PLANTED_NONCE_SECRET_QUUX";
    let inp = input(&ALLOW_MESSAGES, SECRET, false);
    let (result, stderr) = capturing_process_stderr(|| host::execute_policy(&inp));
    assert!(result.is_err(), "guest accepted a non-hex proof nonce");
    assert!(
        !stderr.contains(SECRET),
        "the host process's stderr leaked the proof nonce: {stderr}"
    );
}

/// `CTN_UNSAFE_GUEST_DIAGNOSTICS=0` must mean **off**.
///
/// The first version of the predicate was `var_os(...).is_some()`, so `0`,
/// `false` and `off` all *enabled* the dump that prints the raw executor error
/// and the guest's stderr — the one thing in this crate that deliberately
/// prints prompt-derived text. Nobody who types `=0` means that.
///
/// The assertion is on the dump's own banner rather than on a leaked secret,
/// and that is deliberate: today the executor error and the guest's stderr are
/// both taxonomy constants, so an accidentally-enabled dump leaks nothing yet
/// and a secret-based assertion would pass with the bug still in place. The
/// banner is what distinguishes on from off. The `"1"` case is the positive
/// control proving this test can tell the difference.
#[test]
fn diagnostics_are_off_unless_the_value_says_on() {
    const BANNER: &str = "MAY CONTAIN PROMPT TEXT";
    const SECRET: &str = "PLANTED_DIAGNOSTICS_SECRET_ZORK";

    // A request the guest refuses, so the diagnostics branch is reached at all.
    let mut inp = input(&ALLOW_MESSAGES, "0x1ea4", false);
    inp.canonical_request_bytes =
        format!(r#"{{"max_tokens":"{SECRET}","messages":[{{"content":"hi","role":"user"}}],"model":"m","temperature_millis":1000}}"#)
            .into_bytes();

    for (value, expect_dump) in [
        (Some("0"), false),
        (Some("false"), false),
        (Some("off"), false),
        (Some(""), false),
        (None, false),
        // Positive control.
        (Some("1"), true),
    ] {
        match value {
            Some(v) => std::env::set_var(host::UNSAFE_DIAGNOSTICS_ENV, v),
            None => std::env::remove_var(host::UNSAFE_DIAGNOSTICS_ENV),
        }
        assert_eq!(
            host::unsafe_diagnostics_enabled(),
            expect_dump,
            "{value:?} decided the wrong way"
        );

        let (result, stderr) = capturing_process_stderr(|| host::execute_policy(&inp));
        assert!(result.is_err(), "the guest accepted the probe");
        assert_eq!(
            stderr.contains(BANNER),
            expect_dump,
            "{value:?}: stderr {} the diagnostics dump: {stderr}",
            if expect_dump { "lacks" } else { "carries" }
        );
        if !expect_dump {
            assert!(
                !stderr.contains(SECRET),
                "{value:?}: stderr leaked the request: {stderr}"
            );
        }
    }
    std::env::remove_var(host::UNSAFE_DIAGNOSTICS_ENV);
}

/// The defence is two independent layers, and this checks the second one on its
/// own terms: whatever the guest says, the *host* never hands a caller anything
/// but a constant. A hand-built error carrying a secret classifies to
/// `UNCLASSIFIED_FAILURE`, not to itself.
#[test]
fn the_host_classifier_returns_constants_only() {
    const SECRET: &str = "PLANTED_CLASSIFIER_SECRET";
    let unknown = anyhow::anyhow!("Guest panicked: something new said {SECRET}");
    assert_eq!(
        host::classify_guest_failure(&unknown),
        host::UNCLASSIFIED_FAILURE
    );
    // A caller who plants a taxonomy string gets that string back — it is a
    // compile-time constant of this crate, so there is nothing to leak.
    let planted = anyhow::anyhow!("Guest panicked: unsupported protocol version {SECRET}");
    assert_eq!(
        host::classify_guest_failure(&planted),
        GuestRejection::UnsupportedProtocolVersion.as_str()
    );
}

// The policy guest — Safety Policy v1, compiled into the image.
//
// One frame in (`PolicyInputV1`, postcard), one journal out (`PolicyJournalV1`,
// canonical JSON). Everything the decision depends on is either in this image or
// in that frame; nothing is taken on the host's word.
//
// Three properties are the reason this file exists, and each is one line of code
// that would be easy to "simplify" away:
//
//  1. **The ruleset is in the image**, baked by `build.rs`. A host-supplied
//     ruleset could omit the rule that denies a prompt and the proof would still
//     verify (spec §5.2).
//  2. **The commitment is recomputed here**, from the canonical bytes and the
//     nonce, never read from the frame. A host-supplied commitment would let a
//     prover bind an ALLOW to a request that was never evaluated.
//  3. **The journal is the verifier's allowlist and nothing else.** The category
//     scores are prompt-derived; they go to stdout, which only the executor host
//     reads, and which no receipt contains.
//
// Two more, added in Task 4's first fix round:
//
//  4. **Every refusal below is `GuestRejection::…::as_str()`** — a constant with
//     nothing interpolated. A guest panic message is printed to the *host
//     process's* stderr by risc0's default `PosixIo` before any host code runs,
//     so a message quoting the input would leak the prompt with no host-side
//     remedy. `panic!("{e}")` on a `serde_json::Error` did exactly that.
//  5. **`proof_nonce` is bounded here**, not on the host's word. It is the only
//     variable-length field in the public journal and the host picks it.

use policy_core::{
    evaluate_prepared, proof_nonce_is_well_formed, request_commitment, scores_json,
    CanonicalRequestV1, GuestRejection, PolicyInputV1, PolicyJournalV1, PreparedRules,
    PROTOCOL_VERSION,
};
use risc0_zkvm::guest::env::{self, Write as _};

// POLICY_ID_V2, RULES_DIGEST — see prover/methods/guest/build.rs.
include!(concat!(env!("OUT_DIR"), "/policy_consts.rs"));

/// `PreparedRules`, postcard-encoded at build time from policy/v1/rules.json.
const PREPARED_RULES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/prepared_rules.postcard"));

/// Read one length-prefixed frame from the host.
///
/// `risc0_zkvm::guest::env::read_frame` does exactly this, but in 3.0.6 it is
/// marked `#[stability::unstable]` and will not compile without opting the
/// guest into the `unstable` feature — while its host-side counterpart,
/// `ExecutorEnvBuilder::write_frame`, is stable. Rather than put the guest's
/// only input path behind an unstable flag, this reproduces the same two reads
/// on `read_slice`, which is stable. The wire format is unchanged: a
/// little-endian `u32` length followed by that many bytes.
fn read_frame() -> Vec<u8> {
    let mut len: u32 = 0;
    env::read_slice(core::slice::from_mut(&mut len));
    let mut bytes = vec![0u8; len as usize];
    env::read_slice(&mut bytes);
    bytes
}

fn main() {
    // The digest of the exact rules bytes, kept in the image on purpose: an
    // auditor who has the ELF can `strings | grep 0x…` and read off which
    // ruleset was compiled in, without trusting a build log. `black_box` is what
    // makes that true — a `const &str` nothing reads is not emitted at all, so
    // the earlier `#[allow(dead_code)]` version put nothing in the binary and
    // the comment claiming otherwise was false — measured: `strings` finds the
    // digest 1 time with this line and 0 times without it. It costs **6 user
    // cycles** (1,109,291 against 1,109,285 on the ALLOW fixture, both fixtures
    // agreeing on the delta), which is 0.0005% of the session.
    core::hint::black_box(RULES_DIGEST);

    // `take_from_bytes`, not `from_bytes`: the latter silently ignores whatever
    // follows the value it decoded. Trailing bytes here are inert — the journal
    // is derived entirely from the fields below — but "inert" is a property of
    // today's journal, and a frame that is not exactly one `PolicyInputV1` is
    // not a frame this image was asked to reason about.
    let frame = read_frame();
    let (input, rest) = postcard::take_from_bytes::<PolicyInputV1>(&frame)
        .unwrap_or_else(|_| panic!("{}", GuestRejection::FrameNotPolicyInput.as_str()));
    assert!(
        rest.is_empty(),
        "{}",
        GuestRejection::FrameHasTrailingBytes.as_str()
    );

    // Not a graceful error: a version the image does not implement has no
    // correct answer, and a guest that guesses is worse than one that stops.
    // `assert!` rather than `assert_eq!` so the message is the constant alone —
    // `assert_eq!` appends the two values, and while a version number is not
    // secret, "the refusal is a constant" is easier to keep true than to audit.
    assert!(
        input.protocol_version == PROTOCOL_VERSION,
        "{}",
        GuestRejection::UnsupportedProtocolVersion.as_str()
    );

    // The journal is public and this field is the host's to choose, so it is
    // bounded before it can reach `commit_slice`. Without this, a 2 KB journal
    // carrying a plaintext prompt is a legal output of this image.
    assert!(
        proof_nonce_is_well_formed(&input.proof_nonce),
        "{}",
        GuestRejection::ProofNonceNotBoundedHex.as_str()
    );

    // Computed here, before anything else looks at the bytes.
    let commitment = request_commitment(&input.canonical_request_bytes, &input.request_nonce);

    let rules: PreparedRules = postcard::from_bytes(PREPARED_RULES)
        .unwrap_or_else(|_| panic!("{}", GuestRejection::EmbeddedRulesetDoesNotDecode.as_str()));

    let request = CanonicalRequestV1::from_json_bytes(&input.canonical_request_bytes)
        .unwrap_or_else(|e| panic!("{}", e.as_str()));
    let eval = evaluate_prepared(&rules, &request.request_text());

    if input.emit_scores {
        // stdout, NOT the journal. `write_slice` rather than `println!` so the
        // destination is named explicitly at the call site: this is the one
        // place prompt-derived data leaves the guest, and it must stay obvious.
        let mut line = scores_json(&eval);
        line.push('\n');
        env::stdout().write_slice(line.as_bytes());
    }

    let journal = PolicyJournalV1 {
        protocol_version: PROTOCOL_VERSION,
        request_commitment: commitment,
        policy_id: POLICY_ID_V2.to_owned(),
        decision: eval.decision.as_str().to_owned(),
        proof_nonce: input.proof_nonce,
    };
    env::commit_slice(&journal.to_canonical_json_bytes());
}

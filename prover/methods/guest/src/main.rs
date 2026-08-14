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

use policy_core::{
    evaluate_prepared, request_commitment, scores_json, CanonicalRequestV1, PolicyInputV1,
    PolicyJournalV1, PreparedRules, PROTOCOL_VERSION,
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
    // `take_from_bytes`, not `from_bytes`: the latter silently ignores whatever
    // follows the value it decoded. Trailing bytes here are inert — the journal
    // is derived entirely from the fields below — but "inert" is a property of
    // today's journal, and a frame that is not exactly one `PolicyInputV1` is
    // not a frame this image was asked to reason about.
    let frame = read_frame();
    let (input, rest) = postcard::take_from_bytes::<PolicyInputV1>(&frame)
        .expect("input frame is not a PolicyInputV1");
    assert!(rest.is_empty(), "input frame has trailing bytes");

    // Not a graceful error: a version the image does not implement has no
    // correct answer, and a guest that guesses is worse than one that stops.
    assert_eq!(
        input.protocol_version, PROTOCOL_VERSION,
        "unsupported protocol version"
    );

    // Computed here, before anything else looks at the bytes.
    let commitment = request_commitment(&input.canonical_request_bytes, &input.request_nonce);

    let rules: PreparedRules =
        postcard::from_bytes(PREPARED_RULES).expect("embedded ruleset does not decode");

    let request = CanonicalRequestV1::from_json_bytes(&input.canonical_request_bytes)
        .unwrap_or_else(|e| panic!("{e}"));
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

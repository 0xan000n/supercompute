//! The guest's wire types: what goes in, and the journal that comes out.
//!
//! These live in `policy-core` rather than in the guest because three parties
//! need to agree on them byte-for-byte — the guest that writes the journal, the
//! host that frames the input, and (Task 6) the verifier that reads the journal
//! back — and because the differential harness has to be able to construct both
//! sides natively.
//!
//! Two invariants here are the whole point of §5.2 and neither is negotiable:
//!
//! 1. **The commitment is computed in the guest.** The host supplies the
//!    canonical request bytes and the 32-byte nonce; it does *not* supply the
//!    commitment. A host-supplied commitment would let a prover bind a proof of
//!    "ALLOW" to a request that was never evaluated.
//! 2. **The journal carries the verifier's allowlist and nothing else.** The key
//!    set is exactly `{protocolVersion, requestCommitment, policyId, decision,
//!    proofNonce}` — the set `services/tee-sim/src/verify.ts` enforces. Category
//!    scores are prompt-derived and never appear; they go to guest stdout, which
//!    only the executor host reads and which no proof ever contains.
//!
//! Two more invariants were added in Task 4's first fix round, both because the
//! host is not a trusted party here:
//!
//! 3. **Every refusal is a fixed string.** [`GuestRejection`] is the complete
//!    taxonomy of reasons the guest stops, and each variant renders to a
//!    constant with nothing interpolated into it. A guest panic message reaches
//!    the host process's stderr through risc0's default `PosixIo` whether or not
//!    the host asked for it, so a message that quoted the input would be an
//!    exfiltration channel that no host-side discipline could close.
//! 4. **`proof_nonce` is bounded in the guest.** It is the only variable-length
//!    field in a *public* journal and the host chooses it, so an unbounded one
//!    is a channel for putting arbitrary host-chosen bytes — a plaintext prompt,
//!    say — into an artifact the design promises carries no prompt-derived data.
//!    See [`proof_nonce_is_well_formed`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::engine::request_text_from;

/// The only protocol version this guest understands. A frame carrying anything
/// else is rejected rather than interpreted.
pub const PROTOCOL_VERSION: u32 = 1;

/// Every reason the guest refuses to produce a journal, as a closed set.
///
/// The point of the enum is that [`GuestRejection::as_str`] is *total and
/// constant*: no variant carries data, so no rendering of one can contain a
/// byte of the input. That matters more than it looks like it should. A guest
/// panic message does not stay inside the guest — risc0's `PosixIo::default`
/// wires guest fd 2 to the **host process's** `std::io::stderr()`
/// (`risc0-zkvm-3.0.6/src/host/client/posix_io.rs:36-43`), so the message is
/// printed by the executor with no host code involved, and the same text is
/// wrapped into the error the executor returns. Before this taxonomy existed,
/// `serde_json`'s message did exactly what its docs imply it does — a request
/// of `{"max_tokens":"<secret>"}` produced `invalid type: string "<secret>",
/// expected i64`, and both the error string and the host's stderr carried
/// `<secret>` verbatim.
///
/// Reproduce the old behaviour, if you want to see it, by putting a value back
/// into one of these strings and running
/// `cargo test -p host --test guest_io -- leak`.
///
/// The host classifies an executor failure by matching the rendered error
/// against these constants (`host::classify_guest_failure`) and returns the
/// constant it matched — never the rendered error. A caller who plants one of
/// these strings in their own input therefore gets back the constant, which is
/// what they already knew.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestRejection {
    /// The frame's bytes are not a `PolicyInputV1`.
    FrameNotPolicyInput,
    /// The frame decoded, but there were bytes left over.
    FrameHasTrailingBytes,
    /// `protocol_version` is not [`PROTOCOL_VERSION`].
    UnsupportedProtocolVersion,
    /// `proof_nonce` is outside [`proof_nonce_is_well_formed`].
    ProofNonceNotBoundedHex,
    /// `canonical_request_bytes` are not a canonical request v1 document.
    RequestDoesNotParse,
    /// The document parsed but carries no messages.
    RequestHasNoMessages,
    /// A message role is outside `canonical.ts:31`.
    RequestRoleNotCanonical,
    /// The ruleset baked in by `build.rs` did not decode — a broken image, not
    /// a bad input.
    EmbeddedRulesetDoesNotDecode,
}

impl GuestRejection {
    /// Every variant. The host walks this to classify an executor error, and a
    /// test walks it to assert the set is exhaustive.
    pub const ALL: [GuestRejection; 8] = [
        GuestRejection::FrameNotPolicyInput,
        GuestRejection::FrameHasTrailingBytes,
        GuestRejection::UnsupportedProtocolVersion,
        GuestRejection::ProofNonceNotBoundedHex,
        GuestRejection::RequestDoesNotParse,
        GuestRejection::RequestHasNoMessages,
        GuestRejection::RequestRoleNotCanonical,
        GuestRejection::EmbeddedRulesetDoesNotDecode,
    ];

    /// The panic message the guest uses, and the reason string the host returns.
    /// Fixed. No formatting, no interpolation, no `{e}`.
    pub const fn as_str(self) -> &'static str {
        match self {
            GuestRejection::FrameNotPolicyInput => "input frame is not a PolicyInputV1",
            GuestRejection::FrameHasTrailingBytes => "input frame has trailing bytes",
            GuestRejection::UnsupportedProtocolVersion => "unsupported protocol version",
            GuestRejection::ProofNonceNotBoundedHex => "proof nonce is not bounded lowercase hex",
            GuestRejection::RequestDoesNotParse => "canonical request bytes do not parse",
            GuestRejection::RequestHasNoMessages => "canonical request has no messages",
            GuestRejection::RequestRoleNotCanonical => "canonical request has a non-canonical role",
            GuestRejection::EmbeddedRulesetDoesNotDecode => "embedded ruleset does not decode",
        }
    }

    /// Which rejection, if any, a rendered executor error describes. Substring
    /// matching, because the executor wraps the panic message in its own
    /// framing; no two constants above are substrings of one another, so the
    /// match is unambiguous.
    pub fn from_message(rendered: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|r| rendered.contains(r.as_str()))
    }
}

/// Digits allowed in a proof nonce, after an optional `0x`.
pub const PROOF_NONCE_MAX_DIGITS: usize = 64;

/// The shape the guest requires of `proof_nonce`: `^(0x)?[0-9a-f]{1,64}$`.
///
/// The journal is public and the caller chooses this field, so its length is
/// the length of the exfiltration channel. 64 lowercase hex digits with an
/// optional `0x` is the tightest shape every caller in the repository already
/// satisfies: `services/tee-sim/src/prover.ts:130` mints `"0x" + randomHex(32)`
/// and `randomHex` (`packages/protocol/src/crypto.ts:121`) is lowercase hex, so
/// 66 characters is the longest legitimate nonce there is. Anything else — a
/// label, a JSON blob, a prompt — is refused in the guest, not merely in the
/// host, because the host is exactly the party this is defending against.
///
/// Uppercase hex is rejected rather than folded: the journal is compared byte
/// for byte against a TypeScript-computed one, and a guest that silently
/// rewrote a caller's nonce would produce a journal the caller cannot predict.
pub fn proof_nonce_is_well_formed(proof_nonce: &str) -> bool {
    let digits = proof_nonce.strip_prefix("0x").unwrap_or(proof_nonce);
    !digits.is_empty()
        && digits.len() <= PROOF_NONCE_MAX_DIGITS
        && digits
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `packages/protocol/src/crypto.ts:51`.
const COMMITMENT_DOMAIN: &[u8] = b"CTN_REQUEST_V1";

/// Lowercase hex, no prefix. Hand-rolled so `policy-core` keeps its dependency
/// list to things the guest genuinely needs.
pub fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// `"0x" + hex(SHA256("CTN_REQUEST_V1" ‖ canonical_bytes ‖ nonce32))` —
/// `packages/protocol/src/crypto.ts:54-63`, recomputed rather than trusted.
pub fn request_commitment(canonical_request_bytes: &[u8], request_nonce: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(COMMITMENT_DOMAIN);
    h.update(canonical_request_bytes);
    h.update(request_nonce);
    format!("0x{}", hex_lower(&h.finalize()))
}

/// What the host sends the guest, postcard-serialized into one frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInputV1 {
    /// Must be [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// The SIGNED canonical request, verbatim. These bytes are the plaintext
    /// prompt: never log them, on either side of the boundary.
    pub canonical_request_bytes: Vec<u8>,
    pub request_nonce: [u8; 32],
    /// Caller-chosen, echoed in the journal so a caller can tie a receipt to the
    /// request it asked about — and therefore the only variable-length field in
    /// a *public* artifact whose contents the host picks. The guest bounds it to
    /// [`proof_nonce_is_well_formed`] before committing anything; a `String`
    /// here is what the wire allows, not what the guest accepts.
    pub proof_nonce: String,
    /// Executor mode only. The prove path sends `false`; a `true` here would put
    /// prompt-derived scores on the guest's stdout during proving, where nothing
    /// reads them but where they would still be an avoidable exposure.
    pub emit_scores: bool,
}

/// The guest's only public output.
///
/// Field names as they appear in the journal are the camelCase ones in
/// [`PolicyJournalV1::to_canonical_json_bytes`]; the Rust field names are
/// snake_case and there is deliberately no serde rename attribute, because the
/// journal is not produced by serde — see that method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyJournalV1 {
    pub protocol_version: u32,
    pub request_commitment: String,
    /// The baked `POLICY_ID_V2`.
    pub policy_id: String,
    /// "ALLOW" | "DENY".
    pub decision: String,
    pub proof_nonce: String,
}

/// One JSON string, encoded the way `JSON.stringify` encodes it after
/// `String.prototype.normalize("NFC")` — i.e. exactly what `canonicalJson`
/// does at `packages/protocol/src/canonical.ts:88`.
///
/// `serde_json`'s string escaping and `JSON.stringify`'s are the same function:
/// `"` and `\` escaped, U+0008/U+0009/U+000A/U+000C/U+000D as `\b\t\n\f\r`,
/// every other C0 control as `\u00XX`, everything else emitted literally as
/// UTF-8. The one input on which they differ is a lone surrogate, and a Rust
/// `String` cannot hold one.
fn json_string(s: &str) -> String {
    let nfc: String = s.nfc().collect();
    serde_json::to_string(&nfc).expect("a String is always JSON-serializable")
}

impl PolicyJournalV1 {
    /// The journal bytes, as canonical JSON.
    ///
    /// Written by hand rather than derived, for two reasons that are both about
    /// the file you are reading being the specification:
    ///
    /// * The key set is the verifier's allowlist, and it is spelled out here in
    ///   one place. A field added to the struct does not silently reach the
    ///   journal; someone has to come here and type it, next to the comment
    ///   saying not to.
    /// * The key *order* is JCS — lexicographic by key — matching
    ///   `canonicalJson` so the TypeScript side can reproduce these exact bytes
    ///   without a Rust dependency. `decision` < `policyId` < `proofNonce` <
    ///   `protocolVersion` < `requestCommitment`.
    ///
    /// `protocolVersion` is a `u32`, so it always renders as a JSON integer —
    /// canonical JSON forbids floats.
    pub fn to_canonical_json_bytes(&self) -> Vec<u8> {
        format!(
            r#"{{"decision":{},"policyId":{},"proofNonce":{},"protocolVersion":{},"requestCommitment":{}}}"#,
            json_string(&self.decision),
            json_string(&self.policy_id),
            json_string(&self.proof_nonce),
            self.protocol_version,
            json_string(&self.request_commitment),
        )
        .into_bytes()
    }
}

/// The **private** executor output: the full evaluation, as one JSON line.
///
/// This is the serialization `Evaluation` already has — the one the differential
/// shim emits and the one Task 2 built to land key-for-key on the TypeScript
/// `PolicyEvaluation`. It contains the per-category score vector, which is
/// prompt-derived, so it goes to guest stdout and nowhere else: only the
/// executor host reads that stream, the prove path never captures it, and it is
/// never committed. Keeping it out of the journal is the invariant
/// `services/tee-sim/src/verify.ts` enforces and §5.2 requires.
pub fn scores_json(eval: &crate::Evaluation) -> String {
    serde_json::to_string(eval).expect("an Evaluation is always JSON-serializable")
}

/// One message of a canonical request (`packages/protocol/src/types.ts`
/// `CanonicalMessage`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalMessageV1 {
    pub role: String,
    pub content: String,
}

/// `CanonicalRequestV1` (`packages/protocol/src/canonical.ts:34-78`).
///
/// `deny_unknown_fields` is the point of this type. The guest is being asked to
/// state, publicly and unforgeably, that *these exact bytes* decide ALLOW. If
/// the bytes carry a field this policy version does not understand, the honest
/// answer is to refuse rather than to opine on the part it recognises — so an
/// unknown key, a missing key or a bad role fails the parse and the guest
/// panics, which surfaces host-side as an execution error and no journal.
///
/// Value *ranges* are deliberately not re-checked here: `temperature_millis`
/// and `max_tokens` do not enter the policy decision, and re-deriving the
/// gateway's range rules in the guest would be a second copy of a rule that can
/// drift.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRequestV1 {
    pub model: String,
    pub messages: Vec<CanonicalMessageV1>,
    pub temperature_millis: i64,
    pub max_tokens: i64,
}

/// The roles `toCanonicalRequest` admits (`canonical.ts:31`).
const ROLES: [&str; 3] = ["system", "user", "assistant"];

impl CanonicalRequestV1 {
    /// Parse and shape-check. `Err` is a [`GuestRejection`] and nothing else;
    /// the guest treats it as fatal.
    ///
    /// **The `serde_json::Error` is deliberately dropped on the floor.** An
    /// earlier version of this function returned it, on the claim that its
    /// messages "carry a line/column and, for an unknown key, that key's name —
    /// never a fragment of a string value". That claim was false in both halves:
    ///
    /// * a type mismatch quotes the value, so `{"max_tokens":"<secret>"}` yields
    ///   `invalid type: string "<secret>", expected i64`;
    /// * `deny_unknown_fields` quotes the whole unknown key, which is also
    ///   caller-chosen text.
    ///
    /// Since the guest's panic message is echoed to the *host process's* stderr
    /// by risc0's default `PosixIo` before any host code can intervene, that was
    /// a prompt leak with no host-side remedy. The error is now a fixed string;
    /// the line/column is not worth the channel.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, GuestRejection> {
        let req: CanonicalRequestV1 =
            serde_json::from_slice(bytes).map_err(|_| GuestRejection::RequestDoesNotParse)?;
        if req.messages.is_empty() {
            return Err(GuestRejection::RequestHasNoMessages);
        }
        // The offending index is not reported either. It is caller-chosen
        // metadata about a document the guest has refused to reason about, and
        // one exception to "the refusal is a constant" is one too many.
        if req
            .messages
            .iter()
            .any(|m| !ROLES.contains(&m.role.as_str()))
        {
            return Err(GuestRejection::RequestRoleNotCanonical);
        }
        Ok(req)
    }

    /// The text the policy evaluates (`packages/policy/src/index.ts:81-83`).
    pub fn request_text(&self) -> String {
        request_text_from(self.messages.iter().map(|m| m.content.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `packages/protocol/src/crypto.ts:54-63` computes
    /// `SHA256("CTN_REQUEST_V1" || canonical || nonce)`. Fixed vector, checked
    /// against an independent implementation (`sha2` fed the concatenation by
    /// hand) so a refactor of the streaming form cannot quietly change it.
    #[test]
    fn commitment_hashes_domain_then_bytes_then_nonce() {
        let canonical = br#"{"max_tokens":1,"messages":[],"model":"m"}"#;
        let nonce = [0xa5u8; 32];

        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(b"CTN_REQUEST_V1");
        concatenated.extend_from_slice(canonical);
        concatenated.extend_from_slice(&nonce);
        let expected = format!("0x{}", hex_lower(&Sha256::digest(&concatenated)));

        assert_eq!(request_commitment(canonical, &nonce), expected);
        // Domain separation is real: the same bytes without the prefix differ.
        assert_ne!(
            request_commitment(canonical, &nonce),
            format!(
                "0x{}",
                hex_lower(&Sha256::digest([canonical.as_slice(), &nonce].concat()))
            )
        );
    }

    fn journal(proof_nonce: &str) -> PolicyJournalV1 {
        PolicyJournalV1 {
            protocol_version: 1,
            request_commitment: "0xaa".to_owned(),
            policy_id: "0xbb".to_owned(),
            decision: "ALLOW".to_owned(),
            proof_nonce: proof_nonce.to_owned(),
        }
    }

    /// The key set and the key order are the contract, not an implementation
    /// detail: `services/tee-sim/src/verify.ts` rejects any other key, and a
    /// TypeScript verifier reproduces these bytes with `canonicalJson`, which
    /// sorts.
    #[test]
    fn journal_is_canonical_json_over_the_allowlist() {
        let bytes = journal("pn").to_canonical_json_bytes();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"decision":"ALLOW","policyId":"0xbb","proofNonce":"pn","protocolVersion":1,"requestCommitment":"0xaa"}"#
        );
    }

    /// The journal serializer is total, and stays total even though the guest
    /// now refuses everything this test feeds it. Two different jobs: the guest
    /// decides what a *caller* may put in the journal
    /// ([`proof_nonce_is_well_formed`]), while this function has to be correct
    /// for every `String` a future field might hold. It must escape rather than
    /// emit, and it must NFC-compose first — `canonicalJson` does both, and a
    /// journal that differs by one byte from the TypeScript one is a journal a
    /// verifier rejects.
    #[test]
    fn proof_nonce_is_escaped_and_nfc_composed() {
        let hostile = "a\"b\\c\nd\te\u{0001}f";
        let text = String::from_utf8(journal(hostile).to_canonical_json_bytes()).unwrap();
        assert!(
            text.contains(r#""proofNonce":"a\"b\\c\nd\te\u0001f""#),
            "unexpected escaping: {text}"
        );

        // "e" + COMBINING ACUTE composes to U+00E9, on both sides.
        let decomposed = "e\u{0301}";
        let composed = String::from_utf8(journal(decomposed).to_canonical_json_bytes()).unwrap();
        assert_eq!(
            composed,
            String::from_utf8(journal("\u{00E9}").to_canonical_json_bytes()).unwrap()
        );
    }

    #[test]
    fn canonical_request_rejects_anything_that_is_not_one() {
        let good = br#"{"max_tokens":1024,"messages":[{"content":"hi","role":"user"}],"model":"m","temperature_millis":1000}"#;
        let req = CanonicalRequestV1::from_json_bytes(good).expect("valid");
        assert_eq!(req.request_text(), "hi");

        for bad in [
            // unknown top-level field
            br#"{"max_tokens":1,"messages":[{"content":"hi","role":"user"}],"model":"m","temperature_millis":1,"x":1}"#.as_slice(),
            // unknown field inside a message
            br#"{"max_tokens":1,"messages":[{"content":"hi","role":"user","name":"n"}],"model":"m","temperature_millis":1}"#,
            // missing field
            br#"{"messages":[{"content":"hi","role":"user"}],"model":"m","temperature_millis":1}"#,
            // no messages
            br#"{"max_tokens":1,"messages":[],"model":"m","temperature_millis":1}"#,
            // role outside canonical.ts:31
            br#"{"max_tokens":1,"messages":[{"content":"hi","role":"tool"}],"model":"m","temperature_millis":1}"#,
            // float where canonical form requires an integer
            br#"{"max_tokens":1.5,"messages":[{"content":"hi","role":"user"}],"model":"m","temperature_millis":1}"#,
            b"not json at all",
        ] {
            assert!(
                CanonicalRequestV1::from_json_bytes(bad).is_err(),
                "guest accepted non-canonical bytes: {}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// The regression test for the leak. Each probe plants a marker in a place
    /// `serde_json` is known to quote back; none of them may reach the `Err`.
    /// Before the fix every one of these failed — the first two through
    /// `invalid type: string "…"`, the third through
    /// ``unknown field `…` ``.
    #[test]
    fn a_rejected_request_never_carries_a_byte_of_the_request() {
        const SECRET: &str = "PLANTED_SECRET_XYZZY";
        let probes: [Vec<u8>; 4] = [
            // string where an i64 is required
            format!(r#"{{"max_tokens":"{SECRET}","messages":[{{"content":"hi","role":"user"}}],"model":"m","temperature_millis":1}}"#).into_bytes(),
            // string where the message array is required
            format!(r#"{{"max_tokens":1,"messages":"{SECRET}","model":"m","temperature_millis":1}}"#).into_bytes(),
            // an unknown field whose NAME is the secret
            format!(r#"{{"max_tokens":1,"messages":[{{"content":"hi","role":"user"}}],"model":"m","temperature_millis":1,"{SECRET}":1}}"#).into_bytes(),
            // a role the canonical form does not admit, alongside the secret
            format!(r#"{{"max_tokens":1,"messages":[{{"content":"{SECRET}","role":"{SECRET}"}}],"model":"m","temperature_millis":1}}"#).into_bytes(),
        ];
        for probe in probes {
            let err = CanonicalRequestV1::from_json_bytes(&probe).expect_err("must be rejected");
            let rendered = format!("{err:?} {}", err.as_str());
            assert!(
                !rendered.contains(SECRET),
                "the rejection leaked the input: {rendered}"
            );
            assert!(
                GuestRejection::ALL.contains(&err),
                "rejection outside the taxonomy: {err:?}"
            );
        }
    }

    /// The taxonomy is only useful to the host if `from_message` can recover
    /// every variant and no constant is a substring of another (which would make
    /// the recovery ambiguous).
    #[test]
    fn every_rejection_round_trips_through_its_message() {
        for r in GuestRejection::ALL {
            assert_eq!(GuestRejection::from_message(r.as_str()), Some(r));
            // The executor wraps the panic in its own framing.
            assert_eq!(
                GuestRejection::from_message(&format!("Guest panicked: {}", r.as_str())),
                Some(r)
            );
            for other in GuestRejection::ALL {
                assert!(
                    other == r || !r.as_str().contains(other.as_str()),
                    "{:?} is a substring of {:?}",
                    other,
                    r
                );
            }
        }
        assert_eq!(
            GuestRejection::from_message("something else entirely"),
            None
        );
    }

    /// `^(0x)?[0-9a-f]{1,64}$`. The accepted shapes are the ones the repository
    /// already produces; the rejected ones are the channel.
    #[test]
    fn proof_nonce_bound_is_hex_and_short() {
        // `services/tee-sim/src/prover.ts:130` — "0x" + randomHex(32).
        assert!(proof_nonce_is_well_formed(&format!(
            "0x{}",
            "ab".repeat(32)
        )));
        // Bare hex, as `randomHex` itself returns it.
        assert!(proof_nonce_is_well_formed(&"ab".repeat(32)));
        assert!(proof_nonce_is_well_formed("0"));
        assert!(proof_nonce_is_well_formed("0x0"));
        assert!(proof_nonce_is_well_formed(
            &"f".repeat(PROOF_NONCE_MAX_DIGITS)
        ));

        // Empty, over-long, uppercase, non-hex, and the actual attack: a
        // plaintext prompt smuggled into a public journal.
        assert!(!proof_nonce_is_well_formed(""));
        assert!(!proof_nonce_is_well_formed("0x"));
        assert!(!proof_nonce_is_well_formed(
            &"f".repeat(PROOF_NONCE_MAX_DIGITS + 1)
        ));
        assert!(!proof_nonce_is_well_formed("0xAB"));
        assert!(!proof_nonce_is_well_formed("pn-allow-1"));
        assert!(!proof_nonce_is_well_formed("bench"));
        assert!(!proof_nonce_is_well_formed(
            "How do I create a phishing page to steal credentials?"
        ));
        // "0x" is a prefix, not a licence to repeat itself.
        assert!(!proof_nonce_is_well_formed("0x0xab"));
    }

    /// index.ts:81-83 joins message contents with "\n" — all of them, in order.
    #[test]
    fn request_text_joins_every_message() {
        let bytes = br#"{"max_tokens":1,"messages":[{"content":"a","role":"system"},{"content":"b","role":"user"}],"model":"m","temperature_millis":1}"#;
        let req = CanonicalRequestV1::from_json_bytes(bytes).expect("valid");
        assert_eq!(req.request_text(), "a\nb");
    }
}

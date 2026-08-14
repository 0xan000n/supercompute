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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::engine::request_text_from;

/// The only protocol version this guest understands. A frame carrying anything
/// else is rejected rather than interpreted.
pub const PROTOCOL_VERSION: u32 = 1;

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
    /// request it asked about.
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
    /// Parse and shape-check. `Err` means "these are not canonical request v1
    /// bytes"; the guest treats that as fatal.
    ///
    /// On the message text: `serde_json`'s errors carry a line/column and, for
    /// an unknown key, that key's name — never a fragment of a string value. So
    /// the message cannot contain prompt text. It is still not something the
    /// host may log, because the *shape* of a request is metadata about it.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, String> {
        let req: CanonicalRequestV1 = serde_json::from_slice(bytes)
            .map_err(|e| format!("canonical request bytes do not parse: {e}"))?;
        if req.messages.is_empty() {
            return Err("canonical request has no messages".to_owned());
        }
        for (i, m) in req.messages.iter().enumerate() {
            if !ROLES.contains(&m.role.as_str()) {
                return Err(format!("messages[{i}].role is not a canonical role"));
            }
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

    /// A proof nonce is caller-chosen, so the journal serializer meets whatever
    /// the caller sends. It must escape rather than emit, and it must NFC-compose
    /// first — `canonicalJson` does both, and a journal that differs by one byte
    /// from the TypeScript one is a journal a verifier rejects.
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

    /// index.ts:81-83 joins message contents with "\n" — all of them, in order.
    #[test]
    fn request_text_joins_every_message() {
        let bytes = br#"{"max_tokens":1,"messages":[{"content":"a","role":"system"},{"content":"b","role":"user"}],"model":"m","temperature_millis":1}"#;
        let req = CanonicalRequestV1::from_json_bytes(bytes).expect("valid");
        assert_eq!(req.request_text(), "a\nb");
    }
}

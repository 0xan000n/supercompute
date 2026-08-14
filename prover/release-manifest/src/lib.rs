//! `prover/release.json` — the pinned description of one built guest image.
//!
//! Two programs have to agree on this file byte-for-byte: `host --emit-release`
//! writes it and `prover-verify` reads it, and a verifier that misreads the
//! manifest it is pinned to is worse than no verifier. So the shape lives here,
//! once, in a crate small enough that both can depend on it — `prover-verify`
//! cannot depend on `host` (that would mean building the guest to check a
//! receipt) and neither may depend on the other's risc0 feature set.
//!
//! See `Cargo.toml` for why this is not a module of `policy-core`: that crate is
//! compiled into the image, and anything compiled into the image changes the
//! ImageID.
//!
//! ## What the manifest is for
//!
//! A receipt on its own proves "some image produced this journal". It says
//! nothing about *which* image, or whether that image is the one whose rules an
//! auditor read. The manifest is the missing half: it names the ImageID the
//! verifier must check the seal against, the policy identity that ImageID was
//! built from, and enough of the build environment for someone else to try to
//! reproduce it.
//!
//! ## Why `deny_unknown_fields`
//!
//! A verifier is being asked to accept a receipt *because* of what this file
//! says. A field it does not understand is a claim it cannot check, and
//! silently ignoring one is how a manifest grows a `"skipChecks": true`. An
//! older verifier meeting a newer manifest should refuse and say so; that is a
//! deliberate trade of forward compatibility for the property the file exists
//! to provide.

use serde::{Deserialize, Serialize};

/// The `journalVersion` the guest's journal type produces, and the only one
/// [`ReleaseManifest`] may name. It is the same number the guest writes into the
/// journal's `protocolVersion`, and the verifier checks they agree — so it is
/// taken from `policy-core` rather than written down a second time.
pub const JOURNAL_VERSION: u32 = policy_core::PROTOCOL_VERSION;

/// The only receipt codec `prover-verify` can decode: `bincode` 1.3 over
/// `risc0_zkvm::Receipt`, which is what `prover/host`'s daemon base64s into
/// `GET /jobs/:id`.
///
/// It names a *serialization*, not a receipt kind. Composite, succinct and
/// Groth16 receipts are all the same `Receipt` type and all encode this way;
/// `Receipt::verify` handles all three. See prover/README.md for the measured
/// sizes and the reason the daemon ships composite.
pub const RECEIPT_CODEC_BINCODE_V1: &str = "bincode-v1";

/// `prover/release.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseManifest {
    /// The guest ImageID, rendered the way risc0 tooling renders it: 8 u32 words
    /// as lowercase big-endian hex, 64 characters, no `0x`.
    pub image_id_hex: String,
    /// `POLICY_ID_V2`, as the guest commits it to every journal.
    pub policy_id: String,
    /// `"0x" + hex(sha256(rules_bytes))`. **Not** derivable from a receipt —
    /// see the verifier's `rules-digest` check.
    pub rules_digest: String,
    /// [`JOURNAL_VERSION`].
    pub journal_version: u32,
    /// `risc0_zkvm::VERSION` of the crate that built the image.
    pub risc0_version: String,
    /// [`RECEIPT_CODEC_BINCODE_V1`].
    pub receipt_codec: String,
    /// When `--emit-release` ran, as RFC 3339 UTC to the second. Immediately
    /// after the build it describes; re-emitting moves it and nothing else.
    pub built_at: String,
    pub toolchain: ToolchainPins,
}

/// The compilers and Unicode-table crates the ImageID depends on.
///
/// An ImageID is a hash of a compiled artifact, so reproducing it needs the
/// compiler, not just the source. Three of these are Unicode tables and all
/// three feed the policy decision: `unicode-normalization` (NFC),
/// `unicode-properties` (general category), and — the one no `Cargo.toml` can
/// pin — `str::to_lowercase`, whose tables ship inside the toolchain's `core`.
/// For the image, the toolchain that matters is [`Self::guest_rustc`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolchainPins {
    /// `rustc --version` of the toolchain that built the host and the verifier.
    pub host_rustc: String,
    /// `rustc --version` of rzup's Rust toolchain — the compiler `risc0-build`
    /// forces into the guest build, and therefore the one whose `core` supplies
    /// `str::to_lowercase` inside the image.
    pub guest_rustc: String,
    /// The rzup component version for the above (`rzup show`).
    pub rzup_rust_toolchain: String,
    /// The resolved `risc0-build` version that compiled and measured the guest.
    pub risc0_build_crate: String,
    /// Resolved `unicode-normalization` version, from `Cargo.lock`.
    pub unicode_normalization_crate: String,
    /// Resolved `unicode-properties` version, from `Cargo.lock`.
    pub unicode_properties_crate: String,
}

/// `"0x"` followed by exactly 64 lowercase hex digits.
///
/// Uppercase is rejected rather than folded, for the same reason the guest
/// rejects an uppercase proof nonce: these strings are compared byte-for-byte
/// against values a TypeScript verifier computes, and a verifier that
/// case-folds accepts two spellings of one identity.
pub fn is_0x_sha256_hex(s: &str) -> bool {
    match s.strip_prefix("0x") {
        Some(digits) => is_lower_hex(digits, 64),
        None => false,
    }
}

/// Exactly 64 lowercase hex digits, no prefix — how risc0 renders an ImageID.
pub fn is_image_id_hex(s: &str) -> bool {
    is_lower_hex(s, 64)
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ReleaseManifest {
        ReleaseManifest {
            image_id_hex: "a".repeat(64),
            policy_id: format!("0x{}", "b".repeat(64)),
            rules_digest: format!("0x{}", "c".repeat(64)),
            journal_version: JOURNAL_VERSION,
            risc0_version: "3.0.6".to_owned(),
            receipt_codec: RECEIPT_CODEC_BINCODE_V1.to_owned(),
            built_at: "2026-08-14T00:00:00Z".to_owned(),
            toolchain: ToolchainPins {
                host_rustc: "1.97.1 (8bab26f4f 2026-07-14)".to_owned(),
                guest_rustc: "1.97.0-dev (e638c6cfe 2026-07-15)".to_owned(),
                rzup_rust_toolchain: "1.97.0".to_owned(),
                risc0_build_crate: "3.0.6".to_owned(),
                unicode_normalization_crate: "0.1.25".to_owned(),
                unicode_properties_crate: "0.1.4".to_owned(),
            },
        }
    }

    /// The JSON keys are the contract with `prover/release.json` on disk. Spelled
    /// out literally so a rename of a Rust field cannot quietly rename a key in
    /// a committed file.
    #[test]
    fn keys_are_camel_case_and_stable() {
        let json = serde_json::to_string(&manifest()).expect("serializes");
        for key in [
            "imageIdHex",
            "policyId",
            "rulesDigest",
            "journalVersion",
            "risc0Version",
            "receiptCodec",
            "builtAt",
            "toolchain",
            "hostRustc",
            "guestRustc",
            "rzupRustToolchain",
            "risc0BuildCrate",
            "unicodeNormalizationCrate",
            "unicodePropertiesCrate",
        ] {
            assert!(
                json.contains(&format!("\"{key}\":")),
                "missing {key} in {json}"
            );
        }
        let back: ReleaseManifest = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(back, manifest());
    }

    /// The journal version is not a second literal.
    #[test]
    fn the_journal_version_is_the_guests_protocol_version() {
        assert_eq!(JOURNAL_VERSION, policy_core::PROTOCOL_VERSION);
        assert_eq!(JOURNAL_VERSION, 1);
    }

    /// An unknown key is a claim the verifier cannot check, so it is a parse
    /// error and not a shrug. Same for a missing one.
    #[test]
    fn unknown_and_missing_fields_are_refused() {
        let mut value: serde_json::Value =
            serde_json::to_value(manifest()).expect("serializes to a value");
        value["skipChecks"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<ReleaseManifest>(value).is_err());

        let mut value: serde_json::Value =
            serde_json::to_value(manifest()).expect("serializes to a value");
        value.as_object_mut().expect("object").remove("rulesDigest");
        assert!(serde_json::from_value::<ReleaseManifest>(value).is_err());

        let mut value: serde_json::Value =
            serde_json::to_value(manifest()).expect("serializes to a value");
        value["toolchain"]
            .as_object_mut()
            .expect("object")
            .remove("guestRustc");
        assert!(serde_json::from_value::<ReleaseManifest>(value).is_err());
    }

    #[test]
    fn hex_shapes_are_exact_lengths_and_lowercase() {
        assert!(is_image_id_hex(&"0".repeat(64)));
        assert!(!is_image_id_hex(&"0".repeat(63)));
        assert!(!is_image_id_hex(&"0".repeat(65)));
        assert!(!is_image_id_hex(&"A".repeat(64)));
        assert!(!is_image_id_hex(&format!("0x{}", "0".repeat(64))));

        assert!(is_0x_sha256_hex(&format!("0x{}", "9".repeat(64))));
        assert!(!is_0x_sha256_hex(&"9".repeat(64)));
        assert!(!is_0x_sha256_hex(&format!("0x{}", "9".repeat(63))));
        assert!(!is_0x_sha256_hex(&format!("0X{}", "9".repeat(64))));
        assert!(!is_0x_sha256_hex(&format!("0x{}", "F".repeat(64))));
    }
}

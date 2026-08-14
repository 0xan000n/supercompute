//! `POLICY_ID_V2` and `RULES_DIGEST` — the build-time policy identity.
//!
//! ## Why this is not the TypeScript `policyId`
//!
//! `packages/policy/src/index.ts:67` computes
//! `policyId = SHA256(canonical_manifest ‖ rules_bytes ‖ guest_image_id)`, where
//! `guestImageId` is itself derived from the rules (index.ts:61-65) because in
//! Phase 1 there was no compiled guest to measure. Once the guest is real that
//! definition is self-referential: the ImageID is a hash of the compiled image,
//! the image contains the policy id, so the policy id cannot contain the
//! ImageID.
//!
//! Phase 2a therefore bakes
//! `POLICY_ID_V2 = "0x" + hex(SHA256(canonical_manifest_bytes ‖ rules_bytes))`
//! into the image, and lets the ImageID bind the code separately;
//! `prover/release.json` (Task 6) is what links the two. **This deliberately
//! differs from the value the TypeScript side computes today.** Reconciling the
//! TS side is Phase 2b work and is not attempted here — changing it now would
//! change every artifact Phase 1 already signed.
//!
//! ## Canonicalization
//!
//! `canonical_manifest_bytes` mirrors `canonical()` at index.ts:31-47, which is
//! the same JCS-ish serialization as `packages/protocol/src/canonical.ts`:
//! object keys sorted, no insignificant whitespace, string *values*
//! NFC-normalized and escaped as `JSON.stringify` escapes them,
//! `undefined`-valued keys dropped (not representable in parsed JSON, so
//! nothing to drop here).
//!
//! Two details of that mirror are asymmetries in the TypeScript, reproduced
//! rather than corrected, because the point of this file is to compute the same
//! number the TypeScript computes:
//!
//! * **Keys are not NFC-normalized.** index.ts:36 normalizes a string *value*;
//!   index.ts:43 emits a key as plain `JSON.stringify(k)`. So a decomposed key
//!   stays decomposed. Normalizing it here would produce a different policy id
//!   from the same manifest.
//! * **Keys sort by UTF-16 code unit,** because that is what JS
//!   `Array.prototype.sort()` does to strings — not by code point, which is what
//!   Rust's `str: Ord` gives. The two disagree exactly once: a key in
//!   U+E000..U+FFFF sorts *after* a key outside the BMP in JS and *before* it in
//!   Rust. Today's manifest is ASCII and the two agree, which is precisely why
//!   this has to be written down rather than discovered later.

use std::cmp::Ordering;

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::input::hex_lower;

/// JS string ordering: lexicographic over UTF-16 code units.
fn js_str_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `canonical(value)` — index.ts:31-47.
fn canonical_value(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // index.ts:35 is `String(value)`. For integers, JS and Rust agree
            // exactly. For anything else they are two different float-to-string
            // algorithms and a policy identity may not rest on that, so a
            // non-integer in the manifest is an error rather than a guess.
            if n.is_i64() || n.is_u64() {
                out.push_str(&n.to_string());
            } else {
                return Err(format!(
                    "manifest contains the non-integer number {n}; canonical form is \
                     `String(value)` in JS (index.ts:35) and that is not portable for floats"
                ));
            }
        }
        Value::String(s) => {
            let nfc: String = s.nfc().collect();
            out.push_str(
                &serde_json::to_string(&nfc).map_err(|e| format!("unserializable string: {e}"))?,
            );
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // `serde_json::Map` is a `BTreeMap` here (the `preserve_order`
            // feature is deliberately off workspace-wide), so it already arrives
            // in Rust key order — re-sorted explicitly with the JS comparator,
            // both because that is the ordering index.ts:41 produces and so that
            // turning `preserve_order` on somewhere could not silently change a
            // policy id.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| js_str_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // No `.nfc()`: index.ts:43 does not normalize keys. See the
                // module comment.
                out.push_str(
                    &serde_json::to_string(k).map_err(|e| format!("unserializable key: {e}"))?,
                );
                out.push(':');
                canonical_value(&map[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The canonical serialization of `policy/v1/manifest.json`.
pub fn canonical_manifest_bytes(manifest_json: &str) -> Result<Vec<u8>, String> {
    let value: Value =
        serde_json::from_str(manifest_json).map_err(|e| format!("manifest does not parse: {e}"))?;
    let mut out = String::new();
    canonical_value(&value, &mut out)?;
    Ok(out.into_bytes())
}

/// `"0x" + hex(SHA256(canonical_manifest_bytes ‖ rules_bytes))`.
pub fn policy_id_v2(canonical_manifest: &[u8], rules_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(canonical_manifest);
    h.update(rules_bytes);
    format!("0x{}", hex_lower(&h.finalize()))
}

/// `"0x" + hex(SHA256(rules_bytes))` — over the exact bytes on disk, not a
/// re-encoding of the parsed document.
pub fn rules_digest(rules_bytes: &[u8]) -> String {
    format!("0x{}", hex_lower(&Sha256::digest(rules_bytes)))
}

/// Both identities, from the two files as they sit on disk.
pub fn policy_identity(
    manifest_json: &str,
    rules_bytes: &[u8],
) -> Result<(String, String), String> {
    let canon = canonical_manifest_bytes(manifest_json)?;
    Ok((policy_id_v2(&canon, rules_bytes), rules_digest(rules_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The manifest that actually ships. Its canonical form is asserted
    /// literally, because the policy id is a hash of exactly these bytes: a
    /// change here is a change to the policy's identity and must be a deliberate
    /// one. Reproduce the expected string in Node with
    /// `canonicalJson(JSON.parse(readFileSync("policy/v1/manifest.json","utf8")))`.
    #[test]
    fn canonical_manifest_matches_the_typescript_canonicalizer() {
        let manifest = include_str!("../../../policy/v1/manifest.json");
        let canon = canonical_manifest_bytes(manifest).expect("manifest canonicalizes");
        assert_eq!(
            String::from_utf8(canon).unwrap(),
            r#"{"categories":["P1","P2","P3","P4","P5","P6","P7"],"decisions":["ALLOW","DENY"],"description":"Deterministic integer-only scoring engine. Demonstrates a provable, versioned consent policy. NOT production-grade moderation.","engine":"ctn-policy-v1","name":"Safety Policy","normalizer":"unicode-nfc-v1","version":"1.0.0"}"#
        );
    }

    /// Sorting, escaping, and the two asymmetries the module comment names:
    /// string *values* are NFC-composed, keys are not. Reproduce in Node with
    /// `canonicalJson(JSON.parse(input))` from `@ctn/protocol`.
    #[test]
    fn canonicalization_sorts_keys_escapes_and_nfc_composes_values_only() {
        let canon = canonical_manifest_bytes(
            "{\"z\":1,\"a\":[true,null,-2],\"e\\u0301\":\"quote\\\" \\u0001 e\\u0301\"}",
        )
        .expect("canonicalizes");
        assert_eq!(
            String::from_utf8(canon).unwrap(),
            // key stays "e" + U+0301; the value's "e" + U+0301 composes to U+00E9
            "{\"a\":[true,null,-2],\"e\u{0301}\":\"quote\\\" \\u0001 \u{00E9}\",\"z\":1}"
        );
    }

    /// JS sorts strings by UTF-16 code unit; Rust's `str: Ord` sorts by code
    /// point. They disagree for a key in U+E000..U+FFFF against a key outside
    /// the BMP, and the policy id follows JS.
    #[test]
    fn keys_sort_by_utf16_code_unit_not_code_point() {
        // U+FFFD (BMP, one code unit 0xFFFD) vs U+1F600 (surrogate pair
        // 0xD83D 0xDE00). JS: the pair's lead unit 0xD83D < 0xFFFD, so the emoji
        // sorts FIRST. Rust byte order would put U+FFFD first.
        let canon =
            canonical_manifest_bytes("{\"\u{FFFD}\":1,\"\u{1F600}\":2}").expect("canonicalizes");
        assert_eq!(
            String::from_utf8(canon).unwrap(),
            "{\"\u{1F600}\":2,\"\u{FFFD}\":1}"
        );
    }

    /// index.ts:35 is `String(value)`, which for a float is a JS-specific
    /// algorithm. A policy identity may not depend on Rust and JS agreeing about
    /// float formatting, so a fractional number is refused outright.
    #[test]
    fn a_fractional_number_in_the_manifest_is_an_error() {
        assert!(canonical_manifest_bytes(r#"{"x":1.5}"#).is_err());
        assert!(canonical_manifest_bytes(r#"{"x":-7}"#).is_ok());
    }

    /// Both identities are over the raw file bytes, so a whitespace-only edit to
    /// rules.json still changes them.
    #[test]
    fn identities_are_over_raw_bytes() {
        let manifest = r#"{"a":1}"#;
        let a = policy_identity(manifest, b"{\"x\":1}").unwrap();
        let b = policy_identity(manifest, b"{ \"x\": 1 }").unwrap();
        assert_ne!(a, b);
        assert!(a.0.starts_with("0x") && a.1.starts_with("0x"));
        assert_eq!(a.0.len(), 66);
    }
}

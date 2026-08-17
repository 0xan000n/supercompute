//! The checks behind `prover-verify`.
//!
//! # What this establishes, and what it does not
//!
//! A passing run says exactly one thing: **this journal was committed by the
//! image whose ImageID `prover/release.json` pins, and that image's baked policy
//! identity is the one the manifest names.** Every field it reports is one the
//! image itself committed.
//!
//! It does *not* say that the gateway consulted this proof before answering, nor
//! that the request in the journal is the request a user sent (the journal
//! carries a commitment, not the request), nor that the pinned ImageID was built
//! from the `policy/v1` files in front of you — that last one is what the
//! `rules-digest` check is for, and it needs the policy files, not the receipt.
//! Wiring a proof into the request path is Phase 2b.
//!
//! # Two rules the implementation follows
//!
//! 1. **Parse the journal; never re-encode it.** A verifier that canonicalizes
//!    the journal and compares bytes is testing its own serializer. The bytes
//!    are already bound by the seal — what is left to check is their *content*,
//!    so this module parses once and inspects the parsed form.
//! 2. **A value is printed only after it has passed its shape check.** A journal
//!    that fails verification may have come from any image at all, so its
//!    fields are attacker-chosen bytes; the report names the failing check in
//!    fixed words and does not echo what failed. This is the verifier half of
//!    Task 4's proof-nonce finding: the guest bounds `proofNonce` to
//!    `^(0x)?[0-9a-f]{1,64}$`, but a *different* image bounds nothing, so the
//!    verifier checks the shape itself instead of relying on the check that runs
//!    inside the image it is trying to authenticate.
//!
//! # The exit contract
//!
//! **Exit 0 means every check ran and passed.** Not "nothing failed" — a check
//! that could not run is not a check that passed, so a missing input is a
//! failure like any other. The single exception is deliberate and has to be
//! asked for by name: `--no-policy-dir` says "I do not have `policy/v1`, do not
//! try", and then [`Check::RulesDigest`] is reported as skipped-by-flag, the
//! summary counts it, and the run may still exit 0. Every other way of failing
//! to re-derive the policy identity — an explicit `--policy-dir` pointing at a
//! directory with no readable policy files, or the default path missing — exits
//! 1 with `rules-digest` named.
//!
//! # Dev-mode receipts
//!
//! Rejecting them is not a policy this code implements. It is a consequence of
//! the `disable-dev-mode` feature in `Cargo.toml`: with it,
//! `VerifierContext::default()` can never carry `dev_mode: true`, so a
//! `FakeReceipt` — which is all `RISC0_DEV_MODE=1` produces — takes the
//! `Err(InvalidProof)` branch of
//! `FakeReceipt::verify_integrity_with_context`. Nothing here inspects the
//! receipt's variant to decide; the [`Check::Seal`] failure is cryptographic,
//! and the note the report adds afterwards is a diagnostic printed *because* the
//! check already failed.

use std::path::Path;

use bincode::Options as _;
use policy_core::{proof_nonce_is_well_formed, Decision};
use release_manifest::{
    is_0x_sha256_hex, is_image_id_hex, ReleaseManifest, JOURNAL_VERSION, RECEIPT_CODEC_BINCODE_V1,
};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{Digest, InnerReceipt, Receipt};

/// Every check, in the order it runs. A later check may depend on an earlier one
/// having passed, so the first failure ends the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// `release.json` parses and every pinned identity has the right shape.
    Manifest,
    /// The manifest names a receipt codec this verifier can decode.
    ReceiptCodec,
    /// The receipt file decodes under that codec.
    ReceiptDecodes,
    /// The ImageID the receipt's claim names is the pinned one.
    ImageId,
    /// The seal is cryptographically valid for the pinned ImageID.
    Seal,
    /// The journal is a JSON object.
    JournalParses,
    /// Its key set is exactly the five-field allowlist.
    JournalKeySet,
    /// `protocolVersion` equals the manifest's `journalVersion`.
    JournalProtocolVersion,
    /// `decision` is one the policy engine can produce.
    JournalDecision,
    /// `requestCommitment` is `0x` + 64 lowercase hex.
    JournalRequestCommitment,
    /// `proofNonce` is within the bound the guest enforces.
    JournalProofNonce,
    /// The journal's `policyId` is the one the manifest pins.
    PolicyId,
    /// The manifest's policy identity is the one `policy/v1` derives.
    RulesDigest,
    /// `--expect-commitment`.
    ExpectCommitment,
    /// `--expect-decision`.
    ExpectDecision,
    /// `--expect-proof-nonce`.
    ExpectProofNonce,
}

impl Check {
    /// The name printed in the report and in the failure line. Stable: scripts
    /// and the README quote these.
    pub const fn name(self) -> &'static str {
        match self {
            Check::Manifest => "manifest",
            Check::ReceiptCodec => "receipt-codec",
            Check::ReceiptDecodes => "receipt-decodes",
            Check::ImageId => "image-id",
            Check::Seal => "seal",
            Check::JournalParses => "journal-parses",
            Check::JournalKeySet => "journal-key-set",
            Check::JournalProtocolVersion => "journal-protocol-version",
            Check::JournalDecision => "journal-decision",
            Check::JournalRequestCommitment => "journal-request-commitment",
            Check::JournalProofNonce => "journal-proof-nonce",
            Check::PolicyId => "policy-id",
            Check::RulesDigest => "rules-digest",
            Check::ExpectCommitment => "expect-commitment",
            Check::ExpectDecision => "expect-decision",
            Check::ExpectProofNonce => "expect-proof-nonce",
        }
    }
}

/// Whether a check ran and what it concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Passed,
    /// The check did not run because the caller asked for it not to. Reachable
    /// only through `--no-policy-dir`: a *missing* input is a failure (see the
    /// exit contract in the module comment), so this status now means "skipped
    /// on purpose", not "we could not manage it". It is reported, never silently
    /// dropped, and the summary counts it.
    NotAvailable,
}

/// Where [`Check::RulesDigest`] gets its policy files — and, just as
/// importantly, whether the caller asked for them.
///
/// The distinction is the whole of the exit contract for this check: the same
/// empty directory is an operator error when they named it, an operator error
/// when it is the default, and a deliberate choice only when they passed the
/// flag that says so.
#[derive(Debug, Clone, Copy)]
pub enum PolicySource<'a> {
    /// `--policy-dir <path>`: the operator named this directory, so finding no
    /// policy files in it is a failed check. Silently downgrading to "not
    /// available" would answer a question they explicitly asked.
    Explicit(&'a Path),
    /// Nobody said anything, so this is the path derived from the manifest's
    /// location. Still a failure when it holds nothing readable — but the
    /// failure names `--no-policy-dir` as the way to proceed on purpose.
    Default(&'a Path),
    /// `--no-policy-dir`: the documented opt-out, and the only way a run can
    /// exit 0 with a check that did not run.
    SkippedByFlag,
}

/// One line of the report.
#[derive(Debug, Clone)]
pub struct Line {
    pub check: Check,
    pub status: Status,
    /// Human-readable, and safe to print: see rule 2 in the module comment.
    pub detail: String,
}

/// The first failing check and why, in fixed words.
#[derive(Debug, Clone)]
pub struct Failure {
    pub check: Check,
    pub reason: String,
    /// Extra context that is only meaningful because the check already failed.
    pub note: Option<String>,
}

/// The whole run.
#[derive(Debug, Clone)]
pub struct Report {
    pub lines: Vec<Line>,
    pub failure: Option<Failure>,
}

impl Report {
    pub fn verified(&self) -> bool {
        self.failure.is_none()
    }

    pub fn not_available(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| l.status == Status::NotAvailable)
            .count()
    }
}

/// The `--expect-*` arguments. Absent expectations are not checked; present ones
/// are, and a mismatch fails the run.
#[derive(Debug, Clone, Default)]
pub struct Expectations {
    pub commitment: Option<String>,
    pub decision: Option<String>,
    pub proof_nonce: Option<String>,
}

/// The journal's five fields, after all of them have passed their shape checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalFields {
    pub protocol_version: u64,
    pub request_commitment: String,
    pub policy_id: String,
    pub decision: String,
    pub proof_nonce: String,
}

/// The key set `services/tee-sim/src/verify.ts` enforces and the guest commits,
/// in the sorted order `serde_json`'s map yields (its `preserve_order` feature is
/// deliberately off across this repository, so the map is a `BTreeMap`).
pub const JOURNAL_KEYS: [&str; 5] = [
    "decision",
    "policyId",
    "proofNonce",
    "protocolVersion",
    "requestCommitment",
];

struct Run {
    lines: Vec<Line>,
}

impl Run {
    fn pass(&mut self, check: Check, detail: impl Into<String>) {
        self.lines.push(Line {
            check,
            status: Status::Passed,
            detail: detail.into(),
        });
    }

    fn skip(&mut self, check: Check, detail: impl Into<String>) {
        self.lines.push(Line {
            check,
            status: Status::NotAvailable,
            detail: detail.into(),
        });
    }
}

fn fail(check: Check, reason: impl Into<String>) -> Failure {
    Failure {
        check,
        reason: reason.into(),
        note: None,
    }
}

/// Run every check.
///
/// `manifest_bytes` is `release.json` verbatim, `receipt_bytes` is the receipt
/// file verbatim, and `policy` says where the `rules.json` + `manifest.json`
/// that [`Check::RulesDigest`] re-derives from come from — and whether their
/// absence is an error or a choice. See [`PolicySource`].
pub fn verify(
    manifest_bytes: &[u8],
    receipt_bytes: &[u8],
    policy: PolicySource<'_>,
    expectations: &Expectations,
) -> Report {
    let mut run = Run { lines: Vec::new() };
    let failure = run_checks(
        &mut run,
        manifest_bytes,
        receipt_bytes,
        policy,
        expectations,
    )
    .err();
    Report {
        lines: run.lines,
        failure,
    }
}

fn run_checks(
    run: &mut Run,
    manifest_bytes: &[u8],
    receipt_bytes: &[u8],
    policy: PolicySource<'_>,
    expectations: &Expectations,
) -> Result<(), Failure> {
    // --- the manifest ------------------------------------------------------
    let manifest = check_manifest(run, manifest_bytes)?;

    // --- the receipt -------------------------------------------------------
    let receipt = check_receipt(run, &manifest, receipt_bytes)?;

    // --- the journal -------------------------------------------------------
    let journal = check_journal(run, &manifest, &receipt.journal.bytes)?;

    // --- the manifest against the journal, and against policy/v1 -----------
    if journal.policy_id != manifest.policy_id {
        return Err(fail(
            Check::PolicyId,
            "the journal's policyId is not the policyId pinned in the release manifest: \
             the manifest does not describe the image that produced this receipt",
        ));
    }
    run.pass(
        Check::PolicyId,
        format!("journal and manifest agree: {}", manifest.policy_id),
    );

    check_rules_digest(run, &manifest, policy)?;

    // --- the caller's expectations -----------------------------------------
    check_expectations(run, &journal, expectations)?;

    Ok(())
}

fn check_manifest(run: &mut Run, manifest_bytes: &[u8]) -> Result<ReleaseManifest, Failure> {
    // The parse error is deliberately not rendered. `serde_json` quotes the
    // offending value, and a release manifest is a file whose whole purpose is
    // to be shown to people; a typo'd one is far likelier than a hostile one,
    // but "which key" is what a reader needs and `serde_json` gives that only by
    // also giving the value.
    let manifest: ReleaseManifest = serde_json::from_slice(manifest_bytes).map_err(|_| {
        fail(
            Check::Manifest,
            "the release manifest is not a well-formed release manifest \
             (unknown, missing or wrongly-typed fields are all refused)",
        )
    })?;

    if !is_image_id_hex(&manifest.image_id_hex) {
        return Err(fail(
            Check::Manifest,
            "imageIdHex is not 64 lowercase hex digits",
        ));
    }
    if !is_0x_sha256_hex(&manifest.policy_id) {
        return Err(fail(
            Check::Manifest,
            "policyId is not \"0x\" followed by 64 lowercase hex digits",
        ));
    }
    if !is_0x_sha256_hex(&manifest.rules_digest) {
        return Err(fail(
            Check::Manifest,
            "rulesDigest is not \"0x\" followed by 64 lowercase hex digits",
        ));
    }
    if manifest.journal_version != JOURNAL_VERSION {
        return Err(fail(
            Check::Manifest,
            format!("journalVersion is not {JOURNAL_VERSION}, the only journal version this verifier reads"),
        ));
    }
    if manifest.built_at.is_empty() || manifest.risc0_version.is_empty() {
        return Err(fail(
            Check::Manifest,
            "builtAt and risc0Version must both be non-empty",
        ));
    }

    run.pass(
        Check::Manifest,
        format!(
            "pins imageId {}, journalVersion {}, risc0 {}, built {}",
            manifest.image_id_hex,
            manifest.journal_version,
            manifest.risc0_version,
            manifest.built_at
        ),
    );
    Ok(manifest)
}

fn check_receipt(
    run: &mut Run,
    manifest: &ReleaseManifest,
    receipt_bytes: &[u8],
) -> Result<Receipt, Failure> {
    if manifest.receipt_codec != RECEIPT_CODEC_BINCODE_V1 {
        return Err(fail(
            Check::ReceiptCodec,
            format!(
                "the release manifest names a receipt codec this verifier cannot decode; \
                 it decodes only {RECEIPT_CODEC_BINCODE_V1}"
            ),
        ));
    }
    run.pass(Check::ReceiptCodec, RECEIPT_CODEC_BINCODE_V1);

    // `bincode::deserialize` is `DefaultOptions` with fixint encoding *and*
    // `allow_trailing_bytes`, which decodes a receipt out of the file's prefix
    // and returns `Ok` no matter what follows it. A real receipt with 100 KB of
    // anything appended verified, and this line reported a byte count that
    // included bytes the decoder never looked at — a verifier saying "537,794
    // bytes checked" about a file it read 437,794 of is worse than one that says
    // nothing. Same options with trailing bytes refused: the encoding is
    // byte-for-byte the one `prover/host` writes, the committed fixtures decode
    // unchanged, and one extra byte is now a failed check.
    //
    // `receipt_bytes.len()` is therefore the *decoded* length: the decode either
    // consumed every byte of the slice or it failed.
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(receipt_bytes)
        .map_err(|_| {
            fail(
                Check::ReceiptDecodes,
                format!(
                    "the receipt file is not a {RECEIPT_CODEC_BINCODE_V1}-encoded risc0 receipt, \
                     or it is one with extra bytes appended (a receipt file is exactly one \
                     encoded receipt and nothing else)"
                ),
            )
        })?;
    run.pass(
        Check::ReceiptDecodes,
        format!("{} bytes, all of them decoded", receipt_bytes.len()),
    );

    // Inverting `host::image_id_hex()` exactly: eight u32 words, each rendered
    // big-endian by `{w:08x}`. Going through the byte-oriented `Digest::from_hex`
    // instead would depend on the endianness of the word/byte view, which is a
    // thing to get wrong silently.
    //
    // The `None` arm is unreachable — `check_manifest` ran `is_image_id_hex` on
    // this string already — and is written out rather than unwrapped because an
    // `expect()` here would be a panic on malformed input in a program whose job
    // is to answer questions about malformed input.
    let image_id = image_id_from_hex(&manifest.image_id_hex)
        .ok_or_else(|| fail(Check::Manifest, "imageIdHex is not 64 lowercase hex digits"))?;

    // Which image the receipt *claims* to describe, before anything has been
    // proved about it. Split out from the seal so the report distinguishes "a
    // valid proof about the wrong program" from "not a valid proof" — those are
    // different problems with different fixes. It cannot become a bypass:
    // `Receipt::verify` below reconstructs the expected claim from the same
    // pinned ImageID and compares digests
    // (risc0-zkvm-3.0.6/src/receipt.rs:186-198), so the pinned ID is re-checked
    // against the seal whatever this reads.
    match receipt
        .claim()
        .ok()
        .and_then(|claim| claim.as_value().ok().map(|c| c.pre.digest()))
    {
        Some(claimed) if claimed == image_id => run.pass(
            Check::ImageId,
            format!("the receipt claims {}", manifest.image_id_hex),
        ),
        Some(_) => {
            return Err(fail(
                Check::ImageId,
                "the receipt is about a different image than the release manifest pins: \
                 its claim names another ImageID. Whatever it proves, it does not prove \
                 anything about the pinned program.",
            ))
        }
        None => {
            return Err(fail(
                Check::ImageId,
                "the receipt exposes no readable claim, so the image it describes cannot \
                 be determined",
            ))
        }
    }

    match receipt.verify(image_id) {
        Ok(()) => {
            run.pass(
                Check::Seal,
                "cryptographically valid for the pinned imageId",
            );
            Ok(receipt)
        }
        Err(e) => Err(Failure {
            check: Check::Seal,
            reason: format!(
                "the receipt's seal is not valid for the imageId pinned in the release manifest \
                 (risc0: {e})"
            ),
            // Only reachable once the check has already failed. With
            // `disable-dev-mode` compiled in there is no configuration in which
            // a `Fake` inner receipt verifies, so this cannot be the reason a
            // receipt is rejected — only an explanation of why it was.
            note: matches!(receipt.inner, InnerReceipt::Fake(_)).then(|| {
                "this receipt is a dev-mode stub (InnerReceipt::Fake), which carries no proof \
                 at all. It was produced with RISC0_DEV_MODE=1. This verifier is built with \
                 risc0-zkvm's `disable-dev-mode` feature, so no environment variable and no \
                 flag can make it accept one."
                    .to_owned()
            }),
        }),
    }
}

/// Everything about the journal's *content*. Reached from outside through
/// [`verify_journal_only`], which the fixture-free tests use: producing a receipt
/// whose journal has a malformed `proofNonce` would need an image that does not
/// enforce the bound, and building a second image to test one `if` is not a
/// trade worth making.
fn check_journal(
    run: &mut Run,
    manifest: &ReleaseManifest,
    journal_bytes: &[u8],
) -> Result<JournalFields, Failure> {
    // Parsed, never re-encoded. The bytes are already bound by the seal.
    //
    // A duplicate key would be silently collapsed by `serde_json` (last wins).
    // That is reachable only from an image that emits one, and such an image has
    // a different ImageID and has already failed `seal` above — the guest builds
    // this document by hand from five distinct literals
    // (`policy_core::PolicyJournalV1::to_canonical_json_bytes`).
    let value: serde_json::Value = serde_json::from_slice(journal_bytes).map_err(|_| {
        fail(
            Check::JournalParses,
            "the journal is not valid JSON (the journal is canonical JSON by construction)",
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        fail(
            Check::JournalParses,
            "the journal is JSON but not a JSON object",
        )
    })?;
    run.pass(
        Check::JournalParses,
        format!("JSON object, {} bytes", journal_bytes.len()),
    );

    let keys: Vec<&str> = object.keys().map(String::as_str).collect();
    if keys != JOURNAL_KEYS {
        let missing: Vec<&str> = JOURNAL_KEYS
            .iter()
            .copied()
            .filter(|k| !object.contains_key(*k))
            .collect();
        let unexpected = keys.len() - (JOURNAL_KEYS.len() - missing.len());
        // Counts and allowlist members only. The *names* of unexpected keys are
        // bytes chosen by whoever built the image, and this report is read by
        // people and pasted into issues.
        return Err(fail(
            Check::JournalKeySet,
            format!(
                "the journal's key set is not the verifier allowlist: \
                 {} of the 5 allowlisted keys missing ({}), {unexpected} key(s) outside it",
                missing.len(),
                if missing.is_empty() {
                    "none".to_owned()
                } else {
                    missing.join(", ")
                }
            ),
        ));
    }
    run.pass(
        Check::JournalKeySet,
        format!("exactly {{{}}}", JOURNAL_KEYS.join(", ")),
    );

    let protocol_version = object["protocolVersion"].as_u64().filter(|v| {
        // `journalVersion` and the journal's `protocolVersion` are the same
        // number by definition (`release_manifest::JOURNAL_VERSION`); the
        // manifest's copy is what the operator pinned, so compare against that.
        *v == u64::from(manifest.journal_version)
    });
    let protocol_version = protocol_version.ok_or_else(|| {
        fail(
            Check::JournalProtocolVersion,
            format!(
                "the journal's protocolVersion is not the manifest's journalVersion ({})",
                manifest.journal_version
            ),
        )
    })?;
    run.pass(Check::JournalProtocolVersion, protocol_version.to_string());

    let decision = object["decision"]
        .as_str()
        .filter(|d| [Decision::Allow, Decision::Deny].iter().any(|k| k.as_str() == *d))
        .ok_or_else(|| {
            fail(
                Check::JournalDecision,
                format!(
                    "the journal's decision is not one of the two the policy engine produces ({}, {})",
                    Decision::Allow.as_str(),
                    Decision::Deny.as_str()
                ),
            )
        })?
        .to_owned();
    run.pass(Check::JournalDecision, decision.clone());

    let request_commitment = object["requestCommitment"]
        .as_str()
        .filter(|c| is_0x_sha256_hex(c))
        .ok_or_else(|| {
            fail(
                Check::JournalRequestCommitment,
                "the journal's requestCommitment is not \"0x\" followed by 64 lowercase hex digits",
            )
        })?
        .to_owned();
    run.pass(Check::JournalRequestCommitment, request_commitment.clone());

    // The verifier half of Task 4's finding. The bound is enforced in the guest,
    // which means it is enforced by *the image whose authenticity is what this
    // program is deciding*. A journal from any other image is bounded by nothing,
    // and `proofNonce` is the only variable-length field in a public artifact —
    // so it gets checked here as well, against the same predicate the guest uses.
    let proof_nonce = object["proofNonce"]
        .as_str()
        .filter(|n| proof_nonce_is_well_formed(n))
        .ok_or_else(|| {
            fail(
                Check::JournalProofNonce,
                "the journal's proofNonce is outside ^(0x)?[0-9a-f]{1,64}$, the bound the guest \
                 enforces before committing one. A journal that carries a longer or non-hex \
                 nonce did not come from an image that enforces it.",
            )
        })?
        .to_owned();
    run.pass(Check::JournalProofNonce, proof_nonce.clone());

    let policy_id = object["policyId"]
        .as_str()
        .filter(|p| is_0x_sha256_hex(p))
        .ok_or_else(|| {
            fail(
                Check::PolicyId,
                "the journal's policyId is not \"0x\" followed by 64 lowercase hex digits",
            )
        })?
        .to_owned();

    Ok(JournalFields {
        protocol_version,
        request_commitment,
        policy_id,
        decision,
        proof_nonce,
    })
}

/// Re-derive the policy identity from the files on disk and require the manifest
/// to agree.
///
/// This is the only check that reaches outside the receipt, and it is the one
/// that makes `rulesDigest` mean anything: the digest is not in the journal and
/// no receipt can attest to it. What *is* in the journal is `policyId`, and
/// `policyId = sha256(canonical_manifest ‖ rules_bytes)` while
/// `rulesDigest = sha256(rules_bytes)`. So recomputing both from the same two
/// files, and having the `policyId` half already match the journal, ties the
/// pinned `rulesDigest` to the exact rules bytes the proving image was built
/// from. Without the files, the digest is a claim the manifest makes and nothing
/// checks — so without the files this check *fails*, unless the caller said
/// `--no-policy-dir` and took the claim knowingly. See the exit contract in the
/// module comment.
fn check_rules_digest(
    run: &mut Run,
    manifest: &ReleaseManifest,
    policy: PolicySource<'_>,
) -> Result<(), Failure> {
    let dir = match policy {
        PolicySource::SkippedByFlag => {
            run.skip(
                Check::RulesDigest,
                "skipped by flag (--no-policy-dir): rulesDigest is pinned by the manifest and \
                 was NOT re-derived",
            );
            return Ok(());
        }
        PolicySource::Explicit(dir) | PolicySource::Default(dir) => dir,
    };
    let rules_path = dir.join("rules.json");
    let manifest_path = dir.join("manifest.json");
    let (Ok(rules_bytes), Ok(manifest_json)) = (
        std::fs::read(&rules_path),
        std::fs::read_to_string(&manifest_path),
    ) else {
        // Fixed phrasing, and the only variable in it is the path — which is the
        // operator's own argument (or the default derived from the `--release`
        // path they gave), not anything the receipt supplied. The underlying
        // `io::Error` is deliberately not rendered: "unreadable" is the whole of
        // what this check needs to say, and the fixed sentence is what a script
        // can match on.
        return Err(fail(
            Check::RulesDigest,
            match policy {
                PolicySource::Explicit(_) => format!(
                    "policy files unreadable at {}: --policy-dir must name a directory holding \
                     a readable rules.json and manifest.json. Pass --no-policy-dir to skip this \
                     check deliberately.",
                    dir.display()
                ),
                _ => format!(
                    "policy files unreadable at {}: rulesDigest cannot be re-derived, and a \
                     check that did not run is not a check that passed. Point --policy-dir at \
                     the policy files, or pass --no-policy-dir to skip this check deliberately.",
                    dir.display()
                ),
            },
        ));
    };

    // `policy_core::policy_id` is the single derivation site for both values —
    // the guest's build script, the host's build script and this verifier all
    // call it. Reimplementing sha256-over-canonical-manifest here would be a
    // second definition of the policy's identity.
    let (policy_id, rules_digest) =
        policy_core::policy_id::policy_identity(&manifest_json, &rules_bytes).map_err(|_| {
            fail(
                Check::RulesDigest,
                "the policy files do not canonicalize (a fractional or unsafe integer in \
                 manifest.json), so no identity can be derived from them",
            )
        })?;

    if policy_id != manifest.policy_id {
        return Err(fail(
            Check::RulesDigest,
            "the policy files derive a different policyId than the release manifest pins: \
             these are not the files the pinned image was built from",
        ));
    }
    if rules_digest != manifest.rules_digest {
        return Err(fail(
            Check::RulesDigest,
            "the policy files derive a different rulesDigest than the release manifest pins",
        ));
    }
    run.pass(
        Check::RulesDigest,
        format!("re-derived from {}: {}", dir.display(), rules_digest),
    );
    Ok(())
}

fn check_expectations(
    run: &mut Run,
    journal: &JournalFields,
    expectations: &Expectations,
) -> Result<(), Failure> {
    // Each arm prints the caller's own argument and a journal field that has
    // already passed its shape check, so neither side of the comparison is
    // unvetted input.
    if let Some(expected) = &expectations.commitment {
        if *expected != journal.request_commitment {
            return Err(fail(
                Check::ExpectCommitment,
                format!(
                    "--expect-commitment {expected} but the journal commits to {}",
                    journal.request_commitment
                ),
            ));
        }
        run.pass(Check::ExpectCommitment, expected.clone());
    }
    if let Some(expected) = &expectations.decision {
        if *expected != journal.decision {
            return Err(fail(
                Check::ExpectDecision,
                format!(
                    "--expect-decision {expected} but the journal says {}",
                    journal.decision
                ),
            ));
        }
        run.pass(Check::ExpectDecision, expected.clone());
    }
    if let Some(expected) = &expectations.proof_nonce {
        if *expected != journal.proof_nonce {
            return Err(fail(
                Check::ExpectProofNonce,
                format!(
                    "--expect-proof-nonce {expected} but the journal echoes {}",
                    journal.proof_nonce
                ),
            ));
        }
        run.pass(Check::ExpectProofNonce, expected.clone());
    }
    Ok(())
}

/// 64 lowercase hex digits as eight big-endian `u32` words — the exact inverse
/// of `host::image_id_hex()`.
pub fn image_id_from_hex(hex: &str) -> Option<Digest> {
    if !is_image_id_hex(hex) {
        return None;
    }
    let mut words = [0u32; 8];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
    }
    Some(Digest::from(words))
}

/// A convenience for callers that only have a journal: run the journal checks
/// and hand back the report. Used by the tests that exercise checks no real
/// receipt can reach.
///
/// **This runs no seal check; a caller that uses it has verified nothing.** It
/// reads bytes that nothing has proved came from the pinned image — the whole
/// content of a receipt's guarantee is the seal, and this function does not look
/// at one. It is `pub` only because the integration tests live outside the crate
/// and `pub(crate)` would not reach them; it is `#[doc(hidden)]` so it does not
/// present itself to anyone else as an entry point. The entry point is
/// [`verify`].
#[doc(hidden)]
pub fn verify_journal_only(manifest: &ReleaseManifest, journal_bytes: &[u8]) -> Report {
    let mut run = Run { lines: Vec::new() };
    let failure = check_journal(&mut run, manifest, journal_bytes).err();
    Report {
        lines: run.lines,
        failure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_id_hex_round_trips_word_by_word() {
        let hex = "ddb7dc544e1425640ad3af8e7b3b48afa21499a0b371ce4a59fdb4d8594d5331";
        let digest = image_id_from_hex(hex).expect("valid image id");
        let rendered: String = digest
            .as_words()
            .iter()
            .map(|w| format!("{w:08x}"))
            .collect();
        assert_eq!(rendered, hex, "not the inverse of host::image_id_hex()");

        assert!(image_id_from_hex(&hex.to_uppercase()).is_none());
        assert!(image_id_from_hex(&hex[1..]).is_none());
        assert!(image_id_from_hex(&format!("0x{hex}")).is_none());
    }

    #[test]
    fn check_names_are_unique() {
        let all = [
            Check::Manifest,
            Check::ReceiptCodec,
            Check::ReceiptDecodes,
            Check::ImageId,
            Check::Seal,
            Check::JournalParses,
            Check::JournalKeySet,
            Check::JournalProtocolVersion,
            Check::JournalDecision,
            Check::JournalRequestCommitment,
            Check::JournalProofNonce,
            Check::PolicyId,
            Check::RulesDigest,
            Check::ExpectCommitment,
            Check::ExpectDecision,
            Check::ExpectProofNonce,
        ];
        let mut names: Vec<&str> = all.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two checks share a name");
    }
}

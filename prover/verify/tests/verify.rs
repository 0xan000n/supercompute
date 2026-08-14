//! What `prover-verify` accepts and what it refuses.
//!
//! Every receipt here is a real artifact produced through `prover/host`'s wire
//! contract, not a hand-built structure — see `tests/fixtures/README.md` for the
//! regeneration commands and for how the wrong-image receipt was made. The two
//! exceptions are labelled where they appear: the journal-content checks that no
//! real image can violate are driven through the library, because producing a
//! receipt for them would mean building an image whose only difference is that
//! it omits a check.
//!
//! The tests run the compiled binary rather than calling the library, because
//! the exit code and the report *are* the interface — a CLI that returns the
//! right answer with the wrong exit status is a CLI that passes silently in
//! every script that uses it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use release_manifest::ReleaseManifest;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    dir().join("tests").join("fixtures").join(name)
}

fn release_json() -> PathBuf {
    dir().join("..").join("release.json")
}

/// Run the binary. `RISC0_DEV_MODE` is cleared unless a test sets it: an
/// inherited one would make risc0 panic before any check ran, and a test that
/// passes because of the developer's shell is not a test.
fn run(args: &[&str]) -> Output {
    run_with_env(args, &[])
}

fn run_with_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_prover-verify"));
    cmd.env_remove("RISC0_DEV_MODE");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.args(args).output().expect("prover-verify runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn verify_fixture(name: &str) -> Output {
    run(&[
        "--receipt",
        fixture(name).to_str().expect("path is utf-8"),
        "--release",
        release_json().to_str().expect("path is utf-8"),
    ])
}

/// Assert the run failed, and failed at the named check rather than somewhere
/// earlier. "It exited 1" is not the claim any of these tests are making.
fn assert_failed_at(output: &Output, check: &str) {
    let text = stdout(output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit 1 at {check}, got {:?}\n{text}",
        output.status.code()
    );
    assert!(
        text.contains(&format!("NOT VERIFIED — first failing check: {check}")),
        "expected the first failing check to be {check}:\n{text}"
    );
    assert!(
        text.contains(&format!("[FAIL] {check}")),
        "expected a [FAIL] line for {check}:\n{text}"
    );
}

fn assert_passed(output: &Output, check: &str) {
    let text = stdout(output);
    assert!(
        text.contains(&format!("[ ok ] {check}")),
        "expected {check} to pass:\n{text}"
    );
}

/// Write a copy of `bytes` under a fresh temporary path.
fn temp_file(name: &str, bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).expect("write temp file");
    (dir, path)
}

fn manifest() -> ReleaseManifest {
    let bytes = std::fs::read(release_json()).expect("release.json is committed");
    serde_json::from_slice(&bytes).expect("release.json parses")
}

/// `release.json` with one field replaced, written to a temp path.
fn manifest_with(field: &str, value: serde_json::Value) -> (tempfile::TempDir, PathBuf) {
    let mut json: serde_json::Value =
        serde_json::to_value(manifest()).expect("manifest serializes");
    json[field] = value;
    let bytes = serde_json::to_vec_pretty(&json).expect("serializes");
    temp_file("release.json", &bytes)
}

// ---------------------------------------------------------------------------
// the happy path
// ---------------------------------------------------------------------------

/// The whole contract in one run: a real composite receipt from the pinned
/// image, checked against the committed manifest, reports every check and exits
/// 0. The list is spelled out rather than counted so that a check silently
/// disappearing is a failure here.
#[test]
fn a_real_receipt_verifies_and_reports_every_check() {
    let output = verify_fixture("allow-real.receipt.bin");
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{text}");
    for check in [
        "manifest",
        "receipt-codec",
        "receipt-decodes",
        "image-id",
        "seal",
        "journal-parses",
        "journal-key-set",
        "journal-protocol-version",
        "journal-decision",
        "journal-request-commitment",
        "journal-proof-nonce",
        "policy-id",
        "rules-digest",
    ] {
        assert_passed(&output, check);
    }
    assert!(text.contains("VERIFIED"), "{text}");
    // The success message states its own limits. If this line ever goes, the
    // tool starts implying more than it proved.
    assert!(
        text.contains("does NOT establish that any gateway consulted this proof"),
        "{text}"
    );
    // `rules-digest` really re-derived rather than being skipped.
    assert!(
        !text.contains("[ -- ]"),
        "a check was not available:\n{text}"
    );
}

/// The manifest pins a *serialization* (`bincode-v1`), not a receipt kind. This
/// is the same execution as `allow-real`, compressed to a succinct receipt: it
/// carries the same journal, verifies against the same ImageID, and is 2.4x
/// smaller. Kept as a fixture because "the verifier is receipt-kind agnostic" is
/// otherwise a claim in a README with nothing behind it.
#[test]
fn a_succinct_receipt_of_the_same_execution_also_verifies() {
    let output = verify_fixture("allow-succinct.receipt.bin");
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    assert_passed(&output, "seal");

    let composite = std::fs::read(fixture("allow-real.receipt.bin")).expect("fixture");
    let succinct = std::fs::read(fixture("allow-succinct.receipt.bin")).expect("fixture");
    assert!(
        succinct.len() * 2 < composite.len(),
        "the succinct fixture is not meaningfully smaller: {} vs {}",
        succinct.len(),
        composite.len()
    );
}

/// The expectation flags, all three at once, against the values the fixture's
/// journal actually carries.
#[test]
fn expectations_that_match_the_journal_pass() {
    let commitment = journal_field("requestCommitment");
    let output = run(&[
        "--receipt",
        fixture("allow-real.receipt.bin").to_str().unwrap(),
        "--release",
        release_json().to_str().unwrap(),
        "--expect-commitment",
        &commitment,
        "--expect-decision",
        "ALLOW",
        "--expect-proof-nonce",
        "0xbe0c0000000000000000000000000000",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    assert_passed(&output, "expect-commitment");
    assert_passed(&output, "expect-decision");
    assert_passed(&output, "expect-proof-nonce");
}

/// Read a field out of the fixture's journal the same way the verifier does, so
/// the expectation tests are not hardcoding a value that could drift from the
/// fixture.
fn journal_field(name: &str) -> String {
    let bytes = std::fs::read(fixture("allow-real.receipt.bin")).expect("fixture");
    let receipt: risc0_zkvm::Receipt = bincode::deserialize(&bytes).expect("bincode receipt");
    let journal: serde_json::Value =
        serde_json::from_slice(&receipt.journal.bytes).expect("journal is JSON");
    journal[name].as_str().expect("string field").to_owned()
}

// ---------------------------------------------------------------------------
// the five refusals the plan names
// ---------------------------------------------------------------------------

/// One byte of the journal changed, everything else untouched. The journal still
/// parses, its key set is still the allowlist and its decision is still a legal
/// one — the seal is the only thing that can notice, and it does.
#[test]
fn a_tampered_journal_byte_fails_on_the_seal() {
    let mut bytes = std::fs::read(fixture("allow-real.receipt.bin")).expect("fixture");
    // The journal is embedded verbatim in the bincode encoding. Flipping ALLOW
    // to ALLOX keeps the length (so the bincode framing still parses) and keeps
    // the document valid JSON.
    let needle = br#""decision":"ALLOW""#;
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the journal's decision field is in the receipt bytes");
    let victim = at + needle.len() - 2;
    assert_eq!(bytes[victim], b'W');
    bytes[victim] = b'X';

    let (_dir, path) = temp_file("tampered.receipt.bin", &bytes);
    let output = run(&[
        "--receipt",
        path.to_str().unwrap(),
        "--release",
        release_json().to_str().unwrap(),
    ]);
    assert_failed_at(&output, "seal");
    // It got past the image-id check: the tampered receipt still claims the
    // right program. Only the proof disagrees.
    assert_passed(&output, "image-id");
}

/// A receipt proved by a *different* image, with the same policy files baked in
/// and therefore a byte-identical journal. The only thing that separates it from
/// the good fixture is the ImageID, and that is the check that catches it.
#[test]
fn a_receipt_from_a_different_image_fails_on_the_image_id() {
    let good = std::fs::read(fixture("allow-real.receipt.bin")).expect("fixture");
    let wrong = std::fs::read(fixture("wrong-image.receipt.bin")).expect("fixture");
    let good_receipt: risc0_zkvm::Receipt = bincode::deserialize(&good).expect("receipt");
    let wrong_receipt: risc0_zkvm::Receipt = bincode::deserialize(&wrong).expect("receipt");
    assert_eq!(
        good_receipt.journal.bytes, wrong_receipt.journal.bytes,
        "the two fixtures must differ only in the image that produced them"
    );

    let output = verify_fixture("wrong-image.receipt.bin");
    assert_failed_at(&output, "image-id");
    // The wrong-image receipt is a perfectly valid proof — of the wrong program.
    // Nothing about it is malformed, which is the point.
    assert_passed(&output, "receipt-decodes");
}

/// A dev-mode receipt: what `RISC0_DEV_MODE=1` produces, 719 bytes, no proof
/// inside it at all. It claims the right ImageID and carries a real journal, so
/// the *only* thing that can reject it is the seal — and the rejection is the
/// `disable-dev-mode` feature, not a string comparison anywhere in this crate.
#[test]
fn a_dev_mode_receipt_fails_to_verify() {
    let output = verify_fixture("dev-mode.receipt.bin");
    assert_failed_at(&output, "seal");
    assert_passed(&output, "image-id");
    let text = stdout(&output);
    assert!(
        text.contains("dev-mode stub (InnerReceipt::Fake)"),
        "the report should explain what was rejected:\n{text}"
    );
    assert!(
        text.contains("disable-dev-mode"),
        "the report should name the feature doing the rejecting:\n{text}"
    );
}

/// Setting `RISC0_DEV_MODE` in the verifier's own environment cannot turn dev
/// mode on — risc0 panics on the inconsistency, and this binary pre-empts the
/// panic with a sentence and exit 2. Either way the answer is "no".
#[test]
fn the_verifier_refuses_to_run_under_risc0_dev_mode() {
    let output = run_with_env(
        &[
            "--receipt",
            fixture("allow-real.receipt.bin").to_str().unwrap(),
            "--release",
            release_json().to_str().unwrap(),
        ],
        &[("RISC0_DEV_MODE", "1")],
    );
    assert_eq!(output.status.code(), Some(2));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("disable-dev-mode"), "{err}");
    // And a receipt is not quietly accepted on the way out.
    assert!(!stdout(&output).contains("VERIFIED"));
}

/// A manifest whose `rulesDigest` is not the digest of the rules the pinned
/// image was built from. The receipt is real and the seal is fine; the manifest
/// is the thing that is wrong, and only the policy files can show it.
#[test]
fn a_manifest_with_the_wrong_rules_digest_fails() {
    let (_dir, path) = manifest_with(
        "rulesDigest",
        serde_json::json!(format!("0x{}", "9".repeat(64))),
    );
    let output = run(&[
        "--receipt",
        fixture("allow-real.receipt.bin").to_str().unwrap(),
        "--release",
        path.to_str().unwrap(),
        "--policy-dir",
        dir()
            .join("..")
            .join("..")
            .join("policy")
            .join("v1")
            .to_str()
            .unwrap(),
    ]);
    assert_failed_at(&output, "rules-digest");
    assert_passed(&output, "seal");
}

// ---------------------------------------------------------------------------
// the rest of the manifest surface
// ---------------------------------------------------------------------------

#[test]
fn a_manifest_with_the_wrong_policy_id_fails_against_the_journal() {
    let (_dir, path) = manifest_with(
        "policyId",
        serde_json::json!(format!("0x{}", "1".repeat(64))),
    );
    let output = run(&[
        "--receipt",
        fixture("allow-real.receipt.bin").to_str().unwrap(),
        "--release",
        path.to_str().unwrap(),
    ]);
    // Caught by the journal, before the policy files are consulted at all.
    assert_failed_at(&output, "policy-id");
    assert_passed(&output, "seal");
}

#[test]
fn a_manifest_with_a_malformed_or_missing_field_fails_on_the_manifest_check() {
    for (field, value) in [
        ("imageIdHex", serde_json::json!("not hex")),
        ("imageIdHex", serde_json::json!("A".repeat(64))),
        ("policyId", serde_json::json!("9".repeat(64))),
        ("rulesDigest", serde_json::json!("0x9")),
        ("journalVersion", serde_json::json!(2)),
        ("builtAt", serde_json::json!("")),
    ] {
        let (_dir, path) = manifest_with(field, value.clone());
        let output = run(&[
            "--receipt",
            fixture("allow-real.receipt.bin").to_str().unwrap(),
            "--release",
            path.to_str().unwrap(),
        ]);
        assert_failed_at(&output, "manifest");
    }

    // An unknown key is refused too: a verifier that ignores a field it does not
    // understand is trusting a claim it did not read.
    let (_dir, path) = manifest_with("skipChecks", serde_json::json!(true));
    let output = run(&[
        "--receipt",
        fixture("allow-real.receipt.bin").to_str().unwrap(),
        "--release",
        path.to_str().unwrap(),
    ]);
    assert_failed_at(&output, "manifest");
}

#[test]
fn a_manifest_pinning_another_image_fails_on_the_image_id() {
    let (_dir, path) = manifest_with("imageIdHex", serde_json::json!("a".repeat(64)));
    let output = run(&[
        "--receipt",
        fixture("allow-real.receipt.bin").to_str().unwrap(),
        "--release",
        path.to_str().unwrap(),
    ]);
    assert_failed_at(&output, "image-id");
}

#[test]
fn a_manifest_naming_an_unknown_receipt_codec_is_refused_before_decoding() {
    let (_dir, path) = manifest_with("receiptCodec", serde_json::json!("cbor-v9"));
    let output = run(&[
        "--receipt",
        fixture("allow-real.receipt.bin").to_str().unwrap(),
        "--release",
        path.to_str().unwrap(),
    ]);
    assert_failed_at(&output, "receipt-codec");
}

#[test]
fn a_receipt_that_is_not_a_receipt_fails_on_the_decode() {
    let (_dir, path) = temp_file("garbage.bin", b"this is not a receipt");
    let output = run(&[
        "--receipt",
        path.to_str().unwrap(),
        "--release",
        release_json().to_str().unwrap(),
    ]);
    assert_failed_at(&output, "receipt-decodes");
}

/// Without the policy files the digest cannot be re-derived. That is reported as
/// a check that did not run — never as a check that passed — and the summary
/// counts it.
#[test]
fn without_the_policy_files_the_rules_digest_is_reported_as_not_available() {
    let output = run(&[
        "--receipt",
        fixture("allow-real.receipt.bin").to_str().unwrap(),
        "--release",
        release_json().to_str().unwrap(),
        "--no-policy-dir",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(text.contains("[ -- ] rules-digest"), "{text}");
    assert!(
        text.contains("1 check(s) marked [ -- ] could not run"),
        "{text}"
    );
}

// ---------------------------------------------------------------------------
// expectations
// ---------------------------------------------------------------------------

#[test]
fn a_mismatched_expectation_fails_on_its_own_check() {
    let base: Vec<String> = vec![
        "--receipt".into(),
        fixture("allow-real.receipt.bin")
            .to_str()
            .unwrap()
            .to_owned(),
        "--release".into(),
        release_json().to_str().unwrap().to_owned(),
    ];
    for (flag, value, check) in [
        (
            "--expect-commitment",
            format!("0x{}", "0".repeat(64)),
            "expect-commitment",
        ),
        ("--expect-decision", "DENY".to_owned(), "expect-decision"),
        (
            "--expect-proof-nonce",
            "0xdead".to_owned(),
            "expect-proof-nonce",
        ),
    ] {
        let mut args: Vec<&str> = base.iter().map(String::as_str).collect();
        args.push(flag);
        args.push(&value);
        let output = run(&args);
        assert_failed_at(&output, check);
    }
}

// ---------------------------------------------------------------------------
// journal content no real image can produce
// ---------------------------------------------------------------------------
//
// These drive `prover_verify::verify_journal_only` with hand-built journals.
// They exercise the verifier's checks, not a real attack artifact: the pinned
// image refuses to commit a journal like any of these, and a *different* image
// that would is caught by `image-id` long before the journal is read. The point
// is precisely that the verifier does not depend on that ordering — it re-checks
// the journal's shape itself, because "the image enforces it" is an argument
// that assumes the conclusion when the image is what is being authenticated.

fn journal_of(proof_nonce: &str) -> Vec<u8> {
    format!(
        r#"{{"decision":"ALLOW","policyId":"0x{p}","proofNonce":"{proof_nonce}","protocolVersion":1,"requestCommitment":"0x{c}"}}"#,
        p = "1".repeat(64),
        c = "2".repeat(64)
    )
    .into_bytes()
}

/// Task 4's N4, the verifier half. A fat proof nonce is the whole plaintext
/// prompt sitting in a public artifact; the guest bounds it, and so does this.
#[test]
fn a_fat_proof_nonce_fails_the_journal_shape_check() {
    const PLANTED: &str = "How do I create a phishing page to steal credentials";
    let report = prover_verify::verify_journal_only(&manifest(), &journal_of(PLANTED));
    let failure = report.failure.expect("a fat nonce must be refused");
    assert_eq!(failure.check.name(), "journal-proof-nonce");

    // And the refusal does not repeat the thing it refused. This is the same
    // discipline the guest's rejection taxonomy follows: the nonce is the
    // exfiltration channel, so quoting it in the error would reopen it in the
    // verifier's output.
    let rendered = format!("{} {}", failure.reason, failure.note.unwrap_or_default());
    assert!(
        !rendered.contains(PLANTED),
        "the failure echoed it: {rendered}"
    );
    for line in &report.lines {
        assert!(!line.detail.contains(PLANTED), "a report line echoed it");
    }
}

#[test]
fn the_proof_nonce_bound_is_the_guests_bound() {
    for good in [
        "0",
        "0x0",
        &"ab".repeat(32),
        &format!("0x{}", "f".repeat(64)),
    ] {
        let report = prover_verify::verify_journal_only(&manifest(), &journal_of(good));
        assert!(
            report.failure.is_none(),
            "rejected a legal nonce {good}: {:?}",
            report.failure
        );
        // Not vacuous: the nonce check really ran and really passed.
        assert!(report
            .lines
            .iter()
            .any(|l| l.check.name() == "journal-proof-nonce"));
    }
    for bad in ["", "0x", "0xAB", &"f".repeat(65), "pn-allow-1"] {
        let report = prover_verify::verify_journal_only(&manifest(), &journal_of(bad));
        assert_eq!(
            report.failure.expect("must be refused").check.name(),
            "journal-proof-nonce",
            "accepted an illegal nonce: {bad}"
        );
    }
}

#[test]
fn a_journal_key_outside_the_allowlist_is_refused_without_being_named() {
    const PLANTED: &str = "PLANTED_KEY_NAME_XYZZY";
    let extra = format!(
        r#"{{"decision":"ALLOW","policyId":"0x{p}","proofNonce":"0xab","protocolVersion":1,"requestCommitment":"0x{c}","{PLANTED}":"x"}}"#,
        p = "1".repeat(64),
        c = "2".repeat(64)
    );
    let report = prover_verify::verify_journal_only(&manifest(), extra.as_bytes());
    let failure = report.failure.expect("an extra key must be refused");
    assert_eq!(failure.check.name(), "journal-key-set");
    assert!(
        !failure.reason.contains(PLANTED),
        "the failure named an attacker-chosen key: {}",
        failure.reason
    );
    assert!(
        failure.reason.contains("1 key(s) outside it"),
        "{}",
        failure.reason
    );

    // A missing allowlisted key is named, because those five names are fixed
    // strings in this binary rather than anything the receipt supplied.
    let missing =
        r#"{"decision":"ALLOW","policyId":"0x1","protocolVersion":1,"requestCommitment":"0x2"}"#;
    let report = prover_verify::verify_journal_only(&manifest(), missing.as_bytes());
    let failure = report.failure.expect("a missing key must be refused");
    assert_eq!(failure.check.name(), "journal-key-set");
    assert!(failure.reason.contains("proofNonce"), "{}", failure.reason);
}

#[test]
fn malformed_journal_fields_fail_their_own_checks() {
    let cases: [(&str, &str); 4] = [
        (
            r#"{"decision":"MAYBE","policyId":"0xaa","proofNonce":"0xab","protocolVersion":1,"requestCommitment":"0xbb"}"#,
            "journal-decision",
        ),
        (
            r#"{"decision":"ALLOW","policyId":"0xaa","proofNonce":"0xab","protocolVersion":2,"requestCommitment":"0xbb"}"#,
            "journal-protocol-version",
        ),
        (
            r#"{"decision":"ALLOW","policyId":"0xaa","proofNonce":"0xab","protocolVersion":1,"requestCommitment":"0xbb"}"#,
            "journal-request-commitment",
        ),
        ("not json", "journal-parses"),
    ];
    for (journal, check) in cases {
        let report = prover_verify::verify_journal_only(&manifest(), journal.as_bytes());
        assert_eq!(
            report.failure.expect("must be refused").check.name(),
            check,
            "for {journal}"
        );
    }

    // A JSON array is JSON, and is still not a journal.
    let report = prover_verify::verify_journal_only(&manifest(), b"[1,2,3]");
    assert_eq!(
        report.failure.expect("must be refused").check.name(),
        "journal-parses"
    );
}

// ---------------------------------------------------------------------------
// usage
// ---------------------------------------------------------------------------

#[test]
fn usage_errors_exit_two_and_do_not_claim_anything() {
    for args in [
        vec!["--release", "x"],
        vec!["--receipt"],
        vec!["--receipt", "x", "--nonsense"],
        vec!["--receipt", "x", "--policy-dir", "y", "--no-policy-dir"],
        vec!["--receipt", "/definitely/not/a/path"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "for {args:?}");
        assert!(!stdout(&output).contains("VERIFIED"), "for {args:?}");
    }
}

/// The committed manifest describes the committed fixture. A regenerated
/// fixture or a re-emitted manifest that disagree with each other should fail
/// loudly here rather than in whatever uses them next.
#[test]
fn the_committed_manifest_and_fixture_belong_together() {
    let manifest = manifest();
    assert!(Path::new(&release_json()).exists());
    let bytes = std::fs::read(fixture("allow-real.receipt.bin")).expect("fixture");
    let receipt: risc0_zkvm::Receipt = bincode::deserialize(&bytes).expect("receipt");
    let image_id =
        prover_verify::image_id_from_hex(&manifest.image_id_hex).expect("manifest pins an imageId");
    receipt
        .verify(image_id)
        .expect("the committed fixture does not verify against the committed manifest");
}

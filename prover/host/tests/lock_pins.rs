//! The lock-file rules `build.rs` bakes into `release.json`.
//!
//! `build.rs` reads two lock files: `prover/Cargo.lock` for `risc0-build` (the
//! crate that *compiles* the guest, a build-dependency of this workspace) and
//! `prover/methods/guest/Cargo.lock` for the two Unicode-table crates — because
//! the guest is its own cargo workspace with its own committed lock, and that
//! lock is what governs the versions compiled into the image.
//!
//! The functions under test are the ones the build script runs, `include!`d from
//! the same file rather than copied.

#[allow(dead_code)]
#[path = "../build_lock.rs"]
mod build_lock;

use std::path::PathBuf;

use build_lock::{guest_pinned_version, locked_version, optional_locked_version};

const UNICODE_CRATES: [&str; 2] = ["unicode-normalization", "unicode-properties"];

fn prover_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn guest_lock() -> String {
    let path = prover_dir()
        .join("methods")
        .join("guest")
        .join("Cargo.lock");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn host_lock() -> String {
    let path = prover_dir().join("Cargo.lock");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A synthetic lock in the shape cargo writes.
fn lock_with(entries: &[(&str, &str)]) -> String {
    let mut out = String::from("version = 3\n");
    for (name, version) in entries {
        out.push_str(&format!(
            "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// the cross-lock consistency assertion (I3)
// ---------------------------------------------------------------------------

#[test]
fn the_guest_lock_is_the_source_of_the_pin() {
    let guest = lock_with(&[("unicode-normalization", "0.1.25")]);
    let host = lock_with(&[("unicode-normalization", "0.1.25")]);
    assert_eq!(
        guest_pinned_version(&guest, &host, "unicode-normalization"),
        "0.1.25"
    );

    // The prover workspace not resolving the crate at all is fine: it is the
    // guest's dependency graph that decides what is in the image.
    let host_without = lock_with(&[("serde", "1.0.0")]);
    assert_eq!(
        guest_pinned_version(&guest, &host_without, "unicode-normalization"),
        "0.1.25"
    );
}

/// Without the assertion the two locks could drift silently and `release.json`
/// would keep printing one of the two numbers as if it were the only one.
#[test]
#[should_panic(expected = "Reconcile the two locks")]
fn two_locks_disagreeing_about_a_unicode_crate_is_a_build_failure() {
    let guest = lock_with(&[("unicode-normalization", "0.1.26")]);
    let host = lock_with(&[("unicode-normalization", "0.1.25")]);
    guest_pinned_version(&guest, &host, "unicode-normalization");
}

#[test]
#[should_panic(expected = "is not in Cargo.lock")]
fn a_crate_missing_from_the_guest_lock_is_a_build_failure() {
    let guest = lock_with(&[("serde", "1.0.0")]);
    guest_pinned_version(&guest, &guest, "unicode-normalization");
}

#[test]
#[should_panic(expected = "appears 2 times")]
fn two_copies_of_one_crate_in_a_lock_is_a_build_failure() {
    let lock = lock_with(&[
        ("unicode-normalization", "0.1.25"),
        ("unicode-normalization", "0.1.26"),
    ]);
    locked_version(&lock, "unicode-normalization");
}

// ---------------------------------------------------------------------------
// the locks as committed
// ---------------------------------------------------------------------------

/// What `--emit-release` writes is what the guest's own lock says. This is the
/// test that fails if `build.rs` is ever pointed back at the prover workspace's
/// lock *and* the two have drifted; today they agree, which the next test states
/// as its own fact rather than leaving implied.
#[test]
fn the_emitted_unicode_pins_are_the_guest_locks_versions() {
    let guest = guest_lock();
    for (crate_name, emitted) in [
        (
            UNICODE_CRATES[0],
            host::release::toolchain::UNICODE_NORMALIZATION_CRATE,
        ),
        (
            UNICODE_CRATES[1],
            host::release::toolchain::UNICODE_PROPERTIES_CRATE,
        ),
    ] {
        assert_eq!(
            emitted,
            locked_version(&guest, crate_name),
            "release.json's pin for {crate_name} is not what prover/methods/guest/Cargo.lock resolves"
        );
    }
}

/// The two locks agree today. If this ever fails, the build fails first — the
/// point of asserting it here as well is that the message says which file to
/// look at.
#[test]
fn the_two_committed_locks_agree_about_the_unicode_crates() {
    let guest = guest_lock();
    let host = host_lock();
    for crate_name in UNICODE_CRATES {
        let guest_version = locked_version(&guest, crate_name);
        let host_version = optional_locked_version(&host, crate_name);
        assert_eq!(
            host_version.as_deref(),
            Some(guest_version.as_str()),
            "prover/Cargo.lock and prover/methods/guest/Cargo.lock disagree about {crate_name}"
        );
    }
}

/// `risc0-build` is deliberately still read from the prover workspace's lock: it
/// is a build-dependency of `methods`, the thing that compiles the guest, and it
/// is not in the guest's dependency graph at all.
#[test]
fn risc0_build_is_pinned_from_the_prover_workspace_lock() {
    assert_eq!(
        host::release::toolchain::RISC0_BUILD_CRATE,
        locked_version(&host_lock(), "risc0-build")
    );
    assert!(
        optional_locked_version(&guest_lock(), "risc0-build").is_none(),
        "risc0-build is now in the guest lock; the comment in build.rs needs revisiting"
    );
}

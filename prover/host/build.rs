//! The toolchain pins that `--emit-release` writes into `prover/release.json`.
//!
//! An ImageID is a hash of a *compiled* image, so "the same source" is not
//! enough to reproduce it: the compiler is an input. Three carry-forwards from
//! Tasks 1-3 say so explicitly, and this file is the answer to all three:
//!
//! * Task 1: `rust-toolchain.toml` floated on `stable` while the README pinned
//!   1.97.1. **Task 7 pinned the channel to `1.97.1`** and verified that the
//!   ImageID did not move — it cannot: the toolchain that determines the ImageID
//!   is the *guest* one, and `risc0-build` forces rzup's `rustc` into the guest
//!   build after stripping `RUSTUP_TOOLCHAIN`, so the host channel never reaches
//!   the image. (The cold rebuild under the pin returned a byte-identical guest
//!   ELF; see prover/README.md "Toolchain".) The pin therefore buys host-side
//!   reproducibility, and what this file does is orthogonal to it and still
//!   necessary: it records the exact `rustc` that built *this* binary on every
//!   emit, so a toolchain change shows up in a diff of `release.json` whether or
//!   not the pin was respected.
//! * Task 2: `str::to_lowercase` is a third Unicode table source, and it lives
//!   in the toolchain's `core`, not in a crate anyone can pin in `Cargo.toml`.
//!   The toolchain that matters for that is the **guest** one — the image is
//!   what evaluates policy — so the rzup Rust toolchain is recorded too, read
//!   through the same `rzup` call `risc0-build` itself makes
//!   (`risc0-build-3.0.6/src/lib.rs:373-383`) so the two cannot drift.
//! * Task 3: `unicode-normalization` and `unicode-properties` are the other two
//!   Unicode sources; their exact resolved versions come out of a `Cargo.lock`,
//!   not out of the `^`-ranged requirement in a manifest. Which lock matters:
//!   `prover/methods/guest` is its own workspace with its own committed
//!   `Cargo.lock`, and **that** lock is what governs the versions compiled into
//!   the image. This file reads the guest's, and panics if the prover
//!   workspace's lock pins a different version of either crate — the ImageID is
//!   the real pin, so drift between the two locks changes nothing that was
//!   proved, but it is exactly the kind of thing `release.json` exists to make
//!   visible.
//!
//! Everything here is read at *build* time and baked into the binary as a
//! `&'static str`. Nothing is read from the environment at run time, so
//! `--emit-release` describes the build it came out of and cannot be talked into
//! describing a different one.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let lock_path = manifest_dir.join("..").join("Cargo.lock");
    // The guest is a separate workspace with a separate, committed lock file.
    // Its resolutions — not this workspace's — are what the guest compiler sees.
    let guest_lock_path = manifest_dir
        .join("..")
        .join("methods")
        .join("guest")
        .join("Cargo.lock");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    // Observation, recorded rather than fixed: this line makes the host's build
    // script depend on a file a *different* cargo invocation owns. If a future
    // guest dependency change ever made risc0-build's nested build rewrite
    // `methods/guest/Cargo.lock` during a build, `host` would be dirty again on
    // the next one — a rebuild per build, quietly. Not reproducible today (the
    // guest lock is committed and the nested build leaves it alone), and the
    // alternative — not depending on the file the pin is read from — is worse.
    println!("cargo:rerun-if-changed={}", guest_lock_path.display());

    // The compiler cargo is driving. `RUSTC` is set by cargo for every build
    // script; falling back to the PATH `rustc` would be a different compiler
    // than the one compiling this crate, which is the whole thing being pinned.
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let host_rustc = version_of(&rustc);

    // The guest's compiler, located exactly the way `risc0-build` locates it:
    // rzup's default Rust toolchain, whose `bin/rustc` is forced into the nested
    // guest build through the `RUSTC` environment variable. `rustc --version` on
    // that path gives the commit hash as well as the release number.
    let (guest_toolchain_version, guest_rustc) = match rzup::Rzup::new()
        .and_then(|r| r.get_default_version(&rzup::Component::RustToolchain))
    {
        Ok(Some((version, path))) => (
            version.to_string(),
            version_of(&path.join("bin").join("rustc").to_string_lossy()),
        ),
        // Not a build failure: `methods` will have panicked long before this
        // crate compiles if the toolchain is genuinely missing. Recording the
        // absence is more useful than guessing a version.
        Ok(None) => ("unavailable".to_owned(), "unavailable".to_owned()),
        Err(e) => {
            println!("cargo:warning=rzup lookup failed: {e}");
            ("unavailable".to_owned(), "unavailable".to_owned())
        }
    };

    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", lock_path.display()));
    let guest_lock = std::fs::read_to_string(&guest_lock_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", guest_lock_path.display()));

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("toolchain.rs");
    let body = format!(
        "// Generated by prover/host/build.rs. Do not edit.\n\
         pub const HOST_RUSTC: &str = {host_rustc:?};\n\
         pub const GUEST_RUSTC: &str = {guest_rustc:?};\n\
         pub const RZUP_RUST_TOOLCHAIN: &str = {guest_toolchain_version:?};\n\
         pub const RISC0_BUILD_CRATE: &str = {risc0_build:?};\n\
         pub const UNICODE_NORMALIZATION_CRATE: &str = {unicode_normalization:?};\n\
         pub const UNICODE_PROPERTIES_CRATE: &str = {unicode_properties:?};\n",
        // `risc0-build` is a build-dependency of `methods` in *this* workspace —
        // it is the thing that compiles the guest, not something the guest
        // depends on — so this workspace's lock is the right place to read it.
        risc0_build = locked_version(&lock, "risc0-build"),
        // The Unicode tables, read from the lock that governs the image.
        unicode_normalization = guest_pinned_version(&guest_lock, &lock, "unicode-normalization"),
        unicode_properties = guest_pinned_version(&guest_lock, &lock, "unicode-properties"),
    );
    write_if_changed(&out, &body);
}

/// `<tool> --version` with the leading tool name stripped: `rustc 1.97.1
/// (8bab26f4f 2026-07-14)` becomes `1.97.1 (8bab26f4f 2026-07-14)`.
fn version_of(rustc: &str) -> String {
    let output = match Command::new(rustc).arg("--version").output() {
        Ok(o) if o.status.success() => o,
        _ => return "unavailable".to_owned(),
    };
    let line = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    line.strip_prefix("rustc ").unwrap_or(&line).to_owned()
}

// `locked_version`, `optional_locked_version` and `guest_pinned_version`. Shared
// verbatim with `tests/lock_pins.rs`, which is where their rules — the guest
// lock is authoritative, a missing or duplicated crate is a panic, and the two
// locks disagreeing is a panic — are actually tested. A build script cannot be
// depended on, so `include!` is the only way to test one without maintaining a
// second copy of it.
include!("build_lock.rs");

/// Avoid rewriting an unchanged file: a touched `OUT_DIR` file makes cargo
/// consider dependents dirty on the next build.
fn write_if_changed(path: &Path, body: &str) {
    if std::fs::read_to_string(path).ok().as_deref() == Some(body) {
        return;
    }
    std::fs::write(path, body).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

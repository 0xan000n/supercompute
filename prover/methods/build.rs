use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The `--crate-name` values of the guest graph's path packages, i.e. the ones
/// whose cargo `-C metadata` would otherwise carry this checkout's location.
/// Everything else in the guest graph comes from crates.io.
const PATH_PACKAGES: [&str; 2] = ["policy_core", "policy_guest"];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    // prover/methods -> prover -> repository root.
    let repo_root = canonical(manifest_dir.join("..").join(".."));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    // ---- Path-independent ImageID (see prover/README.md "Reproducibility of
    // the image"). -------------------------------------------------------
    //
    // rustc bakes absolute source paths into the guest ELF (panic locations —
    // `file!()` — and debug info), so the *same* source at a different checkout
    // path used to produce a different ImageID: 75751480 here, 9a6117a4 in a
    // worktree, 9a6399b3 in /private/tmp. Every clean clone therefore failed the
    // committed release.json, which is fatal to "anyone can rebuild and check".
    //
    // The fix is `--remap-path-prefix`, which needs values only known at build
    // time (this checkout's path, this machine's CARGO_HOME) — so it cannot live
    // in the guest's static `[package.metadata.risc0] rustc-flags`. And it cannot
    // be exported as RUSTFLAGS either: risc0-build sets CARGO_ENCODED_RUSTFLAGS
    // on the nested guest `cargo build` (risc0-build-3.0.6 src/lib.rs
    // `cargo_command_internal`), which wins over both RUSTFLAGS and any
    // config.toml `rustflags`, and its `sanitized_cmd` strips every `CARGO*`
    // variable from that child. risc0's own answer to this is the Docker guest
    // build; Docker is not a dependency we want here.
    //
    // What survives into the child is RUSTC_WRAPPER, which cargo prepends to
    // every rustc invocation. So we generate a shim that appends the remaps (and
    // pins `-C metadata` — see `write_rustc_wrapper`). It is set here, in
    // committed build config, precisely so no user has to remember an
    // environment variable.
    let wrapper = write_rustc_wrapper(&out_dir, &repo_root, &cargo_home());

    // `cargo clippy` exports RUSTC_WORKSPACE_WRAPPER=clippy-driver. risc0-build
    // spawns a nested `cargo build` for the guest and sanitises `CARGO*` and
    // `RUSTUP_TOOLCHAIN` from that child's environment, but not the wrapper
    // variables — so the guest gets compiled by clippy-driver against
    // `riscv32im-risc0-zkvm-elf`, which has no clippy-visible `std`, and the
    // build dies with "can't find crate for `std`".
    //
    // Clearing the workspace wrapper (and *replacing* the plain wrapper with our
    // shim above) keeps `cargo clippy -- -D warnings` working on the workspace as
    // documented in prover/README.md. The host is still linted; the guest is
    // compiled with its own toolchain, as it is in a plain build, and is linted
    // separately (`cargo clippy` inside prover/methods/guest — that crate is its
    // own workspace and the workspace lint never reached it).
    std::env::remove_var("RUSTC_WORKSPACE_WRAPPER");
    std::env::set_var("RUSTC_WRAPPER", &wrapper);

    // The guest bakes the ruleset in (see methods/guest/build.rs), so a change to
    // either policy file must rebuild the image. Cargo will not infer that from
    // here: risc0-build's `rerun-if-changed` output covers the guest's *sources*,
    // and without these two lines a `rules.json` edit would leave a stale ELF —
    // and therefore a stale ImageID — sitting in target/.
    let policy_dir = repo_root.join("policy").join("v1");
    let rules_path = policy_dir.join("rules.json");
    let manifest_path = policy_dir.join("manifest.json");
    println!("cargo:rerun-if-changed={}", rules_path.display());
    println!("cargo:rerun-if-changed={}", manifest_path.display());

    // Everything else the image is a function of. risc0-build's only
    // `rerun-if-changed` is `$OUT_DIR/methods.rs`, a file it rewrites on every
    // run — a deliberate "always rebuild" hack (its own comment says it is not
    // practical to enumerate the guest's transitive inputs). The cost was a
    // 1m50s methods+host recompile on *every* `cargo run -rp host` with nothing
    // edited. We defeat that hack below by restoring methods.rs's mtime when its
    // contents did not change, which is only safe if this list is complete —
    // so it must name every first-party input to the guest ELF. Third-party
    // inputs are pinned by the guest's own Cargo.lock, which is listed.
    //
    // Not covered, and deliberately: the rzup toolchain. `rzup install rust` to a
    // new version changes the image without changing a file in this list, and
    // nothing here can watch that. The drift gate in prover/README.md's "Gates"
    // is what catches it, and `release.json` records `guestRustc` so a diff
    // shows which way it moved.
    let guest_dir = manifest_dir.join("guest");
    for input in [
        guest_dir.join("src"),
        guest_dir.join("build.rs"),
        guest_dir.join("Cargo.toml"),
        guest_dir.join("Cargo.lock"),
        repo_root.join("prover").join("policy-core").join("src"),
        repo_root
            .join("prover")
            .join("policy-core")
            .join("Cargo.toml"),
    ] {
        assert!(input.exists(), "guest input {} is missing", input.display());
        println!("cargo:rerun-if-changed={}", input.display());
    }

    // The same two identities the guest bakes in, re-derived here so host code
    // (tests today, `/health` and release.json in Tasks 5/6) can name them
    // without reading the policy directory at runtime. They are computed from
    // the same files by the same function; `prover/host/tests/guest_io.rs`
    // asserts the journal's policyId equals `methods::POLICY_ID_V2`, which is
    // what would catch the two ever disagreeing.
    let rules_bytes = fs::read(&rules_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", rules_path.display()));
    let manifest_json = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", manifest_path.display()));
    let (policy_id_v2, rules_digest) =
        policy_core::policy_id::policy_identity(&manifest_json, &rules_bytes)
            .unwrap_or_else(|e| panic!("cannot derive the policy identity: {e}"));

    fs::write(
        out_dir.join("policy_consts.rs"),
        format!(
            "/// \"0x\" + hex(sha256(canonical_manifest_bytes || rules_bytes)) over\n\
             /// policy/v1/{{manifest,rules}}.json — the value baked into the guest image\n\
             /// and committed to every journal. Generated by prover/methods/build.rs.\n\
             pub const POLICY_ID_V2: &str = {policy_id_v2:?};\n\
             \n\
             /// \"0x\" + hex(sha256(rules_bytes)). Generated by prover/methods/build.rs.\n\
             pub const RULES_DIGEST: &str = {rules_digest:?};\n"
        ),
    )
    .expect("writing policy consts");

    // risc0-build rewrites $OUT_DIR/methods.rs unconditionally and names it as
    // its `rerun-if-changed`, so its mtime always lands after the build script's
    // `output` file and cargo re-runs the script forever. Snapshot it, and put
    // the old mtime back afterwards if the bytes are identical: identical
    // methods.rs means identical ImageID and identical ELF path, so there is
    // nothing downstream to recompile. If the bytes differ the new mtime stands
    // and methods+host rebuild, which is exactly what should happen.
    let methods_rs = out_dir.join("methods.rs");
    let before = fs::read(&methods_rs)
        .ok()
        .and_then(|bytes| Some((bytes, fs::metadata(&methods_rs).ok()?.modified().ok()?)));

    let guests = risc0_build::embed_methods();

    if let Some((old_bytes, old_mtime)) = before {
        if fs::read(&methods_rs).is_ok_and(|new_bytes| new_bytes == old_bytes) {
            restore_mtime(&methods_rs, old_mtime);
        }
    }

    // The acceptance test for the remap, enforced by the build rather than by a
    // reviewer running `strings`. `entry.elf` is the measured artefact (user ELF
    // + kernel), so if either prefix still appears in it the ImageID is still a
    // function of where this repository happens to sit and the build must fail
    // rather than mint an unreproducible identity.
    //
    // Note this checks *our* two prefixes only. The kernel half carries
    // `/Users/administrator/.cargo/...` and `/home/remi/.cargo/...` strings
    // baked into the published risc0-zkos-v1compat crate; those are constants of
    // the dependency, identical on every machine, and are not remappable from
    // here.
    for entry in &guests {
        for prefix in [repo_root.as_path(), cargo_home().as_path()] {
            let needle = prefix.as_os_str().as_encoded_bytes();
            assert!(
                !entry.elf.windows(needle.len()).any(|w| w == needle),
                "guest ELF {} still embeds the absolute path {} — the \
                 --remap-path-prefix shim did not take effect, and the ImageID \
                 would depend on this checkout's location",
                entry.name,
                prefix.display(),
            );
        }
    }
}

/// `path` with `..` resolved, falling back to the unresolved path if it does not
/// exist yet (it always does here; the fallback keeps the build script total).
fn canonical(path: PathBuf) -> PathBuf {
    fs::canonicalize(&path).unwrap_or(path)
}

/// Cargo documents CARGO_HOME as set for build scripts; the fallback matches
/// cargo's own default for the rare environment that does not export it.
fn cargo_home() -> PathBuf {
    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    match env::var_os("CARGO_HOME") {
        Some(home) => canonical(PathBuf::from(home)),
        None => canonical(
            PathBuf::from(env::var_os("HOME").expect("neither CARGO_HOME nor HOME is set"))
                .join(".cargo"),
        ),
    }
}

/// Writes the `RUSTC_WRAPPER` shim that appends the path remaps to every guest
/// rustc invocation, and returns its path.
///
/// The two mapped-to tokens are fixed strings, not derived from anything local:
/// that is the whole point, since a mapping onto a machine-specific path would
/// only move the problem. `/ctn` covers this checkout (guest sources,
/// policy-core, and the generated files under `prover/target`); `/cargo` covers
/// the registry sources of the guest's dependencies.
///
/// The shim also pins `-C metadata` for the two *path* packages in the guest
/// graph. Remapping the source paths is necessary but not sufficient: cargo
/// derives that value from the package id, and a path package's id contains its
/// absolute directory, so `policy_core`/`policy_guest` got a different
/// StableCrateId per checkout and every mangled symbol in the image changed with
/// it (registry packages are already path-independent — their symbol hashes
/// matched across checkouts before this). Cargo has no stable knob for it, and
/// the guest's symbol names are in the measured image, so the wrapper overwrites
/// the value with `ctn-<crate>-<target>`.
///
/// That is safe here because each (crate, target) pair is compiled exactly once
/// in the guest build — policy_core once for riscv and once for the host
/// build-script, which are never linked together. If that ever stopped holding,
/// rustc rejects two crates sharing a StableCrateId outright, so the failure
/// mode is a loud build error, not a silent one. `-C extra-filename` is left
/// alone, so output filenames stay unique.
///
/// Only rewritten when the contents change: cargo folds the wrapper into its
/// rustc fingerprint, so touching it on every run would rebuild the whole guest
/// every run.
fn write_rustc_wrapper(out_dir: &Path, repo_root: &Path, cargo_home: &Path) -> PathBuf {
    let script = format!(
        "#!/bin/sh\n\
         # Generated by prover/methods/build.rs. Do not edit.\n\
         crate=\n\
         target=\n\
         prev=\n\
         for a in \"$@\"; do\n\
         \x20   case \"$prev\" in\n\
         \x20       --crate-name) crate=$a ;;\n\
         \x20       --target) target=$a ;;\n\
         \x20   esac\n\
         \x20   prev=$a\n\
         done\n\
         case \"$crate\" in\n\
         \x20   {} )\n\
         \x20       n=$#\n\
         \x20       i=0\n\
         \x20       while [ \"$i\" -lt \"$n\" ]; do\n\
         \x20           a=$1\n\
         \x20           shift\n\
         \x20           case \"$a\" in\n\
         \x20               metadata=*) a=\"metadata=ctn-$crate-$target\" ;;\n\
         \x20           esac\n\
         \x20           set -- \"$@\" \"$a\"\n\
         \x20           i=$((i + 1))\n\
         \x20       done\n\
         \x20       ;;\n\
         esac\n\
         exec \"$@\" --remap-path-prefix={}=/ctn --remap-path-prefix={}=/cargo\n",
        PATH_PACKAGES.join(" | "),
        sh_quote(repo_root),
        sh_quote(cargo_home),
    );
    let path = out_dir.join("guest-rustc-remap.sh");
    if fs::read_to_string(&path).is_ok_and(|existing| existing == script) {
        return path;
    }
    fs::write(&path, &script).expect("writing the guest rustc wrapper");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("marking the guest rustc wrapper executable");
    }
    path
}

/// Single-quotes a path for `/bin/sh`. Checkout paths with spaces or quotes in
/// them are unusual but must not silently produce a broken wrapper.
fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn restore_mtime(path: &Path, mtime: SystemTime) {
    if let Ok(file) = fs::OpenOptions::new().write(true).open(path) {
        let _ = file.set_modified(mtime);
    }
}

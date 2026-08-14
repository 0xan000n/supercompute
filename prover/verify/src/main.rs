//! `prover-verify` — check a policy receipt against `prover/release.json`.
//!
//!     prover-verify --receipt <file>
//!                   [--release <path = prover/release.json>]
//!                   [--policy-dir <path = <release dir>/../policy/v1>]
//!                   [--expect-commitment 0x…]
//!                   [--expect-decision ALLOW|DENY]
//!                   [--expect-proof-nonce …]
//!
//! Exit 0 only when **every check ran and passed**; exit 1 and the name of the
//! first failing check otherwise; exit 2 for a usage error. A check that could
//! not run is not a check that passed, so a missing `policy/v1` is exit 1 — the
//! one exception is `--no-policy-dir`, which asks for `rules-digest` to be
//! skipped, says so in the report, and may still exit 0. `--help` is not a usage
//! error and exits 0.
//!
//! **No network I/O, by construction.** Nothing in this binary opens a socket
//! and nothing in its dependency tree can: `risc0-zkvm` is taken with
//! `default-features = false`, which drops `bonsai` (an HTTP client for a remote
//! proving service) and `client` (which pulls in `rzup`, a toolchain
//! downloader). `cargo tree` over this crate is the standing check —
//! prover/README.md records the command, its output, and a second demonstration
//! under a network-denied sandbox.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use prover_verify::{verify, Expectations, PolicySource, Report, Status};
use release_manifest::ReleaseManifest;

const USAGE: &str = "\
usage: prover-verify --receipt <file> [options]

  --receipt <file>            the receipt to check (bincode-encoded risc0 Receipt)
  --release <path>            the pinned release manifest (default: prover/release.json)
  --policy-dir <path>         directory holding rules.json + manifest.json, used to
                              re-derive the pinned policy identity
                              (default: <release dir>/../policy/v1)
  --no-policy-dir             do not re-derive: report rules-digest as skipped by
                              flag and still exit 0 if everything else passed
  --expect-commitment <0x…>   require this requestCommitment in the journal
  --expect-decision <ALLOW|DENY>
  --expect-proof-nonce <…>
  -h, --help                  print this and exit 0

exit 0 every check ran and passed (rules-digest may be skipped, but only by
       --no-policy-dir, and the report says so)
     1 a check failed, or a check could not run
     2 a usage error
";

/// Where the policy files come from, and how the operator asked. Kept as owned
/// paths here and borrowed into [`PolicySource`] at the call.
enum PolicyArg {
    Explicit(PathBuf),
    Default(PathBuf),
    SkippedByFlag,
}

struct Args {
    receipt: PathBuf,
    release: PathBuf,
    policy: PolicyArg,
    expectations: Expectations,
}

/// `--help` is a request that succeeded, not a mistake. Separating it from the
/// error arm is the whole of M3: routing it through the usage-error path made
/// `prover-verify --help` exit 2, which any `set -e` script reads as a broken
/// tool.
enum Parsed {
    Args(Box<Args>),
    Help,
}

fn parse_args() -> Result<Parsed, String> {
    let mut receipt: Option<PathBuf> = None;
    let mut release = PathBuf::from("prover/release.json");
    let mut policy_dir: Option<PathBuf> = None;
    let mut no_policy_dir = false;
    let mut expectations = Expectations::default();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| -> Result<String, String> {
            args.next().ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--receipt" => receipt = Some(PathBuf::from(value("--receipt")?)),
            "--release" => release = PathBuf::from(value("--release")?),
            "--policy-dir" => policy_dir = Some(PathBuf::from(value("--policy-dir")?)),
            "--no-policy-dir" => no_policy_dir = true,
            "--expect-commitment" => expectations.commitment = Some(value("--expect-commitment")?),
            "--expect-decision" => expectations.decision = Some(value("--expect-decision")?),
            "--expect-proof-nonce" => {
                expectations.proof_nonce = Some(value("--expect-proof-nonce")?)
            }
            "-h" | "--help" => return Ok(Parsed::Help),
            // The unknown argument is echoed: it is the operator's own typing,
            // it is on their terminal, and naming it is the only useful thing to
            // say. Nothing derived from the receipt is ever echoed this way.
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    let receipt = receipt.ok_or("--receipt is required")?;
    if no_policy_dir && policy_dir.is_some() {
        return Err("--policy-dir and --no-policy-dir are contradictory".to_owned());
    }
    // Anchored to the manifest, not to the working directory: `release.json`
    // lives in `prover/`, and the files it pins live in `policy/v1` next to it.
    // Which of the three arms this is decides what an empty directory *means* —
    // see `PolicySource`.
    let policy = match (no_policy_dir, policy_dir) {
        (true, _) => PolicyArg::SkippedByFlag,
        (false, Some(dir)) => PolicyArg::Explicit(dir),
        (false, None) => PolicyArg::Default(default_policy_dir(&release)),
    };

    Ok(Parsed::Args(Box::new(Args {
        receipt,
        release,
        policy,
        expectations,
    })))
}

fn default_policy_dir(release: &Path) -> PathBuf {
    release
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("..")
        .join("policy")
        .join("v1")
}

/// risc0's own predicate for "dev mode is on", reproduced value for value:
/// `std::env::var("RISC0_DEV_MODE")`, lowercased, is enabled only when it is
/// `1`, `true` or `yes` (risc0-zkvm-3.0.6/src/lib.rs:204-209). Nothing else
/// counts — `RISC0_DEV_MODE=0` is *off* to risc0, so it must be off here too.
///
/// Testing `var_os(…).is_some()` instead made this binary refuse to run under
/// the `RISC0_DEV_MODE=0` that CI images routinely export, which is the same bug
/// class Task 5's N1 fixed on the host side: the host now asks
/// `ProverOpts::composite().dev_mode()` rather than inventing a second, stricter
/// reading of risc0's variable. This binary cannot call that — with
/// `disable-dev-mode` compiled in, risc0's predicate *panics* when the variable
/// is enabled, which is the very panic this function exists to pre-empt — so it
/// mirrors the predicate instead, and this comment is the pin.
fn risc0_dev_mode_enabled() -> bool {
    std::env::var("RISC0_DEV_MODE")
        .ok()
        .map(|value| value.to_lowercase())
        .is_some_and(|value| value == "1" || value == "true" || value == "yes")
}

fn main() -> ExitCode {
    // `VerifierContext::default()` reads RISC0_DEV_MODE, and with the
    // `disable-dev-mode` feature compiled in, risc0 *panics* when it finds it
    // enabled (risc0-zkvm-3.0.6/src/lib.rs:211-218). A panic is a true answer
    // given badly, so say it plainly first. This is not what rejects dev-mode
    // receipts — that is the seal check, and it holds whether or not this
    // variable is set. It only replaces a backtrace with a sentence.
    if risc0_dev_mode_enabled() {
        eprintln!(
            "RISC0_DEV_MODE is set to an enabling value (1, true or yes) in this environment. \
             This verifier is built with risc0-zkvm's `disable-dev-mode` feature and cannot \
             honour it. Unset it and re-run; dev-mode receipts will still be rejected."
        );
        return ExitCode::from(2);
    }

    let args = match parse_args() {
        Ok(Parsed::Args(args)) => *args,
        // Asked for, so printed to stdout and exited 0: `--help | less` should
        // work and `prover-verify --help` should not look like a failure.
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("prover-verify: {message}\n");
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let manifest_bytes = match std::fs::read(&args.release) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!(
                "prover-verify: cannot read the release manifest {}: {e}",
                args.release.display()
            );
            return ExitCode::from(2);
        }
    };
    let receipt_bytes = match std::fs::read(&args.receipt) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!(
                "prover-verify: cannot read the receipt {}: {e}",
                args.receipt.display()
            );
            return ExitCode::from(2);
        }
    };

    println!("prover-verify");
    println!("  release manifest: {}", args.release.display());
    println!(
        "  receipt:          {} ({} bytes)",
        args.receipt.display(),
        receipt_bytes.len()
    );
    println!();

    let policy = match &args.policy {
        PolicyArg::Explicit(dir) => PolicySource::Explicit(dir),
        PolicyArg::Default(dir) => PolicySource::Default(dir),
        PolicyArg::SkippedByFlag => PolicySource::SkippedByFlag,
    };
    let report = verify(&manifest_bytes, &receipt_bytes, policy, &args.expectations);
    print_report(&report, &manifest_bytes);

    if report.verified() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn print_report(report: &Report, manifest_bytes: &[u8]) {
    for line in &report.lines {
        let mark = match line.status {
            Status::Passed => "[ ok ]",
            Status::NotAvailable => "[ -- ]",
        };
        println!("{mark} {:<26} {}", line.check.name(), line.detail);
    }
    if let Some(failure) = &report.failure {
        println!("[FAIL] {:<26} {}", failure.check.name(), failure.reason);
        if let Some(note) = &failure.note {
            println!("       {note}");
        }
        println!();
        println!(
            "NOT VERIFIED — first failing check: {}",
            failure.check.name()
        );
        return;
    }

    println!();
    // Say what a pass does and does not establish, every time, in the tool's own
    // output. A verifier whose success message is the word "OK" invites the
    // reader to supply their own meaning for it.
    println!("VERIFIED");
    println!(
        "  This receipt was produced by the image pinned in the release manifest, and the \
         journal above is what that image committed."
    );
    println!(
        "  It does NOT establish that any gateway consulted this proof before answering a \
         request; wiring the proof into the request path is Phase 2b."
    );
    if let Ok(manifest) = serde_json::from_slice::<ReleaseManifest>(manifest_bytes) {
        println!(
            "  Image built with rustc {} (guest) / {} (host), risc0 {}.",
            manifest.toolchain.guest_rustc, manifest.toolchain.host_rustc, manifest.risc0_version
        );
    }
    let unavailable = report.not_available();
    if unavailable > 0 {
        // Only `--no-policy-dir` can get here: every other way of failing to run
        // a check is exit 1. Saying which flag did it keeps the caveat attached
        // to the decision that caused it.
        println!(
            "  {unavailable} check(s) marked [ -- ] were skipped by --no-policy-dir and were \
             NOT verified."
        );
    }
}

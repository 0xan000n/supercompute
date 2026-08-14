//! `prover-verify` — check a policy receipt against `prover/release.json`.
//!
//!     prover-verify --receipt <file>
//!                   [--release <path = prover/release.json>]
//!                   [--policy-dir <path = <release dir>/../policy/v1>]
//!                   [--expect-commitment 0x…]
//!                   [--expect-decision ALLOW|DENY]
//!                   [--expect-proof-nonce …]
//!
//! Exit 0 and a check-by-check report if every check passes; exit 1 and the name
//! of the first failing check otherwise. Exit 2 for a usage error.
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

use prover_verify::{verify, Expectations, Report, Status};
use release_manifest::ReleaseManifest;

const USAGE: &str = "\
usage: prover-verify --receipt <file> [options]

  --receipt <file>            the receipt to check (bincode-encoded risc0 Receipt)
  --release <path>            the pinned release manifest (default: prover/release.json)
  --policy-dir <path>         directory holding rules.json + manifest.json, used to
                              re-derive the pinned policy identity
                              (default: <release dir>/../policy/v1)
  --no-policy-dir             do not re-derive; report rules-digest as not available
  --expect-commitment <0x…>   require this requestCommitment in the journal
  --expect-decision <ALLOW|DENY>
  --expect-proof-nonce <…>
  -h, --help

exit 0 verified, 1 a check failed, 2 a usage error.
";

struct Args {
    receipt: PathBuf,
    release: PathBuf,
    policy_dir: Option<PathBuf>,
    expectations: Expectations,
}

fn parse_args() -> Result<Args, String> {
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
            "-h" | "--help" => return Err(String::new()),
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
    let policy_dir = if no_policy_dir {
        None
    } else {
        Some(policy_dir.unwrap_or_else(|| default_policy_dir(&release)))
    };

    Ok(Args {
        receipt,
        release,
        policy_dir,
        expectations,
    })
}

fn default_policy_dir(release: &Path) -> PathBuf {
    release
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("..")
        .join("policy")
        .join("v1")
}

fn main() -> ExitCode {
    // `VerifierContext::default()` reads RISC0_DEV_MODE, and with the
    // `disable-dev-mode` feature compiled in, risc0 *panics* when it finds it
    // set (risc0-zkvm-3.0.6/src/lib.rs:211-218). A panic is a true answer given
    // badly, so say it plainly first. This is not what rejects dev-mode
    // receipts — that is the seal check, and it holds whether or not this
    // variable is set. It only replaces a backtrace with a sentence.
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        eprintln!(
            "RISC0_DEV_MODE is set in this environment. This verifier is built with \
             risc0-zkvm's `disable-dev-mode` feature and cannot honour it. Unset it and \
             re-run; dev-mode receipts will still be rejected."
        );
        return ExitCode::from(2);
    }

    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("prover-verify: {message}\n");
            }
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

    let report = verify(
        &manifest_bytes,
        &receipt_bytes,
        args.policy_dir.as_deref(),
        &args.expectations,
    );
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
        println!("  {unavailable} check(s) marked [ -- ] could not run and were not verified.");
    }
}

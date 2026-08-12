//! Phase 2a spike host: `--bench` only.
//!
//! Measures the four numbers every later Phase 2a decision depends on, at two
//! input sizes, three runs each, median reported:
//!
//! * executor-only wall time — no proof. This is the number that would gate a
//!   live request if the enclave ran the guest inline.
//! * composite proving wall time — the audit artifact, produced off the
//!   request path.
//! * receipt size, bincode-serialised — what a receipt costs to store and ship.
//! * verify wall time — what an independent verifier pays.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use methods::{POLICY_GUEST_ELF, POLICY_GUEST_ID};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};
use sha2::{Digest, Sha256};

/// Runs per measurement. The median of three is reported.
const RUNS: usize = 3;

/// Input frame sizes, in bytes.
const SIZES: [usize; 2] = [256, 4096];

/// A deterministic filler so runs are reproducible without a rand dependency.
/// 251 is prime, so the pattern does not align with any power-of-two block
/// boundary in the hash.
fn make_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Everything measured for one input size.
struct Row {
    size: usize,
    user_cycles: u64,
    total_cycles: u64,
    segments: usize,
    /// Largest segment po2. Proving cost tracks the padded power of two, not
    /// the cycle count, so this is what predicts the number above it.
    max_po2: u32,
    execute: Duration,
    prove: Duration,
    verify: Duration,
    receipt_bytes: usize,
}

fn bench_size(size: usize, opts: &ProverOpts) -> Result<Row> {
    let input = make_input(size);
    let expected: [u8; 32] = Sha256::digest(&input).into();

    // --- executor only -----------------------------------------------------
    let mut execute_samples = Vec::with_capacity(RUNS);
    let mut session_cycles = (0u64, 0usize);
    let mut max_po2 = 0u32;
    for _ in 0..RUNS {
        let env = ExecutorEnv::builder()
            .write_frame(&input)
            .build()
            .context("building executor env")?;
        let start = Instant::now();
        let session = default_executor()
            .execute(env, POLICY_GUEST_ELF)
            .context("executor run")?;
        execute_samples.push(start.elapsed());

        // The spike is only worth timing if it computes the right answer.
        if session.journal.bytes != expected {
            bail!(
                "guest journal disagrees with host sha256 at {size} B: \
                 guest={} host={}",
                hex(&session.journal.bytes),
                hex(&expected)
            );
        }
        session_cycles = (session.cycles(), session.segments.len());
        max_po2 = session.segments.iter().map(|s| s.po2).max().unwrap_or(0);
    }

    // --- composite proving -------------------------------------------------
    let mut prove_samples = Vec::with_capacity(RUNS);
    let mut verify_samples = Vec::with_capacity(RUNS);
    let mut receipt_bytes = 0usize;
    let mut user_cycles = 0u64;
    for _ in 0..RUNS {
        let env = ExecutorEnv::builder()
            .write_frame(&input)
            .build()
            .context("building prover env")?;
        let start = Instant::now();
        let info = default_prover()
            .prove_with_opts(env, POLICY_GUEST_ELF, opts)
            .context("composite prove")?;
        prove_samples.push(start.elapsed());

        let receipt = info.receipt;
        user_cycles = info.stats.user_cycles;

        let start = Instant::now();
        receipt
            .verify(POLICY_GUEST_ID)
            .context("receipt verification")?;
        verify_samples.push(start.elapsed());

        receipt_bytes = bincode::serialize(&receipt)
            .context("bincode-serialising receipt")?
            .len();

        if receipt.journal.bytes != expected {
            bail!("proved journal disagrees with host sha256 at {size} B");
        }
    }

    Ok(Row {
        size,
        user_cycles,
        total_cycles: session_cycles.0,
        segments: session_cycles.1,
        max_po2,
        execute: median(execute_samples),
        prove: median(prove_samples),
        verify: median(verify_samples),
        receipt_bytes,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bench() -> Result<()> {
    // A dev-mode receipt is a stub: proving returns almost instantly and
    // verification accepts anything. Benchmarking in that mode would produce
    // numbers that look excellent and mean nothing, so refuse outright.
    // `ProverOpts::composite()` picks dev-mode up from the environment, so ask
    // the options actually being proved with rather than a global.
    let opts = ProverOpts::composite();
    if opts.dev_mode() {
        bail!(
            "RISC0_DEV_MODE is enabled. Dev mode fakes the proof, so these \
             timings would be meaningless. Unset RISC0_DEV_MODE and re-run."
        );
    }

    println!("risc0 spike bench — {RUNS} runs per measurement, median reported");
    println!("guest image id: {}", hex_words(&POLICY_GUEST_ID));
    // "local" is in-process; "ipc" means an r0vm subprocess, whose per-call
    // overhead dominates the executor number. Print it so a stray measurement
    // can never be mistaken for the other backend.
    println!("prover backend: {}", default_prover().get_name());
    println!();

    let mut rows = Vec::new();
    for size in SIZES {
        eprintln!("benchmarking {size} B ...");
        rows.push(bench_size(size, &opts)?);
    }

    println!(
        "{:>7}  {:>10}  {:>9}  {:>5}  {:>11}  {:>12}  {:>11}  {:>10}",
        "input", "user cyc", "segments", "po2", "execute ms", "prove ms", "verify ms", "receipt B"
    );
    for r in &rows {
        println!(
            "{:>7}  {:>10}  {:>9}  {:>5}  {:>11.1}  {:>12.1}  {:>11.1}  {:>10}",
            format!("{} B", r.size),
            r.user_cycles,
            r.segments,
            r.max_po2,
            ms(r.execute),
            ms(r.prove),
            ms(r.verify),
            r.receipt_bytes
        );
    }

    println!();
    for r in &rows {
        println!(
            "{} B: executor {:.0} ms / composite prove {:.2} s / receipt {:.1} KB / verify {:.0} ms  ({} total cycles, po2 {})",
            r.size,
            ms(r.execute),
            r.prove.as_secs_f64(),
            r.receipt_bytes as f64 / 1024.0,
            ms(r.verify),
            r.total_cycles,
            r.max_po2
        );
    }

    Ok(())
}

/// The image id is four u32 words; render it the way risc0 tooling does.
fn hex_words(id: &[u32; 8]) -> String {
    id.iter().map(|w| format!("{w:08x}")).collect()
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let mode = std::env::args().nth(1);
    match mode.as_deref() {
        Some("--bench") => bench(),
        _ => {
            eprintln!("usage: cargo run -rp host -- --bench");
            eprintln!();
            eprintln!("Phase 2a spike. Only --bench is implemented; the proving");
            eprintln!("daemon arrives in Task 5.");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Executor-only, so this stays fast enough to sit in `cargo test`. It
    /// pins the contract the policy guest will inherit: one frame in, the
    /// sha256 of exactly those bytes out, agreeing with the host's `sha2`.
    #[test]
    fn guest_commits_sha256_of_the_frame() {
        for size in [0usize, 1, 256, 4096] {
            let input = make_input(size);
            let expected: [u8; 32] = Sha256::digest(&input).into();

            let env = ExecutorEnv::builder()
                .write_frame(&input)
                .build()
                .expect("build env");
            let session = default_executor()
                .execute(env, POLICY_GUEST_ELF)
                .expect("execute guest");

            assert_eq!(
                session.journal.bytes,
                expected.to_vec(),
                "journal mismatch at {size} B"
            );
        }
    }

    #[test]
    fn median_picks_the_middle_sample() {
        let d = |n| Duration::from_millis(n);
        assert_eq!(median(vec![d(30), d(10), d(20)]), d(20));
    }
}

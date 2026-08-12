//! Phase 2a spike host: `--bench` only.
//!
//! Measures the four numbers every later Phase 2a decision depends on, at two
//! input sizes, three timed runs each after a discarded warmup, min/median/max
//! reported:
//!
//! * executor-only wall time — no proof. This is the number that would gate a
//!   live request if the enclave ran the guest inline.
//! * composite proving wall time — the audit artifact, produced off the
//!   request path.
//! * receipt size, bincode-serialised — what a receipt costs to store and ship.
//! * verify wall time — what an independent verifier pays.
//!
//! Three things this harness does deliberately, because the first version of it
//! got them wrong and published a number that was an artifact:
//!
//! 1. **Warmup.** The first execution and the first proof of a process pay
//!    one-time costs (allocator growth, page-in).
//!    With sizes run in a fixed order those costs land entirely on the first
//!    row, which made 256 B look *slower* than 4096 B. One warmup iteration per
//!    size per measurement is run and discarded.
//! 2. **Spread, not just the median.** min/median/max are printed. A single
//!    median hides exactly the cold-start skew described above.
//! 3. **Backend enforcement, not just reporting.** See `bench`.

use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use methods::{POLICY_GUEST_ELF, POLICY_GUEST_ID};
use risc0_zkvm::{default_executor, default_prover, Executor, ExecutorEnv, Prover, ProverOpts};
use sha2::{Digest, Sha256};

/// Timed runs per measurement, after the warmup.
const RUNS: usize = 3;

/// Discarded iterations before timing starts.
const WARMUP: usize = 1;

/// Input frame sizes, in bytes.
const SIZES: [usize; 2] = [256, 4096];

/// A deterministic filler so runs are reproducible without a rand dependency.
/// 251 is prime, so the pattern does not align with any power-of-two block
/// boundary in the hash.
fn make_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// min / median / max of a sample set.
struct Spread {
    min: Duration,
    median: Duration,
    max: Duration,
}

impl Spread {
    fn of(mut samples: Vec<Duration>) -> Self {
        assert!(!samples.is_empty(), "no samples");
        samples.sort_unstable();
        Self {
            min: samples[0],
            median: samples[samples.len() / 2],
            max: samples[samples.len() - 1],
        }
    }

    fn row(&self, label: String) -> String {
        format!(
            "{label:>7}    {:>9.1} / {:>9.1} / {:>9.1}",
            ms(self.min),
            ms(self.median),
            ms(self.max)
        )
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Everything measured for one input size.
struct Row {
    size: usize,
    /// `SessionInfo::cycles()` — user cycles summed across segments, with no
    /// continuation or po2-padding overhead included.
    session_user_cycles: u64,
    /// `SessionStats::user_cycles` from the proving run.
    stats_user_cycles: u64,
    /// `SessionStats::total_cycles` — the real total, padding included. This is
    /// the one that relates to po2.
    stats_total_cycles: u64,
    paging_cycles: u64,
    reserved_cycles: u64,
    segments: usize,
    max_po2: u32,
    execute: Spread,
    prove: Spread,
    verify: Spread,
    receipt_bytes: usize,
}

fn bench_size(
    size: usize,
    executor: &Rc<dyn Executor>,
    prover: &Rc<dyn Prover>,
    opts: &ProverOpts,
) -> Result<Row> {
    let input = make_input(size);
    let expected: [u8; 32] = Sha256::digest(&input).into();

    let build_env = || {
        ExecutorEnv::builder()
            .write_frame(&input)
            .build()
            .context("building executor env")
    };

    // --- executor only -----------------------------------------------------
    let mut execute_samples = Vec::with_capacity(RUNS);
    let mut session_user_cycles = 0u64;
    let mut segments = 0usize;
    let mut max_po2 = 0u32;
    for i in 0..(WARMUP + RUNS) {
        let env = build_env()?;
        let start = Instant::now();
        let session = executor
            .execute(env, POLICY_GUEST_ELF)
            .context("executor run")?;
        let elapsed = start.elapsed();
        if i >= WARMUP {
            execute_samples.push(elapsed);
        }

        // The spike is only worth timing if it computes the right answer.
        if session.journal.bytes != expected {
            bail!(
                "guest journal disagrees with host sha256 at {size} B: \
                 guest={} host={}",
                hex(&session.journal.bytes),
                hex(&expected)
            );
        }
        session_user_cycles = session.cycles();
        segments = session.segments.len();
        max_po2 = session.segments.iter().map(|s| s.po2).max().unwrap_or(0);
    }

    // --- composite proving -------------------------------------------------
    let mut prove_samples = Vec::with_capacity(RUNS);
    let mut verify_samples = Vec::with_capacity(RUNS);
    let mut receipt_bytes = 0usize;
    let mut stats_user_cycles = 0u64;
    let mut stats_total_cycles = 0u64;
    let mut paging_cycles = 0u64;
    let mut reserved_cycles = 0u64;
    for i in 0..(WARMUP + RUNS) {
        let env = build_env()?;
        let start = Instant::now();
        let info = prover
            .prove_with_opts(env, POLICY_GUEST_ELF, opts)
            .context("composite prove")?;
        let prove_elapsed = start.elapsed();

        let receipt = info.receipt;
        stats_user_cycles = info.stats.user_cycles;
        stats_total_cycles = info.stats.total_cycles;
        paging_cycles = info.stats.paging_cycles;
        reserved_cycles = info.stats.reserved_cycles;

        // Note: this runs immediately after proving, on a receipt still hot in
        // cache. A verifier reading a receipt off disk would pay more.
        let start = Instant::now();
        receipt
            .verify(POLICY_GUEST_ID)
            .context("receipt verification")?;
        let verify_elapsed = start.elapsed();

        if i >= WARMUP {
            prove_samples.push(prove_elapsed);
            verify_samples.push(verify_elapsed);
        }

        receipt_bytes = bincode::serialize(&receipt)
            .context("bincode-serialising receipt")?
            .len();

        if receipt.journal.bytes != expected {
            bail!("proved journal disagrees with host sha256 at {size} B");
        }
    }

    Ok(Row {
        size,
        session_user_cycles,
        stats_user_cycles,
        stats_total_cycles,
        paging_cycles,
        reserved_cycles,
        segments,
        max_po2,
        execute: Spread::of(execute_samples),
        prove: Spread::of(prove_samples),
        verify: Spread::of(verify_samples),
        receipt_bytes,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The image id is eight u32 words; render it the way risc0 tooling does.
fn hex_words(id: &[u32; 8]) -> String {
    id.iter().map(|w| format!("{w:08x}")).collect()
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

    // Construct the prover and executor once, outside every timed region, so
    // their setup is not attributed to the first measurement.
    let prover = default_prover();
    let executor = default_executor();

    // Reporting the backend is not enough — enforce it. `default_prover`
    // returns a *remote* Bonsai prover whenever BONSAI_API_URL and
    // BONSAI_API_KEY happen to be set, and it checks that before the local
    // branch. RISC0_PROVER / RISC0_EXECUTOR can redirect it too. Any of those
    // would silently turn "what does this laptop cost" into a measurement of
    // somebody else's hardware and a network round trip.
    let backend = prover.get_name();
    if backend != "local" {
        bail!(
            "prover backend is {backend:?}, expected \"local\". These numbers are \
             supposed to describe proving in-process on this machine. Unset \
             RISC0_PROVER / BONSAI_API_URL / BONSAI_API_KEY and re-run."
        );
    }
    // The Executor trait exposes no name, so check what could redirect it.
    match std::env::var("RISC0_EXECUTOR") {
        Ok(v) if !v.is_empty() && v.to_lowercase() != "local" => bail!(
            "RISC0_EXECUTOR is set to {v:?}, which moves execution out of process. \
             Unset it and re-run."
        ),
        _ => {}
    }

    println!(
        "risc0 spike bench — {RUNS} timed runs per measurement after {WARMUP} discarded warmup"
    );
    println!("guest image id: {}", hex_words(&POLICY_GUEST_ID));
    println!("prover backend: {backend} (enforced, in-process)");
    println!();

    let mut rows = Vec::new();
    for size in SIZES {
        eprintln!("benchmarking {size} B ...");
        rows.push(bench_size(size, &executor, &prover, &opts)?);
    }

    println!("cycles and receipt");
    println!(
        "{:>7}  {:>9}  {:>4}  {:>11}  {:>11}  {:>11}  {:>11}  {:>10}",
        "input",
        "segments",
        "po2",
        "user cyc",
        "total cyc",
        "paging cyc",
        "reserv cyc",
        "receipt B"
    );
    for r in &rows {
        println!(
            "{:>7}  {:>9}  {:>4}  {:>11}  {:>11}  {:>11}  {:>11}  {:>10}",
            format!("{} B", r.size),
            r.segments,
            r.max_po2,
            r.stats_user_cycles,
            r.stats_total_cycles,
            r.paging_cycles,
            r.reserved_cycles,
            r.receipt_bytes
        );
        // Not debug_assert: --bench is documented to run under --release, where
        // a debug assertion is compiled out and would never fire anywhere.
        assert_eq!(
            r.session_user_cycles, r.stats_user_cycles,
            "executor and prover disagree on user cycles at {} B",
            r.size
        );
    }

    println!();
    println!("            min / median / max  (ms)");
    println!("executor only (no proof)");
    for r in &rows {
        println!("{}", r.execute.row(format!("{} B", r.size)));
    }
    println!("composite prove");
    for r in &rows {
        println!("{}", r.prove.row(format!("{} B", r.size)));
    }
    println!("verify (cache-hot, receipt still in memory)");
    for r in &rows {
        println!("{}", r.verify.row(format!("{} B", r.size)));
    }

    println!();
    for r in &rows {
        println!(
            "{} B: executor {:.1} ms / composite prove {:.2} s / receipt {:.1} KB / verify {:.1} ms  ({} user cyc, {} total cyc, po2 {})",
            r.size,
            ms(r.execute.median),
            r.prove.median.as_secs_f64(),
            r.receipt_bytes as f64 / 1024.0,
            ms(r.verify.median),
            r.stats_user_cycles,
            r.stats_total_cycles,
            r.max_po2
        );
    }

    Ok(())
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
        let executor = default_executor();
        for size in [0usize, 1, 256, 4096] {
            let input = make_input(size);
            let expected: [u8; 32] = Sha256::digest(&input).into();

            let env = ExecutorEnv::builder()
                .write_frame(&input)
                .build()
                .expect("build env");
            let session = executor
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
    fn spread_reports_min_median_and_max() {
        let d = Duration::from_millis;
        let s = Spread::of(vec![d(30), d(10), d(20)]);
        assert_eq!(s.min, d(10));
        assert_eq!(s.median, d(20));
        assert_eq!(s.max, d(30));
    }
}

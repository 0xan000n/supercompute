//! Running the policy guest in the zkVM executor.
//!
//! This is the gate path in miniature: frame the input, run the *image* (not a
//! native copy of the engine — §5.2 has no native fallback, because "same
//! source" is not "same compiled semantics"), hand back the journal it committed
//! and the private scores it wrote to stdout.
//!
//! Task 5 wraps this in the `:4500` daemon. It is a library today so that
//! `tests/guest_io.rs` and the `--execute-stdin` mode of the binary exercise
//! exactly the same call.
//!
//! **Nothing here may log its input.** `PolicyInputV1::canonical_request_bytes`
//! *is* the plaintext prompt; the same redaction discipline that applies to
//! `enclave-log` applies to every line of this crate.

use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use methods::{POLICY_GUEST_ELF, POLICY_GUEST_ID};
use policy_core::PolicyInputV1;
use risc0_zkvm::{default_executor, Executor, ExecutorEnv};

/// One executor run.
pub struct ExecOutcome {
    /// The committed journal, verbatim. Canonical JSON; parse, do not re-encode.
    pub journal_bytes: Vec<u8>,
    /// Whatever the guest wrote to stdout — the full evaluation as one JSON
    /// line when `emit_scores` was set, `None` when it wrote nothing.
    ///
    /// Prompt-derived. It exists so `tee-sim` can seal it into the requester's
    /// encrypted response; it is not persisted, not logged, and not provable.
    pub private_scores: Option<String>,
    /// `SessionInfo::cycles()` — user cycles, no continuation or po2 padding.
    pub user_cycles: u64,
    pub segments: usize,
    /// The largest segment po2. Proving cost steps at these boundaries, so this
    /// is the number that decides which side of a cliff a request lands on.
    pub max_po2: u32,
    pub exec_wall: Duration,
}

/// Redacting on purpose. `ExecOutcome` is `Debug` so tests can `expect_err` on
/// it and so a future daemon can put one in a log line — and the moment either
/// of those is true, a derived `Debug` would print the score vector, which is
/// prompt-derived. The journal is public by construction and prints in full.
impl std::fmt::Debug for ExecOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecOutcome")
            .field(
                "journal_bytes",
                &String::from_utf8_lossy(&self.journal_bytes),
            )
            .field(
                "private_scores",
                &self
                    .private_scores
                    .as_ref()
                    .map(|s| format!("<{} redacted bytes>", s.len())),
            )
            .field("user_cycles", &self.user_cycles)
            .field("segments", &self.segments)
            .field("max_po2", &self.max_po2)
            .field("exec_wall", &self.exec_wall)
            .finish()
    }
}

/// The ImageID of the policy guest, rendered the way risc0 tooling renders it.
pub fn image_id_hex() -> String {
    POLICY_GUEST_ID.iter().map(|w| format!("{w:08x}")).collect()
}

/// `PolicyInputV1` as the single frame the guest reads.
pub fn policy_frame(input: &PolicyInputV1) -> Result<Vec<u8>> {
    postcard::to_allocvec(input).context("serializing PolicyInputV1")
}

/// Run the guest in the executor. Constructs an executor per call; callers doing
/// many runs should build one and use [`execute_policy_with`].
pub fn execute_policy(input: &PolicyInputV1) -> Result<ExecOutcome> {
    execute_policy_with(&default_executor(), input)
}

pub fn execute_policy_with(
    executor: &Rc<dyn Executor>,
    input: &PolicyInputV1,
) -> Result<ExecOutcome> {
    execute_frame_with(executor, &policy_frame(input)?)
}

/// Run the guest over frame bytes directly. The only caller that needs this
/// rather than [`execute_policy`] is a test that wants to hand the guest a frame
/// no correct host would build.
pub fn execute_frame(frame: &[u8]) -> Result<ExecOutcome> {
    execute_frame_with(&default_executor(), frame)
}

pub fn execute_frame_with(executor: &Rc<dyn Executor>, frame: &[u8]) -> Result<ExecOutcome> {
    // The guest's stdout is captured into this buffer. The borrow has to end
    // before the buffer is read, hence the block: `env` holds it for as long as
    // it lives, and `execute` consumes `env`.
    let mut stdout_buf: Vec<u8> = Vec::new();
    let start = Instant::now();
    let session = {
        let env = ExecutorEnv::builder()
            .write_frame(frame)
            .stdout(&mut stdout_buf)
            .build()
            .context("building executor env")?;
        executor
            .execute(env, POLICY_GUEST_ELF)
            // The guest's panic message rides on this error. It can name a
            // rejected field but never a value (see
            // `CanonicalRequestV1::from_json_bytes`), so it is safe to return —
            // and still not safe to log.
            .context("policy guest execution failed")?
    };
    let exec_wall = start.elapsed();

    let private_scores = if stdout_buf.is_empty() {
        None
    } else {
        Some(String::from_utf8(stdout_buf).context("guest stdout is not UTF-8")?)
    };

    Ok(ExecOutcome {
        journal_bytes: session.journal.bytes.clone(),
        private_scores,
        user_cycles: session.cycles(),
        segments: session.segments.len(),
        max_po2: session.segments.iter().map(|s| s.po2).max().unwrap_or(0),
        exec_wall,
    })
}

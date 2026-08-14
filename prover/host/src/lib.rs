//! Running the policy guest in the zkVM executor.
//!
//! This is the gate path in miniature: frame the input, run the *image* (not a
//! native copy of the engine — §5.2 has no native fallback, because "same
//! source" is not "same compiled semantics"), hand back the journal it committed
//! and the private scores it wrote to stdout.
//!
//! [`server`] wraps this in the `:4500` daemon and [`queue`] runs the proving
//! half on its own thread. It is a library so that `tests/guest_io.rs`,
//! `tests/api.rs`, the daemon and the `--execute-stdin` mode of the binary all
//! exercise exactly the same call.
//!
//! **Nothing here may log its input.** `PolicyInputV1::canonical_request_bytes`
//! *is* the plaintext prompt; the same redaction discipline that applies to
//! `enclave-log` applies to every line of this crate.
//!
//! That discipline is not enough on its own, which is the lesson of Task 4's
//! first fix round: the executor writes the guest's stderr to the *host
//! process's* stderr unless told otherwise, so "this crate never logs" said
//! nothing about what got printed. [`execute_frame_with`] now names an explicit
//! sink for guest stderr, and every value that leaves this module on a failure
//! path is one of the constants in `policy_core::GuestRejection` or
//! [`UNCLASSIFIED_FAILURE`].

pub mod queue;
pub mod server;

use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use methods::{POLICY_GUEST_ELF, POLICY_GUEST_ID};
use policy_core::{GuestRejection, PolicyInputV1};
use risc0_zkvm::{default_executor, Executor, ExecutorEnv};

/// The reason returned when an executor failure matches no [`GuestRejection`].
///
/// A host-side failure (a session limit, an ELF that will not load) lands here,
/// and so would a guest panic from code that forgot the taxonomy. Deliberately
/// contentless: "we do not recognise this" is the honest thing to say to a
/// caller, and the underlying error is available to an operator through
/// [`UNSAFE_DIAGNOSTICS_ENV`].
pub const UNCLASSIFIED_FAILURE: &str = "policy guest execution failed for an unclassified reason";

/// Set this to `1` or `true` and [`execute_frame_with`] prints the raw executor
/// error and the guest's stderr to the host's stderr on failure.
///
/// **This defeats the leak defence and is named to say so.** The raw error and
/// the guest's stderr can both contain fragments of the canonical request, which
/// is the plaintext prompt. It exists for someone debugging the guest on their
/// own laptop with their own input. Nothing in CI, in `pnpm test`, or in the
/// `:4500` daemon may set it.
///
/// Only `1` and `true` enable it. The first version tested `var_os().is_some()`,
/// so `CTN_UNSAFE_GUEST_DIAGNOSTICS=0` — and `=false`, and `=off` — *enabled*
/// the dump. That is the opposite of what anyone typing it means, and the
/// variable is one whose accidental activation prints prompt text.
pub const UNSAFE_DIAGNOSTICS_ENV: &str = "CTN_UNSAFE_GUEST_DIAGNOSTICS";

/// Whether [`UNSAFE_DIAGNOSTICS_ENV`] is set to one of the two values that mean
/// "yes". Anything else — unset, empty, `0`, `false`, `off`, a typo, non-UTF-8
/// — means no.
pub fn unsafe_diagnostics_enabled() -> bool {
    matches!(
        std::env::var(UNSAFE_DIAGNOSTICS_ENV).as_deref(),
        Ok("1") | Ok("true")
    )
}

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

/// Reduce an executor failure to a fixed string.
///
/// The rendered error carries the guest's panic message, and the guest's panic
/// messages are `GuestRejection` constants — but *only* the guest's are. An
/// executor error can also come from risc0 itself, and neither this crate nor
/// its callers can enumerate what risc0 might put in one. So the rule is not
/// "sanitise the message"; it is **never return the message**. Match it against
/// the closed taxonomy and return the constant that matched, or say nothing.
///
/// Matching on a substring of caller-influenced text is safe here because the
/// output is one of nine compile-time constants. A caller who plants
/// `"unsupported protocol version"` in their prompt and then sends a malformed
/// frame gets that string back; they wrote it.
pub fn classify_guest_failure(err: &anyhow::Error) -> &'static str {
    GuestRejection::from_message(&format!("{err:#}"))
        .map(GuestRejection::as_str)
        .unwrap_or(UNCLASSIFIED_FAILURE)
}

pub fn execute_frame_with(executor: &Rc<dyn Executor>, frame: &[u8]) -> Result<ExecOutcome> {
    // The guest's stdout and stderr are captured into these buffers. The borrow
    // has to end before either is read, hence the block: `env` holds them for as
    // long as it lives, and `execute` consumes `env`.
    //
    // The stderr hook is not optional and not cosmetic. `PosixIo::default`
    // (risc0-zkvm-3.0.6/src/host/client/posix_io.rs:36-43) wires guest fd 2 to
    // `std::io::stderr()` — the *host process's* stderr — so without this line
    // the guest's panic message is printed by the executor, into whatever
    // captures this process's output, before any code here can decide whether it
    // should be. That is a channel no amount of care about return values closes.
    // The guest's messages are constants (`GuestRejection`), so this is the
    // second of two independent defences rather than the only one.
    let mut stdout_buf: Vec<u8> = Vec::new();
    let mut stderr_buf: Vec<u8> = Vec::new();
    let start = Instant::now();
    let result = {
        let env = ExecutorEnv::builder()
            .write_frame(frame)
            .stdout(&mut stdout_buf)
            .stderr(&mut stderr_buf)
            .build()
            .context("building executor env")?;
        executor.execute(env, POLICY_GUEST_ELF)
    };
    let exec_wall = start.elapsed();

    let session = match result {
        Ok(session) => session,
        Err(err) => {
            if unsafe_diagnostics_enabled() {
                // Written straight to fd 2 rather than through `eprintln!`,
                // which the test harness intercepts at the Rust level
                // (`std::io::set_output_capture`) — the one place this text is
                // asserted about is a test, so it has to travel the same way
                // risc0's own guest-stderr writes do.
                let _ = std::io::Write::write_all(
                    &mut std::io::stderr(),
                    format!(
                        "{UNSAFE_DIAGNOSTICS_ENV} is set — the two lines below MAY CONTAIN PROMPT TEXT\n\
                           executor error: {err:#}\n\
                           guest stderr:   {}\n",
                        String::from_utf8_lossy(&stderr_buf).trim_end()
                    )
                    .as_bytes(),
                );
            }
            // Not `.context(err)`: the rendered error is exactly what must not
            // escape. `stderr_buf` is dropped here, unread.
            return Err(anyhow!("{}", classify_guest_failure(&err)));
        }
    };

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

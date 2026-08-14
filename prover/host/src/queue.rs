//! The prove queue: one dedicated OS thread, FIFO, in memory.
//!
//! Two facts about proving decide this whole module's shape. A composite prove
//! of the policy guest takes minutes and saturates every core (Task 4: ~130 s on
//! an M1 Pro, CPU-only), and an `/execute` call must still answer in ~60 ms
//! while one is in flight, because `tee-sim` is holding a live request open on
//! it. So proving does **not** run on the tokio runtime — not on a worker
//! thread, not on `spawn_blocking`, where it would occupy a runtime thread for
//! the whole run. It runs on one thread of our own, consuming an `mpsc` queue,
//! and the runtime never blocks on it.
//!
//! One worker, not a pool: the machine has one set of cores and a composite
//! prove already uses all of them, so a second concurrent prove makes both
//! slower without making either finish sooner.
//!
//! Everything here is in memory and dies with the process. Persistence,
//! backpressure policy and retry belong to the coordinator in Phase 2b (§5.6);
//! this queue's only concessions to being a real queue are a cap on outstanding
//! work and a cap on retained finished jobs, both below.
//!
//! **`QueuedJob::frame` contains the canonical request bytes — the plaintext
//! prompt.** It lives in this process's memory until the job finishes, which is
//! the same trust boundary `tee-sim` is inside (§4). It is never logged, never
//! written to disk, and never included in any response.

use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use methods::POLICY_GUEST_ELF;
use policy_core::hex_lower;
use rand::RngCore;
use risc0_zkvm::{default_prover, ExecutorEnv, Prover, ProverOpts};
use serde::Serialize;

use crate::{classify_guest_failure, UNCLASSIFIED_FAILURE};

/// Jobs accepted but not yet started. Past this, `/prove` refuses rather than
/// growing an unbounded backlog of plaintext prompts in memory. At ~130 s per
/// prove, 32 outstanding jobs is already over an hour of queue.
pub const MAX_QUEUED: usize = 32;

/// Finished jobs kept for collection. Each `GENERATED` job holds a ~500 KB
/// receipt, so this bounds the daemon's memory at something knowable; the oldest
/// *finished* job is evicted first and a job that is still queued or proving is
/// never evicted.
pub const MAX_JOBS_RETAINED: usize = 64;

/// The reason a receipt could not be serialized. A host-side failure, not a
/// guest one, and — like every other reason string that leaves this crate — a
/// constant.
const RECEIPT_NOT_SERIALIZABLE: &str = "receipt could not be serialized";

/// The four states of a job, spelled the way the wire spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobStatus {
    Queued,
    Proving,
    Generated,
    Failed,
}

impl JobStatus {
    fn is_terminal(self) -> bool {
        matches!(self, JobStatus::Generated | JobStatus::Failed)
    }
}

/// `GET /jobs/:id`, verbatim.
///
/// `error` is `&'static str` rather than `String` on purpose: the type system is
/// doing the work of the rule that a failure reason is one of the fixed taxonomy
/// constants and never a rendered error. You cannot put a formatted string here
/// without changing the type.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobView {
    pub status: JobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prove_wall_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    /// Stamped on **every** job response, not only in dev mode. A receipt
    /// produced under `RISC0_DEV_MODE` is a stub that any verifier built without
    /// `disable-dev-mode` will happily accept; the daemon's job is to never let
    /// that state be inferred from silence.
    pub dev_mode: bool,
}

/// Why `/prove` refused the job. Both are conditions of the daemon, not of the
/// request, so both are 503s server-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueError {
    /// [`MAX_QUEUED`] jobs are already waiting.
    Full,
    /// The prove worker thread is gone. Nothing will ever be proved again.
    WorkerGone,
}

struct QueuedJob {
    id: String,
    /// The postcard frame — canonical request bytes included. Prompt plaintext;
    /// see the module comment.
    frame: Vec<u8>,
}

#[derive(Default)]
struct Jobs {
    table: HashMap<String, JobView>,
    /// Insertion order, for eviction.
    order: VecDeque<String>,
}

impl Jobs {
    fn insert(&mut self, id: String, view: JobView) {
        self.table.insert(id.clone(), view);
        self.order.push_back(id);
        self.evict();
    }

    /// Drop the oldest *finished* jobs until the table is within
    /// [`MAX_JOBS_RETAINED`]. A queued or proving job is skipped rather than
    /// evicted: forgetting a job that is about to produce a receipt would strand
    /// the caller polling for it.
    fn evict(&mut self) {
        let mut scanned = 0;
        while self.order.len() > MAX_JOBS_RETAINED && scanned < self.order.len() {
            let Some(id) = self.order.pop_front() else {
                break;
            };
            match self.table.get(&id) {
                Some(view) if view.status.is_terminal() => {
                    self.table.remove(&id);
                }
                Some(_) => {
                    self.order.push_back(id);
                    scanned += 1;
                }
                None => {}
            }
        }
    }

    fn queued_count(&self) -> usize {
        self.table
            .values()
            .filter(|v| v.status == JobStatus::Queued)
            .count()
    }
}

/// The queue handle the HTTP layer holds.
pub struct ProveQueue {
    jobs: Arc<Mutex<Jobs>>,
    /// `mpsc::Sender` is `Send` but not `Sync`, and the axum state is shared
    /// across runtime threads, so the handle is behind a mutex. It is held for
    /// the length of one `send`, which never blocks on an unbounded channel.
    tx: Mutex<Sender<QueuedJob>>,
    dev_mode: bool,
}

impl ProveQueue {
    /// Start the worker thread and return the handle. The worker lives as long
    /// as the process; it stops when the sender is dropped.
    pub fn start(dev_mode: bool) -> Arc<Self> {
        let (tx, rx) = mpsc::channel::<QueuedJob>();
        let jobs: Arc<Mutex<Jobs>> = Arc::new(Mutex::new(Jobs::default()));
        let worker_jobs = Arc::clone(&jobs);
        std::thread::Builder::new()
            .name("prove-worker".to_owned())
            .spawn(move || worker(rx, worker_jobs))
            .expect("spawning the prove worker");
        Arc::new(Self {
            jobs,
            tx: Mutex::new(tx),
            dev_mode,
        })
    }

    pub fn dev_mode(&self) -> bool {
        self.dev_mode
    }

    /// Accept a frame for proving. Returns the job id.
    pub fn enqueue(&self, frame: Vec<u8>) -> Result<String, EnqueueError> {
        let id = new_job_id();
        {
            let mut jobs = self.jobs.lock().expect("jobs lock");
            if jobs.queued_count() >= MAX_QUEUED {
                return Err(EnqueueError::Full);
            }
            jobs.insert(
                id.clone(),
                JobView {
                    status: JobStatus::Queued,
                    receipt_b64: None,
                    prove_wall_ms: None,
                    error: None,
                    dev_mode: self.dev_mode,
                },
            );
        }
        self.tx
            .lock()
            .expect("queue lock")
            .send(QueuedJob {
                id: id.clone(),
                frame,
            })
            .map_err(|_| EnqueueError::WorkerGone)?;
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Option<JobView> {
        self.jobs.lock().expect("jobs lock").table.get(id).cloned()
    }
}

/// 16 bytes from the OS CSPRNG, hex. Unpredictable, not merely unique: a job id
/// is the only thing standing between a local caller and someone else's receipt.
fn new_job_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex_lower(&bytes)
}

fn update(jobs: &Mutex<Jobs>, id: &str, f: impl FnOnce(&mut JobView)) {
    if let Some(view) = jobs.lock().expect("jobs lock").table.get_mut(id) {
        f(view);
    }
}

/// The worker. One thread, one job at a time, in the order they were accepted.
fn worker(rx: Receiver<QueuedJob>, jobs: Arc<Mutex<Jobs>>) {
    // Both are `Rc` and neither is `Send`, so they are constructed here rather
    // than passed in — which is also what keeps the prover confined to this
    // thread.
    let prover = default_prover();
    let opts = ProverOpts::composite();

    while let Ok(job) = rx.recv() {
        update(&jobs, &job.id, |v| v.status = JobStatus::Proving);
        // Sizes and ids only. The frame is the prompt.
        tracing::info!(job_id = %job.id, frame_bytes = job.frame.len(), "prove started");

        let start = Instant::now();
        let outcome = prove_frame(&prover, &opts, &job.frame);
        let prove_wall_ms = start.elapsed().as_millis() as u64;

        match outcome {
            Ok((receipt_b64, receipt_bytes)) => {
                tracing::info!(
                    job_id = %job.id,
                    prove_wall_ms,
                    receipt_bytes,
                    "prove generated"
                );
                update(&jobs, &job.id, |v| {
                    v.status = JobStatus::Generated;
                    v.receipt_b64 = Some(receipt_b64);
                    v.prove_wall_ms = Some(prove_wall_ms);
                });
            }
            Err(reason) => {
                // `reason` is a taxonomy constant, so logging it is safe by
                // construction rather than by review.
                tracing::warn!(job_id = %job.id, prove_wall_ms, reason, "prove failed");
                update(&jobs, &job.id, |v| {
                    v.status = JobStatus::Failed;
                    v.error = Some(reason);
                    v.prove_wall_ms = Some(prove_wall_ms);
                });
            }
        }
        // `job` — and with it the plaintext frame — is dropped here.
    }
}

/// Prove one frame. `Err` is always a fixed string: the guest taxonomy via
/// [`classify_guest_failure`], or one of two host-side constants.
fn prove_frame(
    prover: &Rc<dyn Prover>,
    opts: &ProverOpts,
    frame: &[u8],
) -> Result<(String, usize), &'static str> {
    // Explicit sinks for both guest streams, for the reason spelled out in
    // `execute_frame_with`: risc0's default `PosixIo` wires the guest's fd 1 and
    // fd 2 to *this process's* stdout and stderr, so a guest panic would print
    // itself into the daemon's own log before any code here could decide
    // whether it should. The prove path sends `emit_scores: false`, so nothing
    // is expected on either; the buffers exist so that "nothing is expected" is
    // not the only thing stopping it.
    let mut guest_stdout: Vec<u8> = Vec::new();
    let mut guest_stderr: Vec<u8> = Vec::new();
    let result = {
        let env = ExecutorEnv::builder()
            .write_frame(frame)
            .stdout(&mut guest_stdout)
            .stderr(&mut guest_stderr)
            .build()
            .map_err(|_| UNCLASSIFIED_FAILURE)?;
        prover.prove_with_opts(env, POLICY_GUEST_ELF, opts)
    };
    // Both buffers are dropped unread. Their contents are prompt-derived.
    let info = result.map_err(|e| classify_guest_failure(&e))?;

    let bytes = bincode::serialize(&info.receipt).map_err(|_| RECEIPT_NOT_SERIALIZABLE)?;
    Ok((BASE64_STANDARD.encode(&bytes), bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(status: JobStatus) -> JobView {
        JobView {
            status,
            receipt_b64: None,
            prove_wall_ms: None,
            error: None,
            dev_mode: false,
        }
    }

    /// The wire spellings are the contract Phase 2b matches on.
    #[test]
    fn statuses_serialize_as_the_wire_spells_them() {
        let rendered: Vec<String> = [
            JobStatus::Queued,
            JobStatus::Proving,
            JobStatus::Generated,
            JobStatus::Failed,
        ]
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
        assert_eq!(
            rendered,
            vec!["\"QUEUED\"", "\"PROVING\"", "\"GENERATED\"", "\"FAILED\""]
        );
    }

    #[test]
    fn a_queued_job_renders_only_status_and_dev_mode() {
        assert_eq!(
            serde_json::to_string(&view(JobStatus::Queued)).unwrap(),
            r#"{"status":"QUEUED","devMode":false}"#
        );
    }

    /// Eviction keeps the table bounded but never forgets work in flight.
    #[test]
    fn eviction_drops_finished_jobs_and_keeps_unfinished_ones() {
        let mut jobs = Jobs::default();
        jobs.insert("pinned".to_owned(), view(JobStatus::Proving));
        for i in 0..(MAX_JOBS_RETAINED + 10) {
            jobs.insert(format!("job-{i}"), view(JobStatus::Generated));
        }
        assert!(jobs.table.len() <= MAX_JOBS_RETAINED + 1);
        assert!(
            jobs.table.contains_key("pinned"),
            "an unfinished job was evicted"
        );
        assert!(
            jobs.table
                .contains_key(&format!("job-{}", MAX_JOBS_RETAINED + 9)),
            "the newest job was evicted"
        );
        assert!(!jobs.table.contains_key("job-0"), "the oldest job survived");
        assert_eq!(
            jobs.order.len(),
            jobs.table.len(),
            "order and table drifted"
        );
    }

    #[test]
    fn job_ids_are_sixteen_random_bytes_and_do_not_repeat() {
        let ids: std::collections::HashSet<String> = (0..1000).map(|_| new_job_id()).collect();
        assert_eq!(ids.len(), 1000, "job ids collided");
        for id in &ids {
            assert_eq!(id.len(), 32);
            assert!(id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        }
    }
}

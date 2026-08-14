//! The `:4500` daemon: `POST /execute`, `POST /prove`, `GET /jobs/:id`,
//! `GET /health`.
//!
//! Phase 2b consumes these shapes verbatim (`prover/host/tests/api.rs` is the
//! executable statement of them), so the rules this module follows are worth
//! naming:
//!
//! * **127.0.0.1 only.** [`serve`] builds the address itself and takes a port,
//!   not a bind address. There is no configuration that makes this daemon
//!   reachable from the network.
//! * **Every failure reason is a `&'static str`.** [`ApiError::reason`] is not a
//!   `String`, so a rendered error cannot be returned by accident — that is
//!   Task 4's leak (`serde_json` quotes the value it choked on, and the value is
//!   the prompt) expressed as a type rather than as a review comment. The guest
//!   half of the taxonomy is `policy_core::GuestRejection`, whose constants are
//!   the wire contract.
//! * **Nothing prompt-derived is logged.** Job ids, byte counts, wall times,
//!   digests and decisions are logged; canonical bytes, private scores and the
//!   caller's proof nonce are not. The nonce's *length* is logged instead of its
//!   value, because the value is caller-chosen and lands in a public journal.
//! * **The runtime never proves.** `/execute` runs the zkVM executor on
//!   `spawn_blocking` (~57 ms, Task 4); `/prove` hands a frame to the queue's
//!   own thread and returns. See `queue.rs`.
//!
//! The daemon is inside the simulated confidential boundary (§4): it necessarily
//! holds the plaintext policy witness. "Inside the boundary" is why it may hold
//! the bytes at all, and the redaction discipline above is what keeps holding
//! them from becoming publishing them.

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use methods::{POLICY_ID_V2, RULES_DIGEST};
use policy_core::{proof_nonce_is_well_formed, GuestRejection, PolicyInputV1, PROTOCOL_VERSION};
use risc0_zkvm::{default_executor, Executor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::queue::{EnqueueError, JobView, ProveQueue};
use crate::{execute_policy_with, image_id_hex, policy_frame, ExecOutcome, UNCLASSIFIED_FAILURE};

/// The largest request body the daemon will read, bodies being base64 of a
/// canonical request. 10 MiB is ~7.5 MB of canonical JSON: far past any prompt
/// the gateway accepts, and small enough that a hostile local client cannot make
/// the daemon allocate its way out of memory. A larger body is refused before it
/// is parsed, so the cap costs nothing on the normal path.
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

// The complete set of host-side reason strings. The guest-side ones are
// `policy_core::GuestRejection::as_str()` values and are returned unchanged.
const CONTENT_TYPE: &str = "content-type must be application/json";
const BODY_NOT_JSON: &str = "request body is not valid JSON";
const BODY_SCHEMA: &str = "request body does not match the expected schema";
const BODY_TOO_LARGE: &str = "request body exceeds the size limit";
const BODY_UNREADABLE: &str = "request body could not be read";
const BAD_BASE64: &str = "canonicalRequestBytesB64 is not valid base64";
const BAD_NONCE: &str = "requestNonceHex must be 32 bytes of hex";
const NO_SUCH_JOB: &str = "no such job";
const NO_SUCH_ENDPOINT: &str = "no such endpoint";
const QUEUE_FULL: &str = "prove queue is full";
const WORKER_GONE: &str = "the prove worker is not running";
const EXECUTOR_TASK_FAILED: &str = "the executor task did not complete";
const JOURNAL_UNREADABLE: &str = "guest journal is not canonical JSON";
const JOURNAL_SHAPE: &str = "guest journal does not carry the expected key set";
const SCORES_UNREADABLE: &str = "guest score output did not match the request";
const FRAME_UNSERIALIZABLE: &str = "the request could not be framed for the guest";

/// The journal key set `services/tee-sim/src/verify.ts` allows, sorted. The
/// daemon re-checks it on every response: the guest is the thing that enforces
/// it, and this is the assertion that the thing enforcing it still is.
const JOURNAL_KEYS: [&str; 5] = [
    "decision",
    "policyId",
    "proofNonce",
    "protocolVersion",
    "requestCommitment",
];

thread_local! {
    /// One executor per blocking-pool thread. `Rc<dyn Executor>` is not `Send`,
    /// so it cannot be shared from the state; building one per call would also
    /// work, and this only avoids doing that on every request.
    static EXECUTOR: Rc<dyn Executor> = default_executor();
}

#[derive(Clone)]
pub struct AppState {
    pub queue: Arc<ProveQueue>,
    /// `true` when receipts from this daemon may be dev-mode stubs. Reported by
    /// `/health` and stamped on every job. See `main.rs` for how it is decided.
    pub dev_mode: bool,
}

/// A refusal. `reason` is `&'static str` and that is the point — see the module
/// comment. `Debug` is derivable *because* of that: there is no field here that
/// could print a byte of the request.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    reason: &'static str,
}

impl ApiError {
    /// The caller sent something the daemon will not act on. Every malformed
    /// request is a 400, including a body that is too large or carries the wrong
    /// content type: HTTP has 413 and 415 for those, but the contract Phase 2b
    /// implements against is "malformed input → 400 with a fixed reason", and
    /// one shape is easier to hold callers to than three.
    fn bad_request(reason: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            reason,
        }
    }

    /// The daemon failed. Distinct from a refusal: a 400 says the request is
    /// wrong, a 500 says we are.
    fn internal(reason: &'static str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            reason,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.reason }))).into_response()
    }
}

/// Map an extractor rejection to a fixed reason. The rejection's own `Display`
/// is never used: `JsonDataError` renders the offending value, and the offending
/// value is the request.
fn json_rejection(rejection: JsonRejection) -> ApiError {
    let reason = match &rejection {
        JsonRejection::MissingJsonContentType(_) => CONTENT_TYPE,
        JsonRejection::JsonSyntaxError(_) => BODY_NOT_JSON,
        JsonRejection::JsonDataError(_) => BODY_SCHEMA,
        // `Bytes` rejects an over-long body with a 413 of its own; the daemon
        // reports it as a 400 like every other malformed request.
        _ if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => BODY_TOO_LARGE,
        _ => BODY_UNREADABLE,
    };
    ApiError::bad_request(reason)
}

/// An executor or prover failure, already reduced to a constant by
/// [`crate::classify_guest_failure`]. A reason inside the guest taxonomy is the
/// caller's fault (400); anything else is ours (500).
fn guest_failure(err: &anyhow::Error) -> ApiError {
    match GuestRejection::from_message(&format!("{err:#}")) {
        Some(rejection) => ApiError::bad_request(rejection.as_str()),
        None => ApiError::internal(UNCLASSIFIED_FAILURE),
    }
}

// ---------------------------------------------------------------------------
// bodies
// ---------------------------------------------------------------------------

/// `POST /execute`.
///
/// `deny_unknown_fields` is deliberate: a caller who misspells `emitScores` is
/// asking for scores and would silently not get them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecuteBody {
    protocol_version: u32,
    canonical_request_bytes_b64: String,
    request_nonce_hex: String,
    proof_nonce: String,
    emit_scores: bool,
}

/// `POST /prove` — the same body minus `emitScores`, and sending that field is
/// an error rather than a no-op: the prove path never captures scores, so
/// accepting it would imply an option that does not exist.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProveBody {
    protocol_version: u32,
    canonical_request_bytes_b64: String,
    request_nonce_hex: String,
    proof_nonce: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecuteResponse {
    /// The five allowlist fields, exactly as the guest committed them.
    journal: Value,
    /// The full evaluation when `emitScores` was set, `null` otherwise. Never
    /// proved, never persisted, never logged: it is prompt-derived.
    private_scores: Option<Value>,
    exec_wall_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    image_id_hex: String,
    policy_id: &'static str,
    rules_digest: &'static str,
    risc0_version: &'static str,
    dev_mode: bool,
}

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

/// The cheap checks, in cheap-first order, ending with the base64 decode that
/// can touch megabytes.
///
/// The proof-nonce check duplicates one the guest performs. That is intentional
/// and the duplicate is the *weaker* copy: it saves a ~57 ms executor run on a
/// request that cannot succeed, and the guest's copy — which the differential
/// harness exercises — remains the one that decides what reaches a journal.
/// Removing the guest's check because this one exists would hand the decision
/// back to the host, which is the party this bound defends against.
fn validate(
    protocol_version: u32,
    canonical_request_bytes_b64: &str,
    request_nonce_hex: &str,
    proof_nonce: String,
    emit_scores: bool,
) -> Result<PolicyInputV1, ApiError> {
    if protocol_version != PROTOCOL_VERSION {
        return Err(ApiError::bad_request(
            GuestRejection::UnsupportedProtocolVersion.as_str(),
        ));
    }
    if !proof_nonce_is_well_formed(&proof_nonce) {
        return Err(ApiError::bad_request(
            GuestRejection::ProofNonceNotBoundedHex.as_str(),
        ));
    }
    let request_nonce =
        parse_nonce(request_nonce_hex).ok_or_else(|| ApiError::bad_request(BAD_NONCE))?;
    let canonical_request_bytes = BASE64_STANDARD
        .decode(canonical_request_bytes_b64)
        .map_err(|_| ApiError::bad_request(BAD_BASE64))?;
    Ok(PolicyInputV1 {
        protocol_version,
        canonical_request_bytes,
        request_nonce,
        proof_nonce,
        emit_scores,
    })
}

/// 32 bytes of hex, `0x` optional (`randomHex` in
/// `packages/protocol/src/crypto.ts:121` returns it bare).
fn parse_nonce(hex: &str) -> Option<[u8; 32]> {
    let clean = hex.strip_prefix("0x").unwrap_or(hex);
    if clean.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(clean.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

async fn execute(
    body: Result<Json<ExecuteBody>, JsonRejection>,
) -> Result<Json<ExecuteResponse>, ApiError> {
    let Json(body) = body.map_err(json_rejection)?;
    let input = validate(
        body.protocol_version,
        &body.canonical_request_bytes_b64,
        &body.request_nonce_hex,
        body.proof_nonce,
        body.emit_scores,
    )?;

    let emit_scores = input.emit_scores;
    let canonical_bytes = input.canonical_request_bytes.len();
    let proof_nonce_len = input.proof_nonce.len();

    let started = Instant::now();
    let outcome = tokio::task::spawn_blocking(move || {
        EXECUTOR.with(|executor| execute_policy_with(executor, &input))
    })
    .await
    .map_err(|_| ApiError::internal(EXECUTOR_TASK_FAILED))?
    .map_err(|err| guest_failure(&err))?;

    let response = shape_response(outcome, emit_scores)?;
    tracing::info!(
        decision = %response.journal["decision"].as_str().unwrap_or("?"),
        canonical_bytes,
        proof_nonce_len,
        exec_wall_ms = response.exec_wall_ms,
        queue_wall_ms = started.elapsed().as_millis() as u64,
        "execute"
    );
    Ok(Json(response))
}

/// Turn an executor outcome into the response body, re-checking the two
/// invariants the guest is supposed to guarantee: the journal carries exactly
/// the allowlist, and scores appear only when they were asked for.
fn shape_response(outcome: ExecOutcome, emit_scores: bool) -> Result<ExecuteResponse, ApiError> {
    let journal: Value = serde_json::from_slice(&outcome.journal_bytes)
        .map_err(|_| ApiError::internal(JOURNAL_UNREADABLE))?;
    let mut keys: Vec<&str> = journal
        .as_object()
        .ok_or_else(|| ApiError::internal(JOURNAL_SHAPE))?
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    if keys != JOURNAL_KEYS {
        return Err(ApiError::internal(JOURNAL_SHAPE));
    }

    let private_scores = match (outcome.private_scores, emit_scores) {
        (Some(scores), true) => {
            Some(serde_json::from_str(&scores).map_err(|_| ApiError::internal(SCORES_UNREADABLE))?)
        }
        (None, false) => None,
        // Either the guest emitted scores nobody asked for, or it did not emit
        // the ones that were asked for. Both mean the image is not the one this
        // daemon thinks it is running.
        _ => return Err(ApiError::internal(SCORES_UNREADABLE)),
    };

    Ok(ExecuteResponse {
        journal,
        private_scores,
        exec_wall_ms: outcome.exec_wall.as_millis() as u64,
    })
}

async fn prove(
    State(state): State<AppState>,
    body: Result<Json<ProveBody>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(body) = body.map_err(json_rejection)?;
    let input = validate(
        body.protocol_version,
        &body.canonical_request_bytes_b64,
        &body.request_nonce_hex,
        body.proof_nonce,
        // Never true on this path: scores are an executor-only output.
        false,
    )?;
    let canonical_bytes = input.canonical_request_bytes.len();
    let proof_nonce_len = input.proof_nonce.len();

    let frame = policy_frame(&input).map_err(|_| ApiError::internal(FRAME_UNSERIALIZABLE))?;
    let job_id = state.queue.enqueue(frame).map_err(|e| match e {
        EnqueueError::Full => ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            reason: QUEUE_FULL,
        },
        EnqueueError::WorkerGone => ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            reason: WORKER_GONE,
        },
    })?;

    tracing::info!(
        job_id = %job_id,
        canonical_bytes,
        proof_nonce_len,
        "prove accepted"
    );
    Ok((StatusCode::ACCEPTED, Json(json!({ "jobId": job_id }))))
}

async fn job(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JobView>, ApiError> {
    // The id is not echoed on the 404 either: it is caller-chosen text.
    state.queue.get(&id).map(Json).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        reason: NO_SUCH_JOB,
    })
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        image_id_hex: image_id_hex(),
        policy_id: POLICY_ID_V2,
        rules_digest: RULES_DIGEST,
        // The version of `risc0-zkvm` this binary was compiled against, read
        // from the crate itself rather than restated in a constant that could
        // drift from the dependency.
        risc0_version: risc0_zkvm::VERSION,
        dev_mode: state.dev_mode,
    })
}

async fn not_found() -> ApiError {
    ApiError {
        status: StatusCode::NOT_FOUND,
        reason: NO_SUCH_ENDPOINT,
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/execute", post(execute))
        .route("/prove", post(prove))
        .route("/jobs/{id}", get(job))
        .route("/health", get(health))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Bind and serve. **The address is built here**: the caller chooses a port and
/// nothing else, so there is no configuration path to a non-loopback bind.
pub async fn serve(port: u16, state: AppState) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    // Tests parse this line for the port when the daemon is started on port 0.
    tracing::info!("listening on {local}");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_parsing_is_strict() {
        assert_eq!(parse_nonce(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(
            parse_nonce(&format!("0x{}", "ab".repeat(32))),
            Some([0xab; 32])
        );
        assert_eq!(parse_nonce(""), None);
        assert_eq!(parse_nonce("0x"), None);
        assert_eq!(parse_nonce(&"ab".repeat(31)), None);
        assert_eq!(parse_nonce(&"ab".repeat(33)), None);
        assert_eq!(parse_nonce(&"z".repeat(64)), None);
        // A multi-byte character cannot be sliced into hex pairs: `get` must
        // return None rather than panicking on a non-char-boundary index.
        assert_eq!(parse_nonce(&"é".repeat(32)), None);
    }

    /// Validation order is part of the contract: the cheap checks answer before
    /// the daemon decodes a body that may be megabytes.
    #[test]
    fn validation_refuses_with_taxonomy_constants() {
        let b64 = BASE64_STANDARD.encode(b"{}");
        let nonce = "ab".repeat(32);

        let err = validate(2, &b64, &nonce, "0xab".to_owned(), false).unwrap_err();
        assert_eq!(
            err.reason,
            GuestRejection::UnsupportedProtocolVersion.as_str()
        );

        let err = validate(1, &b64, &nonce, "not-a-nonce".to_owned(), false).unwrap_err();
        assert_eq!(err.reason, GuestRejection::ProofNonceNotBoundedHex.as_str());

        let err = validate(1, &b64, "short", "0xab".to_owned(), false).unwrap_err();
        assert_eq!(err.reason, BAD_NONCE);

        let err = validate(1, "!!not base64!!", &nonce, "0xab".to_owned(), false).unwrap_err();
        assert_eq!(err.reason, BAD_BASE64);

        let ok = validate(1, &b64, &nonce, "0xab".to_owned(), true).expect("valid");
        assert_eq!(ok.canonical_request_bytes, b"{}");
        assert!(ok.emit_scores);
    }

    /// A secret planted in every caller-controlled field reaches no reason
    /// string. The reasons are `&'static str`, so this cannot fail without
    /// someone changing the type — which is the point of the type.
    #[test]
    fn no_rejection_carries_a_byte_of_the_request() {
        const SECRET: &str = "PLANTED_SECRET_XYZZY";
        let cases = [
            validate(2, SECRET, SECRET, SECRET.to_owned(), false),
            validate(1, SECRET, SECRET, SECRET.to_owned(), false),
            validate(1, SECRET, SECRET, "0xab".to_owned(), false),
            validate(1, SECRET, &"ab".repeat(32), "0xab".to_owned(), false),
        ];
        for case in cases {
            let err = case.expect_err("must be refused");
            assert!(!err.reason.contains(SECRET), "leaked: {}", err.reason);
        }
    }
}

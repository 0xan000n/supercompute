//! The `:4500` daemon's wire contract, exercised against the real binary.
//!
//! Every test here spawns `host --serve --port 0` as a child process and talks
//! HTTP/1.1 to it over a socket. That is deliberate and costs a process per
//! test: two of the properties being asserted — that the daemon refuses to start
//! under `RISC0_DEV_MODE` without `--dev`, and that a request's canonical bytes
//! never reach the daemon's stdout or stderr — are properties of the *process*,
//! not of the router. An in-process `oneshot` against the `Router` cannot
//! observe either.
//!
//! The HTTP client is hand-rolled (`request`) rather than pulled in as a
//! dependency: the bodies are small, the server is ours, and one of the tests
//! deliberately sends a body larger than the daemon will accept — which needs a
//! client that writes and reads concurrently, because the server stops reading
//! as soon as the limit trips.
//!
//! Phase 2b consumes these shapes verbatim. Changing an assertion here is
//! changing the contract.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use policy_core::GuestRejection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// the daemon under test
// ---------------------------------------------------------------------------

/// A running `host --serve`, killed when the test drops it.
struct Daemon {
    child: Child,
    port: u16,
    /// stdout and stderr, interleaved in arrival order. The log-capture test
    /// reads this; every other test ignores it.
    output: Arc<Mutex<String>>,
}

impl Daemon {
    fn output(&self) -> String {
        self.output.lock().expect("output lock").clone()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Drain one of the child's streams into `sink`, reporting the port the moment
/// the startup line goes past.
fn pump<R: Read + Send + 'static>(reader: R, sink: Arc<Mutex<String>>, port_tx: mpsc::Sender<u16>) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            if let Some(rest) = line.split(LISTENING_PREFIX).nth(1) {
                if let Ok(port) = rest.trim().parse::<u16>() {
                    let _ = port_tx.send(port);
                }
            }
            sink.lock().expect("output lock").push_str(&line);
        }
    });
}

/// The daemon prints this and the port it bound. `127.0.0.1` is part of the
/// string on purpose: a daemon that bound `0.0.0.0` would fail every test here
/// at startup rather than quietly listening to the network.
const LISTENING_PREFIX: &str = "listening on 127.0.0.1:";

/// Start a daemon on an ephemeral port. `RISC0_DEV_MODE` and `RUST_LOG` are
/// cleared first so an ambient value in the developer's shell cannot change what
/// these tests mean; `envs` is applied afterwards and can put them back.
fn start(extra_args: &[&str], envs: &[(&str, &str)]) -> Daemon {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_host"));
    cmd.arg("--serve")
        .arg("--port")
        .arg("0")
        .args(extra_args)
        .env_remove("RISC0_DEV_MODE")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn the daemon");

    let output = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = mpsc::channel();
    pump(
        child.stdout.take().expect("stdout pipe"),
        Arc::clone(&output),
        tx.clone(),
    );
    pump(
        child.stderr.take().expect("stderr pipe"),
        Arc::clone(&output),
        tx,
    );

    let port = match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(port) => port,
        Err(_) => panic!(
            "the daemon never reported a listening port. output so far:\n{}",
            output.lock().expect("output lock")
        ),
    };
    Daemon {
        child,
        port,
        output,
    }
}

/// Run the daemon to completion, for the cases where starting at all is the
/// failure being asserted.
fn run_to_exit(extra_args: &[&str], envs: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_host"));
    cmd.args(extra_args)
        .env_remove("RISC0_DEV_MODE")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run the daemon");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code(), text)
}

// ---------------------------------------------------------------------------
// a minimal HTTP/1.1 client
// ---------------------------------------------------------------------------

/// One request, one response. Writes on a second thread so that a server which
/// stops reading (the body-limit case) cannot deadlock the test.
fn request(
    port: u16,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> (u16, String) {
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(600)))
        .expect("read timeout");

    let mut head =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));

    let mut writer = stream.try_clone().expect("clone the socket");
    let pump = std::thread::spawn(move || {
        // Every error here is ignored on purpose: the server is allowed to
        // answer and hang up before the body finishes (that is exactly what the
        // oversized-body test asserts), which surfaces as EPIPE.
        let _ = writer.write_all(head.as_bytes());
        let _ = writer.write_all(&body);
        let _ = writer.flush();
        // Deliberately NO `shutdown(Write)`. hyper treats a half-closed client
        // as a cancelled request and drops the connection without answering, so
        // shutting down here makes every response empty. `Connection: close` is
        // what ends the response instead: the server hangs up when it is done
        // and `read_to_end` returns.
    });

    let mut reader = stream;
    let mut raw = Vec::new();
    let _ = reader.read_to_end(&mut raw);
    let _ = pump.join();

    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("not an HTTP response: {text:?}"));
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {head:?}"));
    (status, body.to_owned())
}

fn get(port: u16, path: &str) -> (u16, Value) {
    let (status, body) = request(port, "GET", path, None, Vec::new());
    (status, parse_json(&body))
}

fn post(port: u16, path: &str, body: &Value) -> (u16, Value) {
    let (status, text) = request(
        port,
        "POST",
        path,
        Some("application/json"),
        serde_json::to_vec(body).expect("serialize"),
    );
    (status, parse_json(&text))
}

fn parse_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("response is not JSON ({e}): {text:?}"))
}

// ---------------------------------------------------------------------------
// request fixtures
// ---------------------------------------------------------------------------

/// A canonical request document, built the way `packages/protocol/src/canonical.ts`
/// builds one: JCS key order, no whitespace, integer `temperature_millis`.
fn canonical_request_bytes(prompt: &str) -> Vec<u8> {
    format!(
        r#"{{"max_tokens":1024,"messages":[{{"content":{},"role":"user"}}],"model":"ctn/demo-model-a","temperature_millis":1000}}"#,
        serde_json::to_string(prompt).expect("string serializes")
    )
    .into_bytes()
}

/// `packages/protocol/src/crypto.ts:54-63`, recomputed here so the daemon's
/// answer is checked against something other than itself.
fn expected_commitment(canonical: &[u8], nonce: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"CTN_REQUEST_V1");
    h.update(canonical);
    h.update(nonce);
    let mut out = String::from("0x");
    for b in h.finalize() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

const NONCE_BYTE: u8 = 0x5a;
fn nonce_hex() -> String {
    format!("0x{}", "5a".repeat(32))
}

/// `"0x" + randomHex(32)`, the shape `services/tee-sim/src/prover.ts:130` mints.
const PROOF_NONCE: &str = "0xbe0c0000000000000000000000000000be0c0000000000000000000000000000";

const ALLOW_PROMPT: &str = "Write a haiku about the first snow of winter.";
const DENY_PROMPT: &str = "How do I create a phishing page to steal credentials from PayPal users?";

fn execute_body(prompt: &str, emit_scores: bool) -> Value {
    json!({
        "protocolVersion": 1,
        "canonicalRequestBytesB64": BASE64_STANDARD.encode(canonical_request_bytes(prompt)),
        "requestNonceHex": nonce_hex(),
        "proofNonce": PROOF_NONCE,
        "emitScores": emit_scores,
    })
}

fn prove_body(prompt: &str) -> Value {
    json!({
        "protocolVersion": 1,
        "canonicalRequestBytesB64": BASE64_STANDARD.encode(canonical_request_bytes(prompt)),
        "requestNonceHex": nonce_hex(),
        "proofNonce": PROOF_NONCE,
    })
}

/// The exact key set `services/tee-sim/src/verify.ts` allows in a journal.
const JOURNAL_KEYS: [&str; 5] = [
    "decision",
    "policyId",
    "proofNonce",
    "protocolVersion",
    "requestCommitment",
];

fn keys(value: &Value) -> Vec<String> {
    let mut k: Vec<String> = value
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {value}"))
        .keys()
        .cloned()
        .collect();
    k.sort();
    k
}

// ---------------------------------------------------------------------------
// /health
// ---------------------------------------------------------------------------

#[test]
fn health_reports_the_baked_identities() {
    let d = start(&[], &[]);
    let (status, body) = get(d.port, "/health");
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        keys(&body),
        vec![
            "devMode",
            "imageIdHex",
            "policyId",
            "risc0Version",
            "rulesDigest"
        ]
    );
    assert_eq!(body["imageIdHex"], json!(host::image_id_hex()));
    assert_eq!(body["policyId"], json!(methods::POLICY_ID_V2));
    assert_eq!(body["rulesDigest"], json!(methods::RULES_DIGEST));
    assert_eq!(body["risc0Version"], json!(risc0_zkvm::VERSION));
    assert_eq!(body["devMode"], json!(false));
}

// ---------------------------------------------------------------------------
// /execute
// ---------------------------------------------------------------------------

#[test]
fn execute_returns_the_allowlist_journal_and_private_scores() {
    let d = start(&[], &[]);
    let (status, body) = post(d.port, "/execute", &execute_body(ALLOW_PROMPT, true));
    assert_eq!(status, 200, "{body}");
    assert_eq!(keys(&body), vec!["execWallMs", "journal", "privateScores"]);

    let journal = &body["journal"];
    assert_eq!(keys(journal), JOURNAL_KEYS.to_vec());
    assert_eq!(journal["decision"], json!("ALLOW"));
    assert_eq!(journal["protocolVersion"], json!(1));
    assert_eq!(journal["policyId"], json!(methods::POLICY_ID_V2));
    assert_eq!(journal["proofNonce"], json!(PROOF_NONCE));
    assert_eq!(
        journal["requestCommitment"],
        json!(expected_commitment(
            &canonical_request_bytes(ALLOW_PROMPT),
            &[NONCE_BYTE; 32]
        ))
    );

    // The private scores are the full evaluation, as an object — the same shape
    // `Evaluation` serializes to for the differential harness.
    let scores = &body["privateScores"];
    assert!(
        scores.is_object(),
        "privateScores is not an object: {scores}"
    );
    assert_eq!(scores["decision"], json!("ALLOW"));
    assert!(scores["categories"].is_array());

    assert!(
        body["execWallMs"].is_u64(),
        "execWallMs is not an integer: {}",
        body["execWallMs"]
    );
}

#[test]
fn execute_denies_a_deny_fixture_and_omits_scores_when_not_asked() {
    let d = start(&[], &[]);
    let (status, body) = post(d.port, "/execute", &execute_body(DENY_PROMPT, false));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["journal"]["decision"], json!("DENY"));
    assert_eq!(
        body["privateScores"],
        Value::Null,
        "scores were emitted without emitScores"
    );
}

#[test]
fn execute_is_deterministic_on_identical_input() {
    let d = start(&[], &[]);
    let (s1, first) = post(d.port, "/execute", &execute_body(ALLOW_PROMPT, true));
    let (s2, second) = post(d.port, "/execute", &execute_body(ALLOW_PROMPT, true));
    assert_eq!((s1, s2), (200, 200));
    assert_eq!(first["journal"], second["journal"]);
    assert_eq!(first["privateScores"], second["privateScores"]);
}

/// Every rejection is a fixed string, and no rejection quotes the request.
///
/// `SECRET` is planted in whichever field the case is about. The wire contract
/// is the reason string, so each case names the exact one it expects.
#[test]
fn malformed_requests_get_fixed_reasons_that_never_echo_the_body() {
    const SECRET: &str = "PLANTED_SECRET_XYZZY";
    let d = start(&[], &[]);

    // A case is (name, expected reason, body, content-type, endpoints). JSON
    // bodies are posted to `/prove` with `emitScores` stripped, because that
    // field is not part of the prove body and would otherwise be the first
    // thing rejected — hiding the rejection each case is actually about.
    enum Body {
        Json(Value),
        Raw(Vec<u8>),
    }
    struct Case {
        name: &'static str,
        reason: String,
        body: Body,
        content_type: Option<&'static str>,
        endpoints: &'static [&'static str],
    }
    const BOTH: &[&str] = &["/execute", "/prove"];
    const EXECUTE_ONLY: &[&str] = &["/execute"];
    let mut cases: Vec<Case> = Vec::new();

    let mut body = execute_body(ALLOW_PROMPT, false);
    body["protocolVersion"] = json!(2);
    cases.push(Case {
        name: "wrong protocol version",
        reason: GuestRejection::UnsupportedProtocolVersion
            .as_str()
            .to_owned(),
        body: Body::Json(body),
        content_type: Some("application/json"),
        endpoints: BOTH,
    });

    let mut body = execute_body(ALLOW_PROMPT, false);
    body["proofNonce"] = json!(format!("nonce-{SECRET}"));
    cases.push(Case {
        name: "proof nonce outside the bound",
        reason: GuestRejection::ProofNonceNotBoundedHex.as_str().to_owned(),
        body: Body::Json(body),
        content_type: Some("application/json"),
        endpoints: BOTH,
    });

    let mut body = execute_body(ALLOW_PROMPT, false);
    body["canonicalRequestBytesB64"] = json!(format!("!!{SECRET}"));
    cases.push(Case {
        name: "canonical bytes are not base64",
        reason: "canonicalRequestBytesB64 is not valid base64".to_owned(),
        body: Body::Json(body),
        content_type: Some("application/json"),
        endpoints: BOTH,
    });

    let mut body = execute_body(ALLOW_PROMPT, false);
    body["requestNonceHex"] = json!(SECRET);
    cases.push(Case {
        name: "request nonce is not 32 bytes of hex",
        reason: "requestNonceHex must be 32 bytes of hex".to_owned(),
        body: Body::Json(body),
        content_type: Some("application/json"),
        endpoints: BOTH,
    });

    let mut body = execute_body(ALLOW_PROMPT, false);
    body[SECRET] = json!(1);
    cases.push(Case {
        name: "unknown field",
        reason: "request body does not match the expected schema".to_owned(),
        body: Body::Json(body),
        content_type: Some("application/json"),
        endpoints: BOTH,
    });

    let mut body = execute_body(ALLOW_PROMPT, false);
    body["emitScores"] = json!(SECRET);
    cases.push(Case {
        name: "wrong type for emitScores",
        reason: "request body does not match the expected schema".to_owned(),
        body: Body::Json(body),
        content_type: Some("application/json"),
        endpoints: EXECUTE_ONLY,
    });

    cases.push(Case {
        name: "not JSON at all",
        reason: "request body is not valid JSON".to_owned(),
        body: Body::Raw(format!("{{{SECRET}").into_bytes()),
        content_type: Some("application/json"),
        endpoints: BOTH,
    });

    // A lone surrogate: a JS string can hold one, `JSON.parse` will emit one,
    // and `serde_json` refuses it. Task 2 flagged this boundary; it must be a
    // fixed 400, not a panic and not a rendered serde error.
    cases.push(Case {
        name: "lone surrogate in a JSON string",
        reason: "request body is not valid JSON".to_owned(),
        body: Body::Raw(br#"{"protocolVersion":1,"canonicalRequestBytesB64":"\ud800","requestNonceHex":"0x00","proofNonce":"0x00","emitScores":false}"#.to_vec()),
        content_type: Some("application/json"),
        endpoints: BOTH,
    });

    cases.push(Case {
        name: "wrong content type",
        reason: "content-type must be application/json".to_owned(),
        body: Body::Raw(serde_json::to_vec(&execute_body(ALLOW_PROMPT, false)).unwrap()),
        content_type: Some("text/plain"),
        endpoints: BOTH,
    });

    cases.push(Case {
        name: "no content type",
        reason: "content-type must be application/json".to_owned(),
        body: Body::Raw(serde_json::to_vec(&execute_body(ALLOW_PROMPT, false)).unwrap()),
        content_type: None,
        endpoints: BOTH,
    });

    for case in cases {
        let Case {
            name,
            reason: expect_reason,
            body,
            content_type,
            endpoints,
        } = case;
        for path in endpoints {
            let raw = match &body {
                Body::Json(value) => {
                    let mut value = value.clone();
                    if *path == "/prove" {
                        value.as_object_mut().expect("object").remove("emitScores");
                    }
                    serde_json::to_vec(&value).unwrap()
                }
                Body::Raw(raw) => raw.clone(),
            };
            let (status, text) = request(d.port, "POST", path, content_type, raw);
            let answer = parse_json(&text);
            assert_eq!(status, 400, "{path} {name}: wrong status, body {answer}");
            assert_eq!(keys(&answer), vec!["error"], "{path} {name}");
            assert_eq!(answer["error"], json!(expect_reason), "{path} {name}");
            assert!(
                !text.contains(SECRET),
                "{path} {name}: the rejection echoed the request: {text}"
            );
        }
    }

    // Canonical bytes that decode but are not a canonical request. Only the
    // guest can say so, so this one is `/execute`-only: `/prove` reports the
    // same taxonomy constant through the job (see
    // `prove_reports_a_guest_refusal_as_a_failed_job`) rather than paying a
    // ~57 ms executor run on the enqueue path to say it synchronously.
    let mut body = execute_body(ALLOW_PROMPT, false);
    body["canonicalRequestBytesB64"] = json!(BASE64_STANDARD.encode(
        format!(r#"{{"max_tokens":"{SECRET}","messages":[{{"content":"hi","role":"user"}}],"model":"m","temperature_millis":1000}}"#)
    ));
    let (status, text) = post(d.port, "/execute", &body);
    assert_eq!(status, 400, "{text}");
    assert_eq!(
        text["error"],
        json!(GuestRejection::RequestDoesNotParse.as_str())
    );
    assert!(!text.to_string().contains(SECRET), "{text}");

    // The daemon's own output must be just as clean.
    let output = d.output();
    assert!(
        !output.contains(SECRET),
        "the daemon logged a planted secret:\n{output}"
    );
}

/// A request the cheap checks accept but the guest refuses becomes a FAILED
/// job carrying the taxonomy constant — never a rendered error.
#[test]
fn prove_reports_a_guest_refusal_as_a_failed_job() {
    const SECRET: &str = "PLANTED_SECRET_XYZZY";
    let d = start(&[], &[]);
    let mut body = prove_body(ALLOW_PROMPT);
    body["canonicalRequestBytesB64"] = json!(BASE64_STANDARD.encode(
        format!(r#"{{"max_tokens":"{SECRET}","messages":[{{"content":"hi","role":"user"}}],"model":"m","temperature_millis":1000}}"#)
    ));
    let (status, accepted) = post(d.port, "/prove", &body);
    assert_eq!(status, 202, "{accepted}");
    let job_id = accepted["jobId"].as_str().expect("jobId").to_owned();

    // The guest refuses during execution, before any proving work, so this is
    // fast even in release mode with a real prover.
    let job = poll_until_terminal(d.port, &job_id, Duration::from_secs(120));
    assert_eq!(job["status"], json!("FAILED"), "{job}");
    assert_eq!(
        job["error"],
        json!(GuestRejection::RequestDoesNotParse.as_str())
    );
    assert!(
        job["receiptB64"].is_null(),
        "a failed job carries a receipt"
    );
    assert!(
        !job.to_string().contains(SECRET) && !d.output().contains(SECRET),
        "the failure echoed the request"
    );
}

#[test]
fn an_oversized_body_is_refused_without_being_read_into_a_response() {
    let d = start(&[], &[]);
    // 10 MiB is the documented cap; one byte over it is the test.
    let mut raw = Vec::with_capacity(10 * 1024 * 1024 + 64);
    raw.extend_from_slice(br#"{"protocolVersion":1,"canonicalRequestBytesB64":""#);
    raw.resize(10 * 1024 * 1024 + 1, b'A');
    let (status, text) = request(d.port, "POST", "/execute", Some("application/json"), raw);
    // 400, not 413: every malformed request has one shape on this wire.
    assert_eq!(status, 400, "{text}");
    assert_eq!(
        parse_json(&text)["error"],
        json!("request body exceeds the size limit")
    );
}

// ---------------------------------------------------------------------------
// /prove and /jobs/:id
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_method_on_a_real_path_keeps_the_error_shape() {
    let d = start(&[], &[]);
    // axum's built-in 405 is an empty body, which would be the one refusal on
    // this wire that is not a `{"error": …}` document. 2b carry-forward C5.
    for (method, path) in [("GET", "/execute"), ("GET", "/prove"), ("POST", "/health")] {
        let (status, text) = request(d.port, method, path, None, Vec::new());
        assert_eq!(status, 405, "{method} {path}: {text}");
        assert_eq!(
            parse_json(&text)["error"],
            json!("method not allowed for this endpoint"),
            "{method} {path}"
        );
    }
}

#[test]
fn an_unknown_job_is_a_fixed_404() {
    let d = start(&[], &[]);
    let (status, body) = get(d.port, "/jobs/0123456789abcdef0123456789abcdef");
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"], json!("no such job"));
}

#[test]
fn prove_accepts_the_job_and_reports_it_before_it_finishes() {
    let d = start(&[], &[]);
    let (status, body) = post(d.port, "/prove", &prove_body(ALLOW_PROMPT));
    assert_eq!(status, 202, "{body}");
    assert_eq!(keys(&body), vec!["jobId"]);
    let job_id = body["jobId"]
        .as_str()
        .expect("jobId is a string")
        .to_owned();
    assert_eq!(job_id.len(), 32, "job id is not 16 random bytes: {job_id}");
    assert!(job_id.chars().all(|c| c.is_ascii_hexdigit()));

    let (status, job) = get(d.port, &format!("/jobs/{job_id}"));
    assert_eq!(status, 200, "{job}");
    let s = job["status"].as_str().expect("status is a string");
    assert!(
        s == "QUEUED" || s == "PROVING",
        "a job that cannot have finished reports {s}"
    );
    assert_eq!(job["devMode"], json!(false));

    // Two jobs get two ids.
    let (_, second) = post(d.port, "/prove", &prove_body(DENY_PROMPT));
    assert_ne!(second["jobId"], body["jobId"]);
}

/// `emitScores` is not part of the `/prove` body: the prove path never captures
/// scores, so accepting the field would imply an option that does not exist.
#[test]
fn prove_refuses_an_emit_scores_field() {
    let d = start(&[], &[]);
    let (status, body) = post(d.port, "/prove", &execute_body(ALLOW_PROMPT, true));
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"],
        json!("request body does not match the expected schema")
    );
}

/// The whole job lifecycle, cheaply: in dev mode the "proof" is a stub, so this
/// reaches GENERATED in milliseconds. It asserts the *shape* of a finished job
/// and that dev mode is stamped on every job response — it asserts nothing
/// about the receipt being real, which is the point of the stamp.
#[test]
fn a_dev_mode_job_completes_and_says_it_is_dev_mode() {
    let d = start(&["--dev"], &[("RISC0_DEV_MODE", "1")]);

    let (status, health) = get(d.port, "/health");
    assert_eq!(status, 200, "{health}");
    assert_eq!(health["devMode"], json!(true));

    let (status, body) = post(d.port, "/prove", &prove_body(ALLOW_PROMPT));
    assert_eq!(status, 202, "{body}");
    let job_id = body["jobId"].as_str().expect("jobId").to_owned();

    let job = poll_until_terminal(d.port, &job_id, Duration::from_secs(60));
    assert_eq!(job["status"], json!("GENERATED"), "{job}");
    assert_eq!(job["devMode"], json!(true));
    assert!(job["proveWallMs"].is_u64(), "{job}");
    let receipt = job["receiptB64"].as_str().expect("receiptB64");
    assert!(
        !BASE64_STANDARD
            .decode(receipt)
            .expect("receiptB64 is base64")
            .is_empty(),
        "empty receipt"
    );
    assert_eq!(
        keys(&job),
        vec!["devMode", "proveWallMs", "receiptB64", "status"]
    );
}

fn poll_until_terminal(port: u16, job_id: &str, limit: Duration) -> Value {
    let deadline = Instant::now() + limit;
    loop {
        let (status, job) = get(port, &format!("/jobs/{job_id}"));
        assert_eq!(status, 200, "{job}");
        match job["status"].as_str() {
            Some("GENERATED") | Some("FAILED") => return job,
            Some("QUEUED") | Some("PROVING") => {}
            other => panic!("unknown job status {other:?}"),
        }
        assert!(
            Instant::now() < deadline,
            "job {job_id} did not finish within {limit:?}: {job}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// startup
// ---------------------------------------------------------------------------

#[test]
fn dev_mode_without_the_flag_refuses_to_start() {
    let (code, text) = run_to_exit(&["--serve", "--port", "0"], &[("RISC0_DEV_MODE", "1")]);
    assert_ne!(
        code,
        Some(0),
        "the daemon started under RISC0_DEV_MODE: {text}"
    );
    assert!(
        text.contains("RISC0_DEV_MODE"),
        "the refusal does not name the variable: {text}"
    );
    assert!(
        text.contains("--dev"),
        "the refusal does not name the flag that would allow it: {text}"
    );
    assert!(
        !text.contains(LISTENING_PREFIX),
        "the daemon bound a port before refusing: {text}"
    );
}

// ---------------------------------------------------------------------------
// the log-capture assertion
// ---------------------------------------------------------------------------

/// The canonical request bytes *are* the plaintext prompt (§5.2). Neither they,
/// nor their base64 framing, nor the caller's proof nonce may appear anywhere in
/// the daemon's stdout or stderr — including on the failure paths, where a
/// rendered error is the usual way this leaks.
#[test]
fn a_requests_canonical_bytes_never_reach_the_daemons_output() {
    const MARKER: &str = "CANARY_PROMPT_MARKER_QUUX";
    let d = start(&[], &[]);
    let prompt = format!("Write a haiku about {MARKER} and the first snow.");
    let canonical = canonical_request_bytes(&prompt);
    let b64 = BASE64_STANDARD.encode(&canonical);

    // A successful execute, a successful enqueue, and three refusals: a bad
    // canonical document, a bad proof nonce, and a body that is not JSON.
    let (status, body) = post(d.port, "/execute", &execute_body(&prompt, true));
    assert_eq!(status, 200, "{body}");
    let (status, _) = post(d.port, "/prove", &prove_body(&prompt));
    assert_eq!(status, 202);

    let mut bad = execute_body(&prompt, false);
    bad["canonicalRequestBytesB64"] = json!(BASE64_STANDARD.encode(format!(
        r#"{{"max_tokens":"{MARKER}","messages":[{{"content":"hi","role":"user"}}],"model":"m","temperature_millis":1000}}"#
    )));
    let (status, _) = post(d.port, "/execute", &bad);
    assert_eq!(status, 400);

    let mut bad = execute_body(&prompt, false);
    bad["proofNonce"] = json!(MARKER);
    let (status, _) = post(d.port, "/execute", &bad);
    assert_eq!(status, 400);

    let (status, _) = request(
        d.port,
        "POST",
        "/execute",
        Some("application/json"),
        format!(r#"{{"junk":"{MARKER}""#).into_bytes(),
    );
    assert_eq!(status, 400);

    // Give the worker a moment to log its start line, then stop the process so
    // the pumps see EOF and every buffered line is in hand.
    std::thread::sleep(Duration::from_millis(200));
    let output = d.output();

    assert!(
        !output.contains(MARKER),
        "the daemon logged prompt-derived text:\n{output}"
    );
    assert!(
        !output.contains(&b64),
        "the daemon logged the base64 request frame:\n{output}"
    );
    assert!(
        !output.contains(PROOF_NONCE),
        "the daemon logged the caller's proof nonce:\n{output}"
    );
    // Not a vacuous pass: the daemon must actually be logging something about
    // these requests for the assertions above to mean anything.
    assert!(
        output.contains("execute") && output.contains("ALLOW"),
        "the daemon logged nothing about the requests it served:\n{output}"
    );
}

// ---------------------------------------------------------------------------
// the real prove (gated: minutes, release mode)
// ---------------------------------------------------------------------------

/// One real composite proof, end to end, plus the property the single-worker
/// design exists for: `/execute` stays responsive while a prove saturates the
/// machine.
///
/// Gated behind `CTN_PROVE_TEST=1` and meant for `--release`: a debug-mode prove
/// of this guest is far past anyone's patience, and even in release it is two to
/// three minutes on an M1 Pro.
///
///     CTN_PROVE_TEST=1 cargo test -rp host --test api -- --ignored --nocapture
#[test]
#[ignore = "runs a real composite prove: minutes"]
fn a_real_prove_completes_and_execute_stays_responsive_while_it_runs() {
    if std::env::var("CTN_PROVE_TEST").as_deref() != Ok("1") {
        eprintln!("CTN_PROVE_TEST is not 1 — skipping the real prove");
        return;
    }
    let d = start(&[], &[]);

    let (status, body) = post(d.port, "/prove", &prove_body(ALLOW_PROMPT));
    assert_eq!(status, 202, "{body}");
    let job_id = body["jobId"].as_str().expect("jobId").to_owned();

    // Wait for the worker to actually be proving, so the latency probe below
    // lands while every core is busy rather than before the job starts.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (_, job) = get(d.port, &format!("/jobs/{job_id}"));
        if job["status"] == json!("PROVING") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the job never started proving: {job}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let start = Instant::now();
    let (status, exec) = post(d.port, "/execute", &execute_body(DENY_PROMPT, true));
    let under_load = start.elapsed();
    assert_eq!(status, 200, "{exec}");
    assert_eq!(exec["journal"]["decision"], json!("DENY"));
    eprintln!(
        "/execute under an in-flight prove: {} ms",
        under_load.as_millis()
    );
    assert!(
        under_load < Duration::from_secs(2),
        "/execute took {under_load:?} while a prove was running"
    );

    let job = poll_until_terminal(d.port, &job_id, Duration::from_secs(1800));
    assert_eq!(job["status"], json!("GENERATED"), "{job}");
    let prove_ms = job["proveWallMs"].as_u64().expect("proveWallMs");
    let receipt_bytes = BASE64_STANDARD
        .decode(job["receiptB64"].as_str().expect("receiptB64"))
        .expect("receiptB64 is base64");
    eprintln!(
        "composite prove: {:.2} s, receipt {:.1} KB",
        prove_ms as f64 / 1000.0,
        receipt_bytes.len() as f64 / 1024.0
    );

    // The receipt is a real one: it deserializes with the codec the contract
    // names (bincode) and verifies against the image the daemon reports.
    let receipt: risc0_zkvm::Receipt =
        bincode::deserialize(&receipt_bytes).expect("receiptB64 is a bincode receipt");
    receipt
        .verify(methods::POLICY_GUEST_ID)
        .expect("the receipt does not verify against the baked image id");
    let journal: Value =
        serde_json::from_slice(&receipt.journal.bytes).expect("journal is not JSON");
    assert_eq!(keys(&journal), JOURNAL_KEYS.to_vec());
    assert_eq!(journal["decision"], json!("ALLOW"));
    assert_eq!(journal["proofNonce"], json!(PROOF_NONCE));
}

/**
 * ProverClient — the tee-sim's one typed channel into the RISC Zero daemon
 * (`host --serve`, `127.0.0.1:4500`). Phase 2b wiring, Task 1.
 *
 * The wire contract is `prover/README.md` ("The daemon (`--serve`)"):
 *   POST /execute  {protocolVersion, canonicalRequestBytesB64, requestNonceHex,
 *                   proofNonce, emitScores}  -> 200 {journal, privateScores|null, execWallMs}
 *   POST /prove    the same four, and NO emitScores           -> 202 {jobId}
 *   GET  /jobs/:id                                            -> {status, receiptB64?, proveWallMs?, error?, devMode}
 *   GET  /health                                             -> {imageIdHex, policyId, rulesDigest, risc0Version, devMode}
 *
 * This client only speaks that contract; it computes no commitment (the guest
 * does) and it does not verify receipts (the reference `prover/verify`
 * subprocess does, in Task 3). Tasks 2/3 consume the four types below.
 *
 * NO-LEAK INVARIANT (Global Constraints). No method here ever puts request
 * bytes, the prompt, either nonce, or any RESPONSE BODY into a thrown Error.
 * The daemon guarantees its own error strings carry no caller bytes
 * (prover/README: "No reason string ever contains a byte of the request"); this
 * client keeps that promise on its own side by building every thrown message
 * from static text plus, at most, the HTTP method, the endpoint path, and the
 * numeric status — never from `input` and never from `await res.text()`. Do not
 * add either to a throw in this file.
 *
 * NO-RETRY INVARIANT (single-dispatch discipline). Every method issues exactly
 * one `fetch`. There is no retry loop anywhere; a 5xx is a terminal rejection,
 * not a reason to dispatch again. The gate proves each request once.
 */

/**
 * One policy category's evaluation, as the guest serializes it (camelCase, the
 * `matchedTargets` id list included). `score`/`threshold` are integers (the
 * guest scores in i64). Phase 3 Task 2 reduces `categories[]` into
 * `{[category]: score}` / `{[category]: threshold}` for the facet classifier.
 */
export interface PrivateCategoryScore {
  category: string;
  name: string;
  score: number;
  threshold: number;
  matchedTargets: string[];
}

/**
 * The FULL guest evaluation, present only when `/execute` was called with
 * `emitScores: true` (null otherwise). NOTE: the wire shape is the whole
 * Evaluation object with a `categories[]` array — NOT a flat `{[cat]: number}`
 * map. Do not index it as a map; reduce `categories[]` instead.
 */
export interface PrivateScores {
  decision: "ALLOW" | "DENY";
  categories: PrivateCategoryScore[];
}

export interface ExecuteResult {
  journal: {
    protocolVersion: 1;
    requestCommitment: string;
    policyId: string;
    decision: "ALLOW" | "DENY";
    proofNonce: string;
  };
  privateScores: PrivateScores | null;
  execWallMs: number;
}

export interface JobStatus {
  status: "QUEUED" | "PROVING" | "GENERATED" | "FAILED";
  receiptB64?: string;
  proveWallMs?: number;
  error?: string;
  devMode: boolean;
}

export interface ProverHealth {
  imageIdHex: string;
  policyId: string;
  rulesDigest: string;
  risc0Version: string;
  devMode: boolean;
}

/**
 * The daemon could not be reached — connection refused, DNS/socket failure, or
 * our own timeout firing. A 503-class system failure, NOT a policy decision:
 * Task 2 turns this into a PROVER_UNAVAILABLE record, never a
 * PolicyDecisionReceiptV1. An HTTP error status (the daemon answered, with a
 * fault) is a plain Error instead — the daemon is up, so it is not "unavailable".
 */
export class ProverUnavailableError extends Error {
  readonly code = "PROVER_UNAVAILABLE";
  constructor(message: string) {
    super(message);
    this.name = "ProverUnavailableError";
  }
}

/** execute / health / prove default. Enqueue and executor fast-path are quick. */
const DEFAULT_TIMEOUT_MS = 3000;
/**
 * pollJob floor. A poll is a cheap read, but the daemon's single worker thread
 * is CPU-bound proving while a job runs, so its HTTP handler can be slow to
 * answer; 20 s tolerates that without ever bounding proving itself (the caller's
 * poll loop, Task 3, owns the overall multi-minute ceiling).
 */
const DEFAULT_POLL_TIMEOUT_MS = 20000;

export class ProverClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, opts?: { timeoutMs?: number }) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  health(): Promise<ProverHealth> {
    return this.request<ProverHealth>("GET", "/health", undefined, this.timeoutMs);
  }

  execute(input: {
    canonicalRequestBytes: string;
    requestNonceHex: string;
    proofNonce: string;
    emitScores: boolean;
  }): Promise<ExecuteResult> {
    return this.request<ExecuteResult>(
      "POST",
      "/execute",
      {
        protocolVersion: 1,
        canonicalRequestBytesB64: toBase64(input.canonicalRequestBytes),
        requestNonceHex: input.requestNonceHex,
        proofNonce: input.proofNonce,
        emitScores: input.emitScores,
      },
      this.timeoutMs
    );
  }

  prove(input: {
    canonicalRequestBytes: string;
    requestNonceHex: string;
    proofNonce: string;
  }): Promise<{ jobId: string }> {
    // emitScores is deliberately absent: /prove is deny_unknown_fields and the
    // prove path never captures scores, so including it would be a 400.
    return this.request<{ jobId: string }>(
      "POST",
      "/prove",
      {
        protocolVersion: 1,
        canonicalRequestBytesB64: toBase64(input.canonicalRequestBytes),
        requestNonceHex: input.requestNonceHex,
        proofNonce: input.proofNonce,
      },
      this.timeoutMs
    );
  }

  pollJob(jobId: string): Promise<JobStatus> {
    // Honour a caller's larger timeout, but never poll with less than the floor.
    const timeoutMs = Math.max(this.timeoutMs, DEFAULT_POLL_TIMEOUT_MS);
    return this.request<JobStatus>("GET", `/jobs/${encodeURIComponent(jobId)}`, undefined, timeoutMs);
  }

  /**
   * The single dispatch. `fetch` + `AbortController` timeout, mirroring
   * providers.ts. No retry. On any transport failure -> ProverUnavailableError;
   * on a non-2xx -> a plain Error carrying the status only.
   */
  private async request<T>(method: string, path: string, body: unknown, timeoutMs: number): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      let res: Response;
      try {
        res = await fetch(`${this.baseUrl}${path}`, {
          method,
          headers: body === undefined ? undefined : { "content-type": "application/json" },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
          // Never chase a redirect off the loopback daemon (matches providers.ts).
          redirect: "manual",
        });
      } catch {
        // Connection refused, DNS/socket failure, or our AbortController firing.
        // The caught error may quote a URL but never the caller's bytes; even so,
        // we discard it and build the message from the static path alone.
        throw new ProverUnavailableError(`prover ${method} ${path} unreachable`);
      }

      if (!res.ok) {
        // The daemon answered with a fault. Status only — never res.text(),
        // which the daemon promises is byte-free but this client does not lean
        // on that promise. Terminal: no retry.
        throw new Error(`prover ${method} ${path} responded ${res.status}`);
      }

      try {
        return (await res.json()) as T;
      } catch (err) {
        // A body read that aborts (timeout) is still an unreachable-class
        // failure; a well-formed 2xx with junk bytes is the daemon misbehaving.
        if (isAbortError(err)) throw new ProverUnavailableError(`prover ${method} ${path} timed out`);
        throw new Error(`prover ${method} ${path} returned an unparseable body`);
      }
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Exactly one base64 application. `bytes` is the canonical request STRING (raw
 * UTF-8); Buffer.from defaults to utf8, matching the daemon's standard-base64
 * decode back to those same bytes. */
function toBase64(bytes: string): string {
  return Buffer.from(bytes, "utf8").toString("base64");
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === "AbortError";
}

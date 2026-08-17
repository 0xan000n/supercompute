import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { ProverClient, ProverUnavailableError } from "./prover-client.js";

/**
 * In-process stub of the :4500 daemon, one per test, on an ephemeral port —
 * the same node:http pattern providers.test.ts / pricing.test.ts use. Every
 * request the client makes is recorded so a test can assert the exact wire body
 * and, critically, that exactly ONE request was dispatched (no retry).
 */
interface RecordedRequest {
  method: string;
  url: string;
  body: string;
  json: any;
}

interface Stub {
  port: number;
  requests: RecordedRequest[];
  server: Server;
}

type Responder = (req: RecordedRequest) => { status: number; body: unknown } | Promise<{ status: number; body: unknown }>;

const servers: Server[] = [];
after(() => {
  for (const s of servers) s.close();
});

function startStub(responder: Responder): Promise<Stub> {
  const requests: RecordedRequest[] = [];
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", async () => {
        let json: unknown;
        try {
          json = raw ? JSON.parse(raw) : undefined;
        } catch {
          json = undefined;
        }
        requests.push({ method: req.method ?? "", url: req.url ?? "", body: raw, json });
        const { status, body } = await responder(requests[requests.length - 1]!);
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      });
    });
    servers.push(server);
    server.listen(0, "127.0.0.1", () => resolve({ port: (server.address() as AddressInfo).port, requests, server }));
  });
}

/** Bind then release a port so nothing is listening on it — connection refused. */
async function deadPort(): Promise<number> {
  const stub = await startStub(() => ({ status: 200, body: {} }));
  await new Promise<void>((r) => stub.server.close(() => r()));
  return stub.port;
}

const NONCE = "ab".repeat(32); // 32 bytes as 64 hex digits
const CANONICAL =
  '{"max_tokens":1024,"messages":[{"content":"Write a haiku about the first snow of winter.","role":"user"}],"model":"ctn/demo-model-a","temperature_millis":1000}';

test("execute posts the camelCase B64 body and returns journal + execWallMs", async () => {
  const journal = {
    protocolVersion: 1,
    requestCommitment: "0x8873f02c",
    policyId: "0x1f74ba4f",
    decision: "ALLOW",
    proofNonce: "0xbe0c",
  };
  const stub = await startStub(() => ({ status: 200, body: { journal, privateScores: null, execWallMs: 57 } }));
  const client = new ProverClient(`http://127.0.0.1:${stub.port}`);

  const result = await client.execute({
    canonicalRequestBytes: CANONICAL,
    requestNonceHex: NONCE,
    proofNonce: "0xbe0c",
    emitScores: true,
  });

  assert.equal(stub.requests.length, 1);
  const req = stub.requests[0]!;
  assert.equal(req.method, "POST");
  assert.equal(req.url, "/execute");
  // Exact camelCase key set — no snake_case, no extras, nothing missing.
  assert.deepEqual(
    Object.keys(req.json).sort(),
    ["canonicalRequestBytesB64", "emitScores", "proofNonce", "protocolVersion", "requestNonceHex"]
  );
  assert.equal(req.json.protocolVersion, 1);
  assert.equal(req.json.requestNonceHex, NONCE);
  assert.equal(req.json.proofNonce, "0xbe0c");
  assert.equal(req.json.emitScores, true);
  // base64 applied EXACTLY ONCE: decoding once yields the original bytes. A
  // double-encode would decode to a base64 string, not the canonical request.
  assert.equal(Buffer.from(req.json.canonicalRequestBytesB64, "base64").toString("utf8"), CANONICAL);

  assert.deepEqual(result.journal, journal);
  assert.equal(result.privateScores, null);
  assert.equal(result.execWallMs, 57);
});

test("execute passes privateScores through when the daemon emits them", async () => {
  const scores = { violence: 0.1, self_harm: 0.0 };
  const stub = await startStub(() => ({
    status: 200,
    body: { journal: { protocolVersion: 1, requestCommitment: "0x1", policyId: "0x2", decision: "ALLOW", proofNonce: "0x3" }, privateScores: scores, execWallMs: 60 },
  }));
  const client = new ProverClient(`http://127.0.0.1:${stub.port}`);
  const result = await client.execute({ canonicalRequestBytes: CANONICAL, requestNonceHex: NONCE, proofNonce: "0x3", emitScores: true });
  assert.deepEqual(result.privateScores, scores);
});

test("prove posts the four fields WITHOUT emitScores and returns the jobId", async () => {
  const stub = await startStub(() => ({ status: 202, body: { jobId: "job-abc-123" } }));
  const client = new ProverClient(`http://127.0.0.1:${stub.port}`);

  const out = await client.prove({ canonicalRequestBytes: CANONICAL, requestNonceHex: NONCE, proofNonce: "0x01" });

  assert.equal(out.jobId, "job-abc-123");
  assert.equal(stub.requests.length, 1);
  const req = stub.requests[0]!;
  assert.equal(req.method, "POST");
  assert.equal(req.url, "/prove");
  assert.deepEqual(
    Object.keys(req.json).sort(),
    ["canonicalRequestBytesB64", "proofNonce", "protocolVersion", "requestNonceHex"]
  );
  assert.equal("emitScores" in req.json, false, "emitScores is forbidden on /prove");
  assert.equal(Buffer.from(req.json.canonicalRequestBytesB64, "base64").toString("utf8"), CANONICAL);
});

test("pollJob returns the daemon JobStatus verbatim, including devMode:false", async () => {
  const status = { status: "GENERATED", receiptB64: "cmVjZWlwdA==", proveWallMs: 124570, devMode: false };
  const stub = await startStub(() => ({ status: 200, body: status }));
  const client = new ProverClient(`http://127.0.0.1:${stub.port}`);

  const js = await client.pollJob("job-abc-123");

  assert.equal(stub.requests[0]!.method, "GET");
  assert.equal(stub.requests[0]!.url, "/jobs/job-abc-123");
  assert.deepEqual(js, status);
  assert.equal(js.devMode, false);
});

test("pollJob carries devMode:true through unchanged", async () => {
  const status = { status: "QUEUED", devMode: true };
  const stub = await startStub(() => ({ status: 200, body: status }));
  const client = new ProverClient(`http://127.0.0.1:${stub.port}`);
  const js = await client.pollJob("j");
  assert.equal(js.devMode, true);
  assert.equal(js.status, "QUEUED");
});

test("health returns ProverHealth from GET /health", async () => {
  const health = {
    imageIdHex: "ddb7dc544e1425640ad3af8e7b3b48afa21499a0b371ce4a59fdb4d8594d5331",
    policyId: "0x1f74ba4f2353012cd26f5d3279625c3b45e927eeb341f0ee4b72124b056a7db2",
    rulesDigest: "0x9f85ba59fd1429f10c373efc56d69aefa255a01a08df3ab6bd8e1ccecd3f93ea",
    risc0Version: "3.0.6",
    devMode: false,
  };
  const stub = await startStub(() => ({ status: 200, body: health }));
  const client = new ProverClient(`http://127.0.0.1:${stub.port}`);
  const h = await client.health();
  assert.equal(stub.requests[0]!.method, "GET");
  assert.equal(stub.requests[0]!.url, "/health");
  assert.deepEqual(h, health);
});

test("connection refused maps to ProverUnavailableError on EVERY method", async () => {
  const port = await deadPort();
  const client = new ProverClient(`http://127.0.0.1:${port}`, { timeoutMs: 1000 });

  await assert.rejects(() => client.health(), ProverUnavailableError);
  await assert.rejects(
    () => client.execute({ canonicalRequestBytes: CANONICAL, requestNonceHex: NONCE, proofNonce: "0x1", emitScores: false }),
    ProverUnavailableError
  );
  await assert.rejects(
    () => client.prove({ canonicalRequestBytes: CANONICAL, requestNonceHex: NONCE, proofNonce: "0x1" }),
    ProverUnavailableError
  );
  await assert.rejects(() => client.pollJob("j"), ProverUnavailableError);
});

test("a timeout maps to ProverUnavailableError", async () => {
  // The stub delays before writing headers; the client aborts first.
  const stub = await startStub(async () => {
    await new Promise((r) => setTimeout(r, 300));
    return { status: 200, body: {} };
  });
  const client = new ProverClient(`http://127.0.0.1:${stub.port}`, { timeoutMs: 40 });
  await assert.rejects(() => client.health(), ProverUnavailableError);
});

test("a 500 from /execute rejects with NO retry — exactly one request dispatched", async () => {
  const stub = await startStub(() => ({ status: 500, body: { error: "internal" } }));
  const client = new ProverClient(`http://127.0.0.1:${stub.port}`);

  const err = await client
    .execute({ canonicalRequestBytes: CANONICAL, requestNonceHex: NONCE, proofNonce: "0x1", emitScores: true })
    .then(() => null, (e) => e);

  assert.ok(err instanceof Error, "a 500 rejects");
  // A 500 is the daemon answering with a fault — it is UP, so this is NOT the
  // PROVER_UNAVAILABLE (unreachable) class. That distinction is load-bearing for
  // Task 2's system-failure record vs. a transport failure.
  assert.ok(!(err instanceof ProverUnavailableError), "a 500 is not PROVER_UNAVAILABLE");
  assert.equal(stub.requests.length, 1, "no retry loop: exactly one request reached the daemon");
});

test("thrown errors NEVER contain request bytes / prompt content", async () => {
  const secret = "SUPER_SECRET_PROMPT_CONTENT_marker_9f85ba59";
  const canonical = `{"max_tokens":1,"messages":[{"content":"${secret}","role":"user"}],"model":"m","temperature_millis":1000}`;

  // Transport-failure path (ProverUnavailableError).
  const port = await deadPort();
  const c1 = new ProverClient(`http://127.0.0.1:${port}`, { timeoutMs: 500 });
  const e1 = await c1
    .execute({ canonicalRequestBytes: canonical, requestNonceHex: NONCE, proofNonce: "0x1", emitScores: false })
    .then(() => null, (e) => e);
  assert.ok(e1 instanceof ProverUnavailableError);
  assert.ok(!String(e1.message).includes(secret), "message leaks no prompt bytes");
  assert.ok(!String(e1.stack ?? "").includes(secret), "stack leaks no prompt bytes");

  // HTTP-error path (the daemon echoes bytes in its body; the client must not
  // surface that body regardless).
  const stub = await startStub(() => ({ status: 400, body: { error: secret } }));
  const c2 = new ProverClient(`http://127.0.0.1:${stub.port}`);
  const e2 = await c2
    .execute({ canonicalRequestBytes: canonical, requestNonceHex: NONCE, proofNonce: "0x1", emitScores: false })
    .then(() => null, (e) => e);
  assert.ok(e2 instanceof Error);
  assert.ok(!String(e2.message).includes(secret), "the response body is never placed into the thrown message");
});

test("baseUrl trailing slash does not produce a double slash path", async () => {
  const stub = await startStub(() => ({ status: 200, body: { imageIdHex: "x", policyId: "y", rulesDigest: "z", risc0Version: "3.0.6", devMode: false } }));
  const client = new ProverClient(`http://127.0.0.1:${stub.port}/`);
  await client.health();
  assert.equal(stub.requests[0]!.url, "/health");
});

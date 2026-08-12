import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { AnthropicAdapter, OpenAICompatibleAdapter } from "./providers.js";

// The §69 gate blocks direct construction of authorized values; adapter unit
// tests only need the structural fields complete() reads.
function fakeAuthorized(model: string, messages: Array<{ role: string; content: string }>) {
  const request = { request: { model, messages, temperature_millis: 0, max_tokens: 64 } } as never;
  const credential = { secret: "sk-ant-test-000000000000" } as never;
  return { request, credential };
}

let server: Server | undefined;
let lastReq: { url?: string; headers: Record<string, string | string[] | undefined>; body: string };

function start(status: number, payload: unknown): Promise<number> {
  // Each test stands up a fresh stub; a still-listening previous one is an open
  // handle that keeps the runner's child process alive after the last assertion.
  server?.close();
  return new Promise((resolve) => {
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        lastReq = { url: req.url, headers: req.headers, body };
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(payload));
      });
    });
    server.listen(0, "127.0.0.1", () => resolve((server!.address() as { port: number }).port));
  });
}
after(() => server?.close());

test("anthropic adapter: wire shape, headers, parsing", async () => {
  const port = await start(200, {
    content: [{ type: "text", text: "hello from claude" }],
    usage: { input_tokens: 10, output_tokens: 5 },
  });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [
    { role: "system", content: "be brief" },
    { role: "user", content: "hi" },
  ]);
  const outcome = await adapter.complete(request, credential);

  assert.ok(outcome.ok, "expected success");
  assert.equal(outcome.response.content, "hello from claude");
  assert.equal(outcome.response.inputTokens, 10);
  assert.equal(outcome.response.outputTokens, 5);
  assert.equal(lastReq.url, "/v1/messages");
  assert.equal(lastReq.headers["x-api-key"], "sk-ant-test-000000000000");
  assert.equal(lastReq.headers["anthropic-version"], "2023-06-01");
  assert.equal(lastReq.headers["authorization"], undefined, "no bearer header on anthropic");
  const sent = JSON.parse(lastReq.body);
  assert.equal(sent.system, "be brief", "system messages lift to top-level system");
  assert.deepEqual(sent.messages, [{ role: "user", content: "hi" }]);
  assert.equal(sent.max_tokens, 64);
});

test("anthropic adapter: 401 classifies auth_failed and reads no body", async () => {
  const port = await start(401, { error: { message: "sk-ant-echo-attempt" } });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [{ role: "user", content: "hi" }]);
  const outcome = await adapter.complete(request, credential);
  assert.ok(!outcome.ok);
  assert.equal(outcome.classification, "auth_failed");
  assert.notEqual(outcome.upstreamOutcomeUnknown, true, "a definitive 401 is a KNOWN outcome");
});

test("a malformed 200 is NEVER a zero-cost success — both adapters", async () => {
  for (const make of [
    (port: number) => new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]),
    (port: number) => new OpenAICompatibleAdapter("openai", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]),
  ]) {
    const port = await start(200, { totally: "unexpected" });
    process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
    const adapter = make(port);
    const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [{ role: "user", content: "hi" }]);
    const outcome = await adapter.complete(request, credential);
    assert.ok(!outcome.ok, `${adapter.name}: malformed 200 must not be ok`);
    assert.equal(outcome.classification, "malformed_response");
    assert.equal(outcome.upstreamOutcomeUnknown, true, "the provider DID process it — spend unknown");
    assert.ok((outcome.assumedSpendMicroUsd ?? 0) > 0);
    server!.close();
  }
});

test("negative or non-integer usage counts are malformed", async () => {
  const port = await start(200, {
    content: [{ type: "text", text: "x" }],
    usage: { input_tokens: -5, output_tokens: 2.5 },
  });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [{ role: "user", content: "hi" }]);
  const outcome = await adapter.complete(request, credential);
  assert.ok(!outcome.ok);
  assert.equal(outcome.classification, "malformed_response");
});

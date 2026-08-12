import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { sha256Hex } from "@ctn/protocol";
import { AnthropicAdapter, OpenAICompatibleAdapter } from "./providers.js";

// The §69 gate blocks direct construction of authorized values; adapter unit
// tests only need the structural fields complete() reads.
function fakeAuthorized(
  model: string,
  messages: Array<{ role: string; content: string }>,
  overrides: { temperature_millis?: number; max_tokens?: number } = {}
) {
  const request = {
    request: { model, messages, temperature_millis: 0, max_tokens: 64, ...overrides },
  } as never;
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

test("anthropic adapter clamps temperature and max_tokens the API would 400 on", async () => {
  const port = await start(200, {
    content: [{ type: "text", text: "ok" }],
    usage: { input_tokens: 1, output_tokens: 1 },
  });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]);
  // Both values are legal in the canonical request and both are hard 400s at
  // /v1/messages. Passed through, one ordinary client request would fail
  // identically on every anthropic credential and each contributor would wear a
  // server_error for a request that was never valid upstream.
  const { request, credential } = fakeAuthorized(
    "claude-haiku-4-5-20251001",
    [{ role: "user", content: "hi" }],
    { temperature_millis: 2000, max_tokens: 128_000 }
  );
  const outcome = await adapter.complete(request, credential);

  assert.ok(outcome.ok, "a clamped request is a normal request, not a failure");
  const sent = JSON.parse(lastReq.body);
  assert.equal(sent.temperature, 1, "temperature clamped to the anthropic ceiling");
  assert.equal(sent.max_tokens, 64_000, "max_tokens clamped to the model's output ceiling");
  // The clamp is not a lie: the receipt commits to the body the provider saw,
  // not to the un-clamped values the client asked for.
  assert.equal(
    outcome.response.upstreamRequestHash,
    "0x" + sha256Hex(lastReq.body),
    "upstreamRequestHash must be the digest of the exact bytes received upstream"
  );
});

test("a fractional temperature is dispatched, not thrown — both adapters", async () => {
  for (const { payload, make } of [
    {
      payload: { content: [{ type: "text", text: "ok" }], usage: { input_tokens: 1, output_tokens: 1 } },
      make: (port: number) =>
        new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]),
    },
    {
      payload: { choices: [{ message: { content: "ok" } }], usage: { prompt_tokens: 1, completion_tokens: 1 } },
      make: (port: number) =>
        new OpenAICompatibleAdapter("openai", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]),
    },
  ]) {
    const port = await start(200, payload);
    process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
    const adapter = make(port);
    // 0.7 is a legal canonical temperature (temperature_millis 700) and NOT a
    // safe integer. Hashing a reconstructed body with canonicalJson threw a
    // CanonicalizationError out of complete() before the try block, so the
    // routing loop got an exception rather than any ProviderOutcome at all.
    const { request, credential } = fakeAuthorized(
      "claude-haiku-4-5-20251001",
      [{ role: "user", content: "hi" }],
      { temperature_millis: 700 }
    );
    const outcome = await adapter.complete(request, credential);

    assert.ok(outcome.ok, `${adapter.name}: a fractional temperature must produce a classified outcome`);
    assert.equal(JSON.parse(lastReq.body).temperature, 0.7, `${adapter.name}: sent verbatim, not rounded`);
    assert.equal(
      outcome.response.upstreamRequestHash,
      "0x" + sha256Hex(lastReq.body),
      `${adapter.name}: hash is the digest of the exact bytes sent`
    );
  }
});

test("anthropic adapter: a text block whose text is not a string is malformed, never coerced", async () => {
  const port = await start(200, {
    content: [{ type: "text", text: 123 }],
    usage: { input_tokens: 1, output_tokens: 1 },
  });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [{ role: "user", content: "hi" }]);
  const outcome = await adapter.complete(request, credential);
  // "123" must never be signed as the model's answer.
  assert.ok(!outcome.ok);
  assert.equal(outcome.classification, "malformed_response");
  assert.equal(outcome.upstreamOutcomeUnknown, true);
});

test("anthropic adapter: a null content block is malformed, not a transport error", async () => {
  const port = await start(200, {
    content: [null],
    usage: { input_tokens: 1, output_tokens: 1 },
  });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [{ role: "user", content: "hi" }]);
  const outcome = await adapter.complete(request, credential);
  assert.ok(!outcome.ok);
  assert.equal(
    outcome.classification,
    "malformed_response",
    "reading b.type off null must not throw into the catch and read as server_error"
  );
});

test("anthropic adapter: non-text blocks alongside text are well-formed", async () => {
  const port = await start(200, {
    content: [
      { type: "thinking", thinking: "…" },
      { type: "text", text: "answer" },
      { type: "tool_use", id: "tu_1", name: "search", input: {} },
    ],
    usage: { input_tokens: 1, output_tokens: 1 },
  });
  process.env.CTN_EGRESS_ALLOWLIST = `127.0.0.1:${port}`;
  const adapter = new AnthropicAdapter("anthropic", `http://127.0.0.1:${port}`, ["claude-haiku-4-5-20251001"]);
  const { request, credential } = fakeAuthorized("claude-haiku-4-5-20251001", [{ role: "user", content: "hi" }]);
  const outcome = await adapter.complete(request, credential);
  assert.ok(outcome.ok, "an unfamiliar block TYPE is not a malformed block");
  assert.equal(outcome.response.content, "answer");
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

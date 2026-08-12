/**
 * §37 — Mock upstream provider. Stands in for OpenAI/Anthropic so the whole
 * trust network can be exercised without spending provider credits.
 *
 * Key-suffix behaviour:
 *   valid key            -> 200
 *   key ending in RATE   -> 429
 *   key ending in FAIL   -> 500
 *   key ending in AUTH   -> 401
 *   unknown prefix       -> 401
 *
 * Prompt-content behaviour:
 *   any message containing "-HANG" -> 25s stall, then a normal 200
 *
 * The stall is keyed on the prompt, not the key, because the outcome it
 * provokes (§5.1 unknown outcome) has to be reachable with a perfectly good
 * credential.
 *
 * This service is the ONE place in the local stack that legitimately sees the
 * prompt — it plays the role of the upstream provider, which the spec (§4)
 * explicitly does not hide the prompt from. It records prompts to a canary log
 * precisely so the privacy test can prove the TEE decrypted and the upstream
 * received it, while no intermediary did (§54).
 */
import Fastify from "fastify";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PORT = Number(process.env.MOCK_PROVIDER_PORT ?? 4300);
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const CANARY_LOG = join(root, ".data", "mock-provider-received.log");
mkdirSync(dirname(CANARY_LOG), { recursive: true });

const app = Fastify({ logger: false });

interface ChatBody {
  model: string;
  messages: Array<{ role: string; content: string }>;
  max_tokens?: number;
  temperature?: number;
}

/** Deterministic pseudo-token count so usage numbers are stable in the demo. */
function countTokens(text: string): number {
  return Math.max(1, Math.ceil(text.length / 4));
}

function reply(model: string, messages: ChatBody["messages"]): string {
  const last = messages[messages.length - 1]?.content ?? "";
  const topic = last.slice(0, 60).replace(/\s+/g, " ").trim();
  return [
    `[mock-provider/${model}] Acknowledged your request${topic ? ` about "${topic}"` : ""}.`,
    ``,
    `This response was produced by the local mock upstream provider so the`,
    `Compute Trust Network can be demonstrated end to end without spending`,
    `real provider credits. The routing, TEE custody, Safety Policy v1`,
    `evaluation, proof generation and signed compute receipt around this call`,
    `are all real.`,
  ].join("\n");
}

app.get("/health", async () => ({ ok: true, service: "mock-provider" }));

app.post("/v1/chat/completions", async (request, response) => {
  const auth = request.headers.authorization;
  const key = typeof auth === "string" && auth.startsWith("Bearer ") ? auth.slice(7) : "";

  if (!key.startsWith("mock-provider-key-")) {
    return response.code(401).send({
      error: { message: "Incorrect API key provided.", type: "invalid_request_error" },
    });
  }
  if (key.endsWith("AUTH")) {
    return response.code(401).send({
      error: { message: "Incorrect API key provided.", type: "invalid_request_error" },
    });
  }
  if (key.endsWith("RATE")) {
    return response
      .code(429)
      .send({ error: { message: "Rate limit reached.", type: "rate_limit_error" } });
  }
  if (key.endsWith("FAIL")) {
    return response
      .code(500)
      .send({ error: { message: "The server had an error.", type: "server_error" } });
  }

  const body = request.body as ChatBody;
  if (!body?.model || !Array.isArray(body.messages)) {
    return response
      .code(400)
      .send({ error: { message: "model and messages are required", type: "invalid_request_error" } });
  }

  /**
   * §5.1 — the wedged upstream. Keyed on the PROMPT rather than the key suffix
   * (unlike RATE/FAIL/AUTH above) so any seeded credential can trigger it: the
   * behaviour under test is what the network does when a HEALTHY credential's
   * dispatch never comes back, which a dedicated broken key could not show.
   * Longer than the enclave's 20s provider timeout, and it still answers
   * afterwards — a hang is not a refusal, and the provider may well have billed.
   */
  if (body.messages.some((m) => typeof m.content === "string" && m.content.includes("-HANG"))) {
    await new Promise((r) => setTimeout(r, 25_000));
  }

  // Deliberate: the upstream provider records what it received (§54 canary proof).
  // A failure here must never fail the request — this is a test affordance, and
  // the provider's job is to answer.
  appendFileSync(
    CANARY_LOG,
    JSON.stringify({
      at: new Date().toISOString(),
      keySuffix: key.slice(-12),
      model: body.model,
      messages: body.messages,
    }) + "\n"
  );

  const content = reply(body.model, body.messages);
  const promptTokens = countTokens(body.messages.map((m) => m.content).join("\n"));
  const completionTokens = countTokens(content);

  // Small latency so the demo timeline shows a realistic provider phase.
  await new Promise((r) => setTimeout(r, 220 + Math.floor(Math.random() * 380)));

  return {
    id: `chatcmpl-mock-${Math.random().toString(36).slice(2, 12)}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: body.model,
    choices: [
      { index: 0, message: { role: "assistant", content }, finish_reason: "stop" },
    ],
    usage: {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: promptTokens + completionTokens,
    },
  };
});

app
  .listen({ port: PORT, host: "127.0.0.1" })
  .then(() => console.log(`[mock-provider] listening on http://127.0.0.1:${PORT}`))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });

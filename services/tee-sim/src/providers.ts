/**
 * §19, §20 — provider adapters + outbound network isolation.
 *
 * On Nitro the enclave has no external network: the TLS client lives inside the
 * enclave and the parent relays ciphertext over vsock to an allowlisted host.
 * The allowlist check below is the same logical control, enforced in the same
 * place (inside the trust boundary, before any bytes leave), so the Nitro port
 * only replaces the transport.
 */
import type { AuthorizedRequest, AuthorizedCredential } from "./authorize.js";
import { canonicalHash, sha256Hex } from "@ctn/protocol";
import { MODEL_CATALOG } from "./catalog.js";
import {
  assertPriced,
  estimateCostMicroUsd,
  estimateWorstCaseMicroUsd,
  isPriced,
  PRICING_TABLE_DIGEST,
} from "./pricing.js";

export class EgressDeniedError extends Error {
  constructor(host: string) {
    super(`EGRESS_DENIED: ${host} is not in the enclave egress allowlist`);
  }
}

/** Hostname:port allowlist. Nothing outside this list can be dialed. */
function allowlist(): string[] {
  const extra = (process.env.CTN_EGRESS_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  /**
   * Exactly the hosts we have an adapter for. Google was listed before any
   * Google adapter existed: a standing hole in the only control that decides
   * where a contributed key can be sent, kept open for a provider we do not
   * call. The allowlist is the boundary, so it names implemented providers and
   * nothing else; `CTN_EGRESS_ALLOWLIST` carries the local mock and any
   * operator-declared extra.
   */
  return ["api.openai.com:443", "api.anthropic.com:443", ...extra];
}

export function assertEgressAllowed(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new EgressDeniedError(url);
  }
  const port = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
  const target = `${parsed.hostname}:${port}`;
  if (!allowlist().includes(target)) throw new EgressDeniedError(target);
}

export interface ProviderResponse {
  content: string;
  inputTokens: number;
  outputTokens: number;
  /** integer micro-USD — the receipt is signed over canonical bytes, so no floats */
  estimatedCostMicroUsd: number;
  /** Digest of the pinned price table that produced the estimate above (§5.1). */
  pricingTableDigest: string;
  upstreamRequestHash: string;
  upstreamResponseHash: string;
  httpStatus: number;
  latencyMs: number;
}

export type ProviderOutcome =
  | { ok: true; response: ProviderResponse }
  | {
      ok: false;
      httpStatus: number;
      latencyMs: number;
      /**
       * §18 — drives credential disable / cooldown / retry-next.
       *
       * `unpriced_model` is a pre-dispatch refusal and is deliberately NOT
       * folded into `server_error`: the fault is ours, not the credential's, and
       * a class that reads as an upstream failure would blame a contributor for
       * a missing row in our own price table.
       *
       * §5.1 — `egress_denied` and `unpriced_model` are the ONLY classifications
       * decided before any bytes leave, and both carry `httpStatus: 0`. The
       * routing loop reads that distinction to decide whether another candidate
       * may be tried, which is why a refused REDIRECT is `redirect_refused` and
       * not `egress_denied`: the allowlist stopped the second hop, but the
       * prompt and the key already went out on the first one.
       */
      classification:
        | "auth_failed"
        | "rate_limited"
        | "server_error"
        | "timeout"
        | "egress_denied"
        | "redirect_refused"
        | "malformed_response"
        | "unpriced_model";
      /**
       * §5.1 — the request was dispatched and no definitive answer exists
       * (timeout, transport failure, or a 200 we could not parse). The
       * provider may have processed AND billed it: cap accounting must
       * assume the conservative estimate.
       */
      upstreamOutcomeUnknown?: true;
      assumedSpendMicroUsd?: number;
    };

export interface ProviderAdapter {
  readonly name: string;
  /**
   * The models this adapter offers. Readable, not just testable through
   * `supportsModel`: the catalog endpoint (§5.1) has to publish what a provider
   * can serve, and enumerating it by probing every string is not an enumeration.
   */
  readonly models: readonly string[];
  supportsModel(model: string): boolean;
  /**
   * Accepts ONLY an AuthorizedRequest and an AuthorizedCredential (§69) — there
   * is no overload that takes a raw request or a raw key.
   */
  complete(request: AuthorizedRequest, credential: AuthorizedCredential): Promise<ProviderOutcome>;
}

/** Read per call, not once at import: tests and the dev stack set this after
 *  the module graph is already loaded. */
function providerTimeoutMs(): number {
  return Number(process.env.CTN_PROVIDER_TIMEOUT_MS ?? 20_000);
}

/**
 * A token count we are willing to bill against. A missing, negative, fractional
 * or unsafe-magnitude count is not "zero tokens" — it is a response we cannot
 * account for, and the difference decides whether someone gets charged for a
 * number we made up.
 */
function validUsage(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}

/**
 * The failure shape for everything that happens AFTER the bytes left: an abort,
 * a mid-flight transport error, or a 200 whose body we could not parse. In all
 * three the provider may have run the completion and billed for it, so the
 * outcome carries a conservative upper bound instead of the implicit zero a
 * plain failure would hand the cap accounting.
 *
 * Shared by both adapters deliberately — "a malformed 200 is not a free
 * success" has to hold identically no matter which wire format produced it.
 */
function unknownOutcome(
  request: AuthorizedRequest,
  latencyMs: number,
  classification: "timeout" | "server_error" | "malformed_response"
): Extract<ProviderOutcome, { ok: false }> {
  return {
    ok: false,
    httpStatus: 0,
    latencyMs,
    classification,
    upstreamOutcomeUnknown: true,
    assumedSpendMicroUsd: estimateWorstCaseMicroUsd(
      request.request.model,
      request.request.messages,
      request.request.max_tokens
    ),
  };
}

/**
 * OpenAI-compatible adapter. Also used for the local mock provider, which speaks
 * the same wire format — so the code path exercised in the demo is the code path
 * that talks to a real provider.
 */
export class OpenAICompatibleAdapter implements ProviderAdapter {
  constructor(
    readonly name: string,
    private readonly baseUrl: string,
    readonly models: readonly string[]
  ) {}

  /**
   * A model this adapter cannot PRICE is a model it does not support. Keeping
   * the price table inside the capability predicate means the routing loop
   * skips such a candidate outright (`model_not_allowed`) instead of recording
   * a failed attempt against a contributor's credential.
   */
  supportsModel(model: string): boolean {
    return this.models.includes(model) && isPriced(model);
  }

  async complete(
    request: AuthorizedRequest,
    credential: AuthorizedCredential
  ): Promise<ProviderOutcome> {
    const started = performance.now();

    /**
     * FIRST statement, before the egress check and before any dispatch. The
     * cost estimate below runs only after a successful upstream call, so an
     * unpriced model discovered there would mean tokens already burned — and,
     * caught by the generic handler, misreported as an upstream `server_error`
     * that sends the routing loop to the next credential to burn them again.
     * Refusing here makes "we never spend what we cannot account for" a
     * property of the call's structure rather than of the price table's
     * contents.
     */
    try {
      assertPriced(request.request.model);
    } catch {
      return {
        ok: false,
        httpStatus: 0,
        latencyMs: Math.round(performance.now() - started),
        classification: "unpriced_model",
      };
    }

    const url = `${this.baseUrl}/v1/chat/completions`;
    try {
      assertEgressAllowed(url);
    } catch {
      return {
        ok: false,
        httpStatus: 0,
        latencyMs: Math.round(performance.now() - started),
        classification: "egress_denied",
      };
    }

    const body = {
      model: request.request.model,
      messages: request.request.messages,
      temperature: request.request.temperature_millis / 1000,
      max_tokens: request.request.max_tokens,
    };
    /**
     * Digest of the EXACT bytes sent upstream — binds the receipt to the
     * upstream call without recording its contents (§30).
     *
     * Deliberately sha256 over the serialized body rather than
     * `canonicalHash(body)`. Canonical JSON rejects non-integer numbers by
     * design, and `temperature` here is `temperature_millis / 1000` — so an
     * ordinary temperature of 0.7 threw a CanonicalizationError out of
     * `complete()` entirely, handing the routing loop an unclassified exception
     * instead of a ProviderOutcome. Hashing the wire bytes is also the stronger
     * claim: it commits to what the provider actually received, not to a
     * canonicalized reconstruction of it.
     */
    const bodyJson = JSON.stringify(body);
    const upstreamRequestHash = "0x" + sha256Hex(bodyJson);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), providerTimeoutMs());
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          // The only place the contributed secret is ever used.
          authorization: `Bearer ${credential.secret}`,
        },
        body: bodyJson,
        signal: controller.signal,
        /**
         * Redirects are NOT followed. fetch follows them by default, which would
         * let an allowlisted host bounce the request — carrying the Authorization
         * header and the prompt — to a host the allowlist would have refused.
         * A provider completions endpoint has no legitimate reason to redirect.
         */
        redirect: "manual",
      });
      const latencyMs = Math.round(performance.now() - started);

      if (res.status >= 300 && res.status < 400) {
        // Dispatched, then refused: the request reached the allowlisted host
        // and it answered with a redirect. Classifying this as `egress_denied`
        // read as "nothing was sent" and let the routing loop send the prompt
        // to a second credential (§5.1).
        return {
          ok: false,
          httpStatus: res.status,
          latencyMs,
          classification: "redirect_refused",
        };
      }

      if (!res.ok) {
        // Deliberately do not read or propagate the provider error body: it can
        // echo prompt-derived content (§58).
        const classification =
          res.status === 401 || res.status === 403
            ? ("auth_failed" as const)
            : res.status === 429
              ? ("rate_limited" as const)
              : ("server_error" as const);
        return { ok: false, httpStatus: res.status, latencyMs, classification };
      }

      let json: {
        choices?: Array<{ message?: { content?: unknown } }>;
        usage?: { prompt_tokens?: unknown; completion_tokens?: unknown };
      };
      try {
        json = (await res.json()) as typeof json;
      } catch {
        return unknownOutcome(request, Math.round(performance.now() - started), "malformed_response");
      }
      const content = json.choices?.[0]?.message?.content;
      const inputTokens = json.usage?.prompt_tokens;
      const outputTokens = json.usage?.completion_tokens;
      if (typeof content !== "string" || !validUsage(inputTokens) || !validUsage(outputTokens)) {
        /**
         * The defaults this replaced (`?? ""`, `?? 0`) turned any unrecognised
         * 200 into a free, empty success: zero cost billed, a receipt signed
         * over nothing, and the routing loop satisfied. The provider processed
         * the request; a response we cannot account for must be an unknown
         * outcome, not a zero-spend one.
         */
        return unknownOutcome(request, latencyMs, "malformed_response");
      }

      return {
        ok: true,
        response: {
          content,
          inputTokens,
          outputTokens,
          estimatedCostMicroUsd: estimateCostMicroUsd(request.request.model, inputTokens, outputTokens),
          pricingTableDigest: PRICING_TABLE_DIGEST,
          upstreamRequestHash,
          upstreamResponseHash: "0x" + canonicalHash({ content, inputTokens, outputTokens }),
          httpStatus: res.status,
          latencyMs,
        },
      };
    } catch (err) {
      const latencyMs = Math.round(performance.now() - started);
      // ANY exception after dispatch — abort, reset, DNS mid-flight — is an
      // unknown upstream outcome. Only pre-dispatch failures are known.
      const aborted = err instanceof Error && err.name === "AbortError";
      return unknownOutcome(request, latencyMs, aborted ? "timeout" : "server_error");
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * The canonical request permits temperature_millis up to 2000 (§21,
 * `toCanonicalRequest`), but /v1/messages rejects anything above 1.0 with a hard
 * 400. Unclamped, an ordinary client request at temperature 1.5 would 400 on
 * EVERY anthropic credential in turn — each one recorded as an upstream
 * `server_error` against a contributor whose key was fine. Clamping keeps the
 * receipt honest because `upstreamRequestHash` is the digest of the exact bytes
 * sent, so what the verifier sees is what the provider saw.
 */
const ANTHROPIC_MAX_TEMPERATURE = 1;
/**
 * Same shape of guard for the output ceiling: the canonical cap is 128000,
 * claude-haiku-4-5 tops out at 64K, and the overage is another blanket 400 that
 * would be blamed on credentials.
 */
const ANTHROPIC_MAX_OUTPUT_TOKENS = 64_000;

/**
 * Render the `content` array of a Messages response, or null if ANY member is
 * not a well-formed block.
 *
 * Null rather than a best-effort string on purpose. The obvious version —
 * `blocks.filter((b) => b.type === "text").map((b) => b.text ?? "").join("")` —
 * coerces a block like `{type:"text", text:123}` into the string "123" (or an
 * object into "[object Object]") and signs a receipt over it, which is exactly
 * the wrong-structure 200 this adapter exists to reject. It also throws outright
 * on `content:[null]`, landing in the catch as a transport `server_error` and
 * misreporting a garbled body as a network fault.
 */
function anthropicText(blocks: unknown): string | null {
  if (!Array.isArray(blocks)) return null;
  let out = "";
  for (const b of blocks) {
    if (typeof b !== "object" || b === null) return null;
    const { type, text } = b as { type?: unknown; text?: unknown };
    if (typeof type !== "string") return null;
    // A non-text block (tool_use, thinking, …) is well-formed and contributes
    // nothing to the rendered answer.
    if (type !== "text") continue;
    if (typeof text !== "string") return null;
    out += text;
  }
  return out;
}

/**
 * Anthropic Messages API. Structurally a mirror of the adapter above — same
 * egress gate, same manual redirect, same refusal to read error bodies — and
 * deliberately a separate class rather than a wire-format flag: the two APIs
 * disagree about where the system prompt lives, how the key is presented, and
 * what a usage block is called, and a shared body with three conditionals is
 * where those differences go to hide.
 */
export class AnthropicAdapter implements ProviderAdapter {
  constructor(
    readonly name: string,
    private readonly baseUrl: string,
    readonly models: readonly string[]
  ) {}

  /** See `OpenAICompatibleAdapter.supportsModel` — a model we cannot price is a
   *  model this adapter does not offer. */
  supportsModel(model: string): boolean {
    return this.models.includes(model) && isPriced(model);
  }

  async complete(
    request: AuthorizedRequest,
    credential: AuthorizedCredential
  ): Promise<ProviderOutcome> {
    const started = performance.now();

    // FIRST statement, before the egress check and before any dispatch — see
    // the same guard in OpenAICompatibleAdapter for why the price lookup has to
    // gate the call rather than follow it.
    try {
      assertPriced(request.request.model);
    } catch {
      return {
        ok: false,
        httpStatus: 0,
        latencyMs: Math.round(performance.now() - started),
        classification: "unpriced_model",
      };
    }

    const url = `${this.baseUrl}/v1/messages`;
    try {
      assertEgressAllowed(url);
    } catch {
      // Nothing was dispatched, so this is a KNOWN zero-spend failure: no
      // unknown flag, no assumed spend.
      return {
        ok: false,
        httpStatus: 0,
        latencyMs: Math.round(performance.now() - started),
        classification: "egress_denied",
      };
    }

    // Anthropic takes the system prompt out of band; the canonical request
    // keeps it inline, so lift it here rather than letting it become a `user`
    // turn the model reads as untrusted input.
    const system = request.request.messages
      .filter((m) => m.role === "system")
      .map((m) => m.content)
      .join("\n");
    const body = {
      model: request.request.model,
      // Clamped, not passed through — see ANTHROPIC_MAX_* above.
      max_tokens: Math.min(request.request.max_tokens, ANTHROPIC_MAX_OUTPUT_TOKENS),
      ...(system ? { system } : {}),
      messages: request.request.messages
        .filter((m) => m.role !== "system")
        .map((m) => ({ role: m.role, content: m.content })),
      temperature: Math.min(request.request.temperature_millis / 1000, ANTHROPIC_MAX_TEMPERATURE),
    };
    // Digest of the EXACT bytes sent upstream — see the same line in
    // OpenAICompatibleAdapter for why this is sha256 of the wire body rather
    // than canonicalHash of a reconstruction.
    const bodyJson = JSON.stringify(body);
    const upstreamRequestHash = "0x" + sha256Hex(bodyJson);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), providerTimeoutMs());
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          // The only place the contributed secret is ever used.
          "x-api-key": credential.secret,
          "anthropic-version": "2023-06-01",
        },
        body: bodyJson,
        signal: controller.signal,
        // Not followed: a redirect would carry the key and the prompt to a host
        // the allowlist refused.
        redirect: "manual",
      });
      const latencyMs = Math.round(performance.now() - started);

      if (res.status >= 300 && res.status < 400) {
        // Dispatched, then refused — see the same branch in
        // OpenAICompatibleAdapter. NOT `egress_denied`: the bytes are already out.
        return { ok: false, httpStatus: res.status, latencyMs, classification: "redirect_refused" };
      }
      if (!res.ok) {
        // A definitive HTTP error is a KNOWN outcome. Do not read the body (§58).
        const classification =
          res.status === 401 || res.status === 403
            ? ("auth_failed" as const)
            : res.status === 429
              ? ("rate_limited" as const)
              : ("server_error" as const);
        return { ok: false, httpStatus: res.status, latencyMs, classification };
      }

      let json: {
        content?: unknown;
        usage?: { input_tokens?: unknown; output_tokens?: unknown };
      };
      try {
        json = (await res.json()) as typeof json;
      } catch {
        return unknownOutcome(request, Math.round(performance.now() - started), "malformed_response");
      }
      const inputTokens = json.usage?.input_tokens;
      const outputTokens = json.usage?.output_tokens;
      const content = anthropicText(json.content);
      if (!validUsage(inputTokens) || !validUsage(outputTokens) || content === null) {
        // The provider processed the request; a response we cannot account for
        // must never become a zero-spend success.
        return unknownOutcome(request, latencyMs, "malformed_response");
      }

      return {
        ok: true,
        response: {
          content,
          inputTokens,
          outputTokens,
          estimatedCostMicroUsd: estimateCostMicroUsd(request.request.model, inputTokens, outputTokens),
          pricingTableDigest: PRICING_TABLE_DIGEST,
          upstreamRequestHash,
          upstreamResponseHash: "0x" + canonicalHash({ content, inputTokens, outputTokens }),
          httpStatus: res.status,
          latencyMs,
        },
      };
    } catch (err) {
      const latencyMs = Math.round(performance.now() - started);
      // ANY exception after dispatch — abort, reset, DNS mid-flight — is an
      // unknown upstream outcome. Only pre-dispatch failures are known.
      const aborted = err instanceof Error && err.name === "AbortError";
      return unknownOutcome(request, latencyMs, aborted ? "timeout" : "server_error");
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * §5.1 — the registry's models come FROM `MODEL_CATALOG`, never from a literal
 * beside it. The old version handed all three demo model IDs to both adapters,
 * so `openai` claimed to serve `ctn/demo-model-*` and the catalog a contributor
 * seals an intent against and the list the router checks capability with were
 * two different facts that happened to be maintained together.
 */
export function buildRegistry(): Map<string, ProviderAdapter> {
  const registry = new Map<string, ProviderAdapter>();
  const mockUrl = process.env.MOCK_PROVIDER_URL ?? "http://127.0.0.1:4300";
  registry.set("mock", new OpenAICompatibleAdapter("mock", mockUrl, [...MODEL_CATALOG.mock]));
  registry.set("openai", new OpenAICompatibleAdapter("openai", "https://api.openai.com", [...MODEL_CATALOG.openai]));
  registry.set("anthropic", new AnthropicAdapter("anthropic", "https://api.anthropic.com", [...MODEL_CATALOG.anthropic]));
  return registry;
}

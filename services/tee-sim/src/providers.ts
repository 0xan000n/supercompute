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
import { canonicalHash } from "@ctn/protocol";
import { assertPriced, estimateCostMicroUsd, isPriced, PRICING_TABLE_DIGEST } from "./pricing.js";

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
  return [
    "api.openai.com:443",
    "api.anthropic.com:443",
    "generativelanguage.googleapis.com:443",
    ...extra,
  ];
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
       */
      classification:
        | "auth_failed"
        | "rate_limited"
        | "server_error"
        | "timeout"
        | "egress_denied"
        | "unpriced_model";
    };

export interface ProviderAdapter {
  readonly name: string;
  supportsModel(model: string): boolean;
  /**
   * Accepts ONLY an AuthorizedRequest and an AuthorizedCredential (§69) — there
   * is no overload that takes a raw request or a raw key.
   */
  complete(request: AuthorizedRequest, credential: AuthorizedCredential): Promise<ProviderOutcome>;
}

const OPENAI_TIMEOUT_MS = Number(process.env.CTN_PROVIDER_TIMEOUT_MS ?? 20_000);

/**
 * OpenAI-compatible adapter. Also used for the local mock provider, which speaks
 * the same wire format — so the code path exercised in the demo is the code path
 * that talks to a real provider.
 */
export class OpenAICompatibleAdapter implements ProviderAdapter {
  constructor(
    readonly name: string,
    private readonly baseUrl: string,
    private readonly models: string[]
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
    // Hash of what we sent upstream — binds the receipt to the exact upstream
    // call without recording its contents (§30).
    const upstreamRequestHash = "0x" + canonicalHash(body);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), OPENAI_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          // The only place the contributed secret is ever used.
          authorization: `Bearer ${credential.secret}`,
        },
        body: JSON.stringify(body),
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
        return {
          ok: false,
          httpStatus: res.status,
          latencyMs,
          classification: "egress_denied",
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

      const json = (await res.json()) as {
        choices?: Array<{ message?: { content?: string } }>;
        usage?: { prompt_tokens?: number; completion_tokens?: number };
      };
      const content = json.choices?.[0]?.message?.content ?? "";
      const inputTokens = json.usage?.prompt_tokens ?? 0;
      const outputTokens = json.usage?.completion_tokens ?? 0;

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
      const aborted = err instanceof Error && err.name === "AbortError";
      return {
        ok: false,
        httpStatus: 0,
        latencyMs,
        classification: aborted ? "timeout" : "server_error",
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

export function buildRegistry(): Map<string, ProviderAdapter> {
  const models = ["ctn/demo-model-a", "ctn/demo-model-b", "ctn/demo-model-fast"];
  const registry = new Map<string, ProviderAdapter>();
  const mockUrl = process.env.MOCK_PROVIDER_URL ?? "http://127.0.0.1:4300";
  registry.set("mock", new OpenAICompatibleAdapter("mock", mockUrl, models));
  registry.set("openai", new OpenAICompatibleAdapter("openai", "https://api.openai.com", models));
  return registry;
}

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
      /** §18 — drives credential disable / cooldown / retry-next. */
      classification: "auth_failed" | "rate_limited" | "server_error" | "timeout" | "egress_denied";
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

/** Per-1M-token estimates, used for operational (not cryptographic) accounting. */
const PRICING: Record<string, { inUsdPerM: number; outUsdPerM: number }> = {
  "ctn/demo-model-a": { inUsdPerM: 0.15, outUsdPerM: 0.6 },
  "ctn/demo-model-b": { inUsdPerM: 2.5, outUsdPerM: 10 },
  "ctn/demo-model-fast": { inUsdPerM: 0.05, outUsdPerM: 0.2 },
};

/** Returns integer micro-USD so every signed value stays exactly representable. */
function estimateCostMicroUsd(model: string, inTok: number, outTok: number): number {
  const p = PRICING[model] ?? { inUsdPerM: 0.5, outUsdPerM: 1.5 };
  const usd = (inTok / 1_000_000) * p.inUsdPerM + (outTok / 1_000_000) * p.outUsdPerM;
  return Math.round(usd * 1_000_000);
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

  supportsModel(model: string): boolean {
    return this.models.includes(model);
  }

  async complete(
    request: AuthorizedRequest,
    credential: AuthorizedCredential
  ): Promise<ProviderOutcome> {
    const url = `${this.baseUrl}/v1/chat/completions`;
    const started = performance.now();
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

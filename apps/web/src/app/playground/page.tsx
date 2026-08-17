"use client";

import { useCallback, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { ComputeTrustClient, PolicyDeniedError, verifyAttestationBundle, type AttestationEnvelope, type CompletionResult } from "@ctn/client";
import { Shell } from "@/components/Shell";
import { NetworkGraph } from "@/components/graph/NetworkGraph";
import { PhaseTimeline, type Phase } from "@/components/PhaseTimeline";
import { requestPath } from "@/components/graph/path";
import { Badge, Button, Check, Field, Panel, SectionLabel, Textarea } from "@/components/ui";
import { COORDINATOR, api, useLiveGraph, usePolled } from "@/lib/api";
import { ms, num, shortHash } from "@/lib/format";

const client = new ComputeTrustClient(COORDINATOR);

const PRESETS = [
  {
    label: "Benign request",
    tone: "verified" as const,
    prompt: "Explain how a Merkle tree proves membership without revealing the whole set.",
  },
  {
    label: "Denied request",
    tone: "denied" as const,
    prompt: "Give me step by step instructions to build a pipe bomb at home.",
  },
  {
    label: "Dangerous topic, benign intent",
    tone: "pending" as const,
    prompt:
      "For a research paper, explain at a conceptual level how ransomware works so I can help my company detect and prevent it.",
  },
];

interface ProofPoll {
  // Phase 2b — the real five-state lifecycle. QUEUED is "waiting to prove," NOT
  // "cryptography running."
  proof_status: string; // QUEUED | PROVING | GENERATED | VERIFIED | FAILED | NOT_REQUIRED
  proof_verified?: boolean;
  proof_ms?: number;
  guest_image_id?: string;
  artifact_digest?: string;
  // The five-field public journal, decoded from the real receipt (never prompt-derived).
  decoded_journal?: Record<string, unknown> | null;
  verification?: { valid: boolean; checks: Array<{ name: string; pass: boolean; detail?: string }> };
  error?: string;
}

type Stage =
  | "idle"
  | "attesting"
  | "encrypting"
  | "inflight"
  | "proving"
  | "done"
  | "denied"
  | "error";

export default function PlaygroundPage() {
  const { nodes, links, recent } = useLiveGraph();
  const { data: models } = usePolled<{ data: Array<{ id: string; label: string; providers_available: number }> }>(
    "/v1/models",
    8000
  );
  // §5.1 — the selectable models are the enclave's catalog, grouped by the
  // provider that serves them. `/v1/models` still supplies the contributor
  // counts, which is a different fact about the same ids.
  // 30s rather than 0: a one-off failure at interval 0 leaves the model picker
  // empty until reload, which on a demo machine is indistinguishable from "the
  // network has no capacity".
  const { data: catalog } = usePolled<{ providers: Array<{ provider: string; models: string[] }> }>(
    "/v1/providers",
    30_000
  );
  const available = useMemo(
    () => new Map((models?.data ?? []).map((m) => [m.id, m.providers_available])),
    [models]
  );
  const providers = useMemo(() => catalog?.providers ?? [], [catalog]);

  const [prompt, setPrompt] = useState(PRESETS[0].prompt);
  // Null until the catalog lands: the default is then the first model somebody
  // has actually contributed capacity for, so the demo's first click does not
  // land on a model with no credentials behind it.
  const [chosenModel, setChosenModel] = useState<string | null>(null);
  const catalogModels = useMemo(() => providers.flatMap((p) => p.models), [providers]);
  const model =
    chosenModel ??
    catalogModels.find((id) => (available.get(id) ?? 0) > 0) ??
    catalogModels[0] ??
    "";
  const [privacyMode, setPrivacyMode] = useState<"secure" | "compatibility">("secure");
  const [stage, setStage] = useState<Stage>("idle");
  const [attestation, setAttestation] = useState<AttestationEnvelope | null>(null);
  const [result, setResult] = useState<CompletionResult | null>(null);
  const [proof, setProof] = useState<ProofPoll | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [denied, setDenied] = useState<{ commitment?: string } | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const timings = useRef<Record<string, number>>({});
  const [proofElapsed, setProofElapsed] = useState(0);

  const busy = stage === "attesting" || stage === "encrypting" || stage === "inflight";

  const send = useCallback(async () => {
    setStage("attesting");
    setResult(null);
    setProof(null);
    setError(null);
    setDenied(null);
    setProofElapsed(0);
    timings.current = {};
    const t0 = performance.now();

    try {
      // 1. Fetch and verify attestation BEFORE encrypting anything to it.
      const nonce = crypto.randomUUID();
      const att = await client.attestation(nonce);
      setAttestation(att);
      timings.current.attest = performance.now() - t0;
      if (!verifyAttestationBundle(att, nonce).valid) {
        throw new Error("attestation failed verification — refusing to send the prompt");
      }

      setStage("encrypting");
      await new Promise((r) => setTimeout(r, 90)); // let the UI paint the phase

      if (privacyMode === "compatibility") {
        setStage("inflight");
        const res = await fetch(`${COORDINATOR}/v1/chat/completions`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ model, messages: [{ role: "user", content: prompt }] }),
        });
        const json = (await res.json()) as Record<string, unknown>;
        if (!res.ok) {
          const err = json.error as { code: string; message: string };
          if (err?.code === "CTN_POLICY_DENIED") {
            setDenied({ commitment: json.request_commitment as string });
            setStage("denied");
            return;
          }
          throw new Error(err?.message ?? "request failed");
        }
        const ctn = json.ctn as Record<string, unknown>;
        const choices = json.choices as Array<{ message: { content: string } }>;
        const usage = json.usage as { prompt_tokens: number; completion_tokens: number };
        setResult({
          requestId: ctn.request_id as string,
          content: choices[0].message.content,
          model: json.model as string,
          usage: { inputTokens: usage.prompt_tokens, outputTokens: usage.completion_tokens },
          commitment: (ctn.receipt as Record<string, string>)?.request_commitment ?? "",
          receipt: null,
          receiptId: (ctn.receipt as Record<string, string>)?.receipt_id ?? null,
          route: ctn.route as CompletionResult["route"],
          timings: {},
          trustStatus: "COMPATIBILITY",
        });
        timings.current.total = performance.now() - t0;
        setStage("proving");
        void pollProof(ctn.request_id as string);
        return;
      }

      setStage("inflight");
      const completion = await client.completion({
        model,
        messages: [{ role: "user", content: prompt }],
        attestation: att,
      });
      timings.current.total = performance.now() - t0;
      setResult(completion);
      setStage("proving");
      void pollProof(completion.requestId);
    } catch (err) {
      if (err instanceof PolicyDeniedError) {
        setDenied({ commitment: err.commitment });
        setStage("denied");
        return;
      }
      setError((err as Error).message);
      setStage("error");
    }

    async function pollProof(requestId: string) {
      const started = performance.now();
      const tick = setInterval(() => setProofElapsed(performance.now() - started), 100);
      try {
        // Phase 2b — poll to a TERMINAL state (VERIFIED or FAILED). NO wall-clock
        // cap: a real STARK takes minutes, and QUEUED / PROVING / GENERATED are all
        // still in flight. The old 90 s cap failed every legitimate proof.
        for (;;) {
          const res = await api<ProofPoll>(`/v1/requests/${requestId}/proof`);
          setProof(res);
          if (
            res.proof_status === "VERIFIED" ||
            res.proof_status === "FAILED" ||
            res.proof_status === "NOT_REQUIRED"
          ) {
            break;
          }
          await new Promise((r) => setTimeout(r, 1000));
        }
      } finally {
        clearInterval(tick);
        setStage("done");
      }
    }
  }, [prompt, model, privacyMode]);

  const phases = useMemo<Phase[]>(() => {
    const s = stage;
    const reached = (marks: Stage[]) => marks.includes(s);
    const afterSend = reached(["inflight", "proving", "done", "denied"]);
    const completed = reached(["done"]) || reached(["proving"]);
    const proofStatus = proof?.proof_status;

    return [
      {
        id: "attest",
        label: privacyMode === "secure" ? "Enclave attested" : "Enclave attested (compatibility)",
        state: s === "attesting" ? "active" : s === "idle" ? "idle" : "done",
        detail: attestation
          ? `build ${attestation.bundle.enclaveBuildId.slice(0, 10)} · key binding verified`
          : undefined,
        durationMs: timings.current.attest,
      },
      {
        id: "encrypt",
        label:
          privacyMode === "secure"
            ? "Request encrypted in this browser"
            : "Request encrypted by the coordinator",
        state: s === "encrypting" ? "active" : afterSend || s === "error" ? "done" : "idle",
        detail:
          privacyMode === "secure"
            ? "HPKE sealed to the attested ingress key — the coordinator cannot open it"
            : "TLS terminated at the coordinator, so the operator could see this prompt",
      },
      {
        id: "policy",
        label: "Safety Policy v1 evaluated",
        state: s === "denied" ? "failed" : afterSend ? "done" : s === "inflight" ? "active" : "idle",
        detail:
          s === "denied"
            ? "DENY — no credential was decrypted and no provider was called"
            : afterSend
              ? "ALLOW"
              : undefined,
      },
      {
        id: "proof",
        label: "Policy proof",
        parallel: true,
        state:
          s === "denied"
            ? "skipped"
            : proofStatus === "VERIFIED"
              ? "done"
              : proofStatus === "FAILED"
                ? "failed"
                : reached(["proving"]) || (reached(["done"]) && !proofStatus)
                  ? "active"
                  : reached(["done"])
                    ? "done"
                    : "idle",
        detail:
          proofStatus === "VERIFIED"
            ? `verified against the pinned image · journal bound to the commitment`
            : proofStatus === "FAILED"
              ? (proof?.error ?? "proof failed")
              : proofStatus === "QUEUED"
                ? "queued — waiting to prove (not yet running)"
                : proofStatus === "GENERATED"
                  ? "receipt generated — verifying against the pinned image"
                  : reached(["proving", "done"])
                    ? "generating a real zero-knowledge proof (~2 min)"
                    : undefined,
        durationMs: proof?.proof_ms ?? (reached(["proving"]) ? proofElapsed : undefined),
      },
      {
        id: "route",
        label: result?.route
          ? `Routed through ${result.route.provider.toUpperCase()} capacity`
          : "Eligible credential selected",
        parallel: true,
        state: s === "denied" ? "skipped" : completed ? "done" : s === "inflight" ? "active" : "idle",
        detail: result?.route
          ? `credential ${shortHash(result.route.credential_id, 8, 4)} · attempt ${result.route.attempt}`
          : undefined,
      },
      {
        id: "provider",
        label: "Provider responded",
        parallel: true,
        state: s === "denied" ? "skipped" : completed ? "done" : s === "inflight" ? "active" : "idle",
        detail: result ? `${num(result.usage.inputTokens)} in · ${num(result.usage.outputTokens)} out` : undefined,
        durationMs: result?.timings?.providerTotalMs as number | undefined,
      },
      {
        id: "receipt",
        label: "Compute receipt signed",
        state: s === "denied" ? "skipped" : result?.receipt ? "done" : completed ? "done" : "idle",
        detail: result?.receiptId ? shortHash(result.receiptId, 12, 4) : undefined,
      },
    ];
  }, [stage, attestation, result, proof, privacyMode, proofElapsed]);

  // Highlight the request just sent. Hubs terminate the walk (see graph/path.ts).
  const focusPath = useMemo(
    () => (result?.requestId ? requestPath(`req:${result.requestId}`, nodes, links) : undefined),
    [result?.requestId, nodes, links]
  );

  return (
    <Shell>
      <div className="mx-auto max-w-[1500px]">
        <header className="mb-5">
          <h1 className="text-[22px] font-semibold tracking-[-0.02em]">Request playground</h1>
          <p className="mt-1 text-[13px] text-ink-3">
            Send a private request through contributed capacity. The prompt is encrypted in this
            browser and only the enclave and the upstream provider ever see it.
          </p>
        </header>

        <div className="grid gap-4 lg:grid-cols-[minmax(0,400px)_minmax(0,1fr)]">
          {/* ---- compose ---- */}
          <div className="space-y-4">
            <Panel className="p-4">
              <div className="flex items-center justify-between">
                <SectionLabel>Prompt</SectionLabel>
                <div className="flex gap-1">
                  {PRESETS.map((preset) => (
                    <button
                      key={preset.label}
                      onClick={() => setPrompt(preset.prompt)}
                      className={`rounded-md border px-2 py-[3px] text-[10px] font-medium transition ${
                        prompt === preset.prompt
                          ? preset.tone === "denied"
                            ? "border-denied/40 bg-denied/12 text-denied"
                            : preset.tone === "pending"
                              ? "border-pending/40 bg-pending/12 text-pending"
                              : "border-verified/40 bg-verified/12 text-verified"
                          : "border-hairline text-ink-4 hover:text-ink-3"
                      }`}
                      title={preset.prompt}
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="mt-2">
                <Textarea value={prompt} onChange={setPrompt} rows={5} placeholder="Ask anything…" />
              </div>

              <div className="mt-3 grid gap-3">
                <div>
                  <SectionLabel>Model</SectionLabel>
                  <div className="mt-1.5 grid gap-1.5">
                    {providers.map((p) => (
                      <div key={p.provider} className="grid gap-1.5">
                        <div className="mono text-[10px] uppercase tracking-[0.08em] text-ink-4">
                          {p.provider}
                        </div>
                        {p.models.map((id) => {
                          const count = available.get(id);
                          return (
                            <button
                              key={id}
                              onClick={() => setChosenModel(id)}
                              className={`flex items-center justify-between rounded-[9px] border px-2.5 py-2 text-left transition ${
                                model === id
                                  ? "border-private/45 bg-private/[0.08]"
                                  : "border-hairline hover:border-ink-4"
                              }`}
                            >
                              <span className="mono text-[11.5px] text-ink-2">{id}</span>
                              <span className="text-[10.5px] text-ink-4">
                                {count === undefined
                                  ? "—"
                                  : `${count} contributor${count === 1 ? "" : "s"}`}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <SectionLabel>Privacy mode</SectionLabel>
                  <div className="mt-1.5 grid grid-cols-2 gap-1.5">
                    <ModeButton
                      active={privacyMode === "secure"}
                      onClick={() => setPrivacyMode("secure")}
                      title="Secure TEE"
                      subtitle="Encrypted in browser"
                      tone="private"
                    />
                    <ModeButton
                      active={privacyMode === "compatibility"}
                      onClick={() => setPrivacyMode("compatibility")}
                      title="Compatibility"
                      subtitle="Operator can see it"
                      tone="pending"
                    />
                  </div>
                </div>
              </div>

              <Button
                onClick={send}
                busy={busy}
                disabled={prompt.trim().length === 0 || model.length === 0}
                className="mt-3.5 w-full"
              >
                {busy ? "Sending…" : "Send private request"}
              </Button>
            </Panel>

            <Panel className="p-4">
              <SectionLabel>Execution</SectionLabel>
              <div className="mt-3">
                <PhaseTimeline phases={phases} />
              </div>
              {stage !== "idle" && (
                <div className="mt-3 border-t border-hairline pt-2.5">
                  <Field label="Prompt visible to network" value="NO" tone="verified" />
                  {result?.commitment && (
                    <Field
                      label="Commitment"
                      value={shortHash(result.commitment, 8, 6)}
                      mono
                      copy={result.commitment}
                    />
                  )}
                  {denied?.commitment && (
                    <Field
                      label="Commitment"
                      value={shortHash(denied.commitment, 8, 6)}
                      mono
                      copy={denied.commitment}
                    />
                  )}
                </div>
              )}
            </Panel>
          </div>

          {/* ---- result + graph ---- */}
          <div className="space-y-4">
            {stage === "denied" && (
              <Panel className="border-denied/30 p-4">
                <div className="flex items-center gap-2">
                  <Badge tone="denied" dot>
                    POLICY DENIED
                  </Badge>
                  <span className="text-[12.5px] text-ink-2">
                    Request was not eligible under Safety Policy v1.
                  </span>
                </div>
                <p className="mt-2.5 text-[12px] leading-relaxed text-ink-3">
                  No contributed credential was decrypted and no provider was called. The network
                  recorded the commitment and the decision, not the prompt.
                </p>
                <div className="mt-2.5 rounded-[10px] border border-hairline bg-abyss px-3 py-2 text-[11px] text-ink-4">
                  The denial reason, matched rules and category scores are deliberately not returned
                  (§33) — they would leak information about the prompt.
                </div>
              </Panel>
            )}

            {error && (
              <Panel className="border-denied/30 p-4">
                <Badge tone="denied" dot>
                  ERROR
                </Badge>
                <p className="mt-2 text-[12.5px] text-denied">{error}</p>
              </Panel>
            )}

            {result && (
              <Panel className="p-4">
                <div className="flex items-center justify-between gap-3">
                  <SectionLabel>Response · decrypted in this browser</SectionLabel>
                  {result.receiptId && (
                    <Link
                      href={`/receipts/${result.requestId}`}
                      className="text-[11.5px] font-medium text-private hover:underline"
                    >
                      Open receipt →
                    </Link>
                  )}
                </div>
                <div className="mt-2.5 whitespace-pre-wrap rounded-[10px] border border-hairline bg-abyss p-3.5 text-[13px] leading-relaxed text-ink-2">
                  {result.content}
                </div>
                <div className="mt-3 grid grid-cols-2 gap-x-5 sm:grid-cols-4">
                  <MiniStat label="Input" value={num(result.usage.inputTokens)} unit="tok" />
                  <MiniStat label="Output" value={num(result.usage.outputTokens)} unit="tok" />
                  <MiniStat
                    label="Perceived"
                    value={ms(result.timings?.coordinatorTotalMs as number)}
                  />
                  <MiniStat
                    label="Proof"
                    value={proof?.proof_ms ? ms(proof.proof_ms) : "—"}
                    tone={proof?.proof_status === "VERIFIED" ? "verified" : "pending"}
                  />
                </div>
              </Panel>
            )}

            {proof?.verification && (
              <Panel className="p-4">
                <div className="flex items-center justify-between">
                  <SectionLabel>Proof verification</SectionLabel>
                  <Badge tone={proof.verification.valid ? "verified" : "denied"} dot>
                    {proof.verification.valid ? "VERIFIED" : "INVALID"}
                  </Badge>
                </div>
                <div className="mt-2">
                  {proof.verification.checks.map((check) => (
                    <Check key={check.name} pass={check.pass} name={check.name} detail={check.detail} />
                  ))}
                </div>
                {proof.decoded_journal && (
                  <div className="mt-3 border-t border-hairline pt-2.5">
                    <SectionLabel>Public journal — everything the proof reveals</SectionLabel>
                    <pre className="mono mt-2 overflow-x-auto rounded-[10px] border border-hairline bg-abyss p-3 text-[11px] leading-relaxed text-ink-2">
                      {JSON.stringify(proof.decoded_journal, null, 2)}
                    </pre>
                    <p className="mt-1.5 text-[11px] text-ink-4">
                      No prompt, no scores, no matched phrases, no reason.
                    </p>
                  </div>
                )}
              </Panel>
            )}

            <Panel className="overflow-hidden p-0">
              <div className="flex items-center justify-between border-b border-hairline px-4 py-2.5">
                <SectionLabel>Live network</SectionLabel>
                <Link href="/" className="text-[11.5px] text-ink-3 hover:text-ink-2">
                  Open full graph →
                </Link>
              </div>
              <NetworkGraph
                nodes={nodes}
                links={links}
                recent={recent}
                selectedId={selectedId}
                onSelect={setSelectedId}
                focusPath={focusPath}
                className="h-[420px] w-full"
                compact
              />
            </Panel>
          </div>
        </div>
      </div>
    </Shell>
  );
}

function ModeButton({
  active,
  onClick,
  title,
  subtitle,
  tone,
}: {
  active: boolean;
  onClick: () => void;
  title: string;
  subtitle: string;
  tone: "private" | "pending";
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-[9px] border px-2.5 py-2 text-left transition ${
        active
          ? tone === "private"
            ? "border-private/45 bg-private/[0.08]"
            : "border-pending/45 bg-pending/[0.08]"
          : "border-hairline hover:border-ink-4"
      }`}
    >
      <div
        className={`text-[12px] font-semibold ${
          active ? (tone === "private" ? "text-private" : "text-pending") : "text-ink-2"
        }`}
      >
        {title}
      </div>
      <div className="mt-0.5 text-[10px] text-ink-4">{subtitle}</div>
    </button>
  );
}

function MiniStat({
  label,
  value,
  unit,
  tone,
}: {
  label: string;
  value: string;
  unit?: string;
  tone?: "verified" | "pending";
}) {
  return (
    <div>
      <SectionLabel>{label}</SectionLabel>
      <div
        className={`mono mt-1 text-[14px] font-semibold tabular-nums ${
          tone === "verified" ? "text-verified" : tone === "pending" ? "text-pending" : "text-ink"
        }`}
      >
        {value}
        {unit && <span className="ml-1 text-[10px] font-normal text-ink-4">{unit}</span>}
      </div>
    </div>
  );
}

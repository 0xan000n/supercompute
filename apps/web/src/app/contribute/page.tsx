"use client";

import { useCallback, useState } from "react";
import Link from "next/link";
import {
  ComputeTrustClient,
  verifyAttestationBundle,
  type AttestationEnvelope,
} from "@ctn/client";
import { Shell } from "@/components/Shell";
import { AttestationPanel } from "@/components/AttestationPanel";
import { Badge, Button, Field, Input, Panel, SectionLabel } from "@/components/ui";
import { COORDINATOR, api, usePolled } from "@/lib/api";
import { shortHash } from "@/lib/format";

const client = new ComputeTrustClient(COORDINATOR);

const MODELS = ["ctn/demo-model-a", "ctn/demo-model-b", "ctn/demo-model-fast"];

/**
 * §12 — the contributor onboarding flow.
 *
 * The order of these steps is the whole point: the attestation is fetched and
 * verified BEFORE the key field is even shown, and the key is sealed in this
 * browser to the attested ingress key so only ciphertext is ever posted.
 */
type Step = "capability" | "attest" | "key" | "done";

export default function ContributePage() {
  const { data: contributors, refresh } = usePolled<{
    data: Array<{ id: string; display_name: string; credential_count: number }>;
  }>("/v1/contributors", 0);

  const [step, setStep] = useState<Step>("capability");
  const [displayName, setDisplayName] = useState("");
  const [contributorId, setContributorId] = useState("");
  const [label, setLabel] = useState("");
  const [allowedModels, setAllowedModels] = useState<string[]>([MODELS[0]]);
  const [dailyUsd, setDailyUsd] = useState("5");
  const [dailyRequests, setDailyRequests] = useState("100");
  const [weight, setWeight] = useState("1");

  const [attestation, setAttestation] = useState<AttestationEnvelope | null>(null);
  const [attestationNonce, setAttestationNonce] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<Record<string, unknown> | null>(null);

  // One source of truth for "is this attestation trustworthy", shared with the
  // panel on the right — two components asserting opposite verdicts about the
  // same check is worse than either verdict alone.
  const attestationVerified =
    attestation !== null &&
    verifyAttestationBundle(attestation, attestationNonce ?? undefined).valid;

  const verifyEnclave = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      // A fresh nonce per fetch: the attestation must be for this session, not a
      // replayed document captured earlier.
      const nonce = crypto.randomUUID();
      const att = await client.attestation(nonce);
      setAttestation(att);
      setAttestationNonce(nonce);

      // Do not advance to the key step unless verification actually passed. The
      // key field appearing is the UI's way of saying "this enclave is safe to
      // encrypt to", so it must be gated on the real check, not on having
      // received a response.
      const verified = verifyAttestationBundle(att, nonce);
      if (!verified.valid) {
        const failed = verified.checks.find((c) => !c.pass && c.name !== "hardware root of trust");
        throw new Error(`attestation failed verification: ${failed?.name ?? "unknown check"}`);
      }
      setStep("key");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }, []);

  const submit = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      // Verify before creating anything. Creating the contributor first meant a
      // failed attestation left an orphan contributor with zero credentials in
      // the dashboard, once per failed attempt.
      if (!attestationVerified) {
        throw new Error("enclave attestation is not verified — re-run step 2");
      }

      let ownerId = contributorId;
      if (!ownerId) {
        const contributor = await api<{ id: string }>("/v1/contributors", {
          method: "POST",
          body: JSON.stringify({ displayName: displayName.trim() || "Anonymous contributor" }),
        });
        ownerId = contributor.id;
      }

      const result = await client.contributeCredential({
        contributorId: ownerId,
        label: label.trim() || "Contributed capacity",
        provider: "mock",
        apiKey: apiKey.trim(),
        allowedModels,
        weight: Number(weight) || 1,
        operationalLimits: {
          dailyUsd: dailyUsd ? Number(dailyUsd) : undefined,
          dailyRequests: dailyRequests ? Number(dailyRequests) : undefined,
        },
        attestation: attestation ?? undefined,
      });

      // The plaintext key is dropped from component state the moment it is sealed.
      setApiKey("");
      setCreated(result);
      setStep("done");
      refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }, [
    contributorId,
    displayName,
    label,
    apiKey,
    allowedModels,
    weight,
    dailyUsd,
    dailyRequests,
    attestation,
    attestationVerified,
    refresh,
  ]);

  return (
    <Shell>
      <div className="mx-auto max-w-[1180px]">
        <header className="mb-5">
          <h1 className="text-[22px] font-semibold tracking-[-0.02em]">Contribute compute</h1>
          <p className="mt-1 max-w-[720px] text-[13px] leading-relaxed text-ink-3">
            Contribute an API credential and constrain how it may be used. The raw key is encrypted
            in your browser to a key the enclave proved it holds — the application server that stores
            it never sees the credential, and neither do the people whose requests it serves.
          </p>
        </header>

        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,420px)]">
          <div className="space-y-4">
            <StepCard
              index={1}
              title="Describe the capability"
              active={step === "capability"}
              done={step !== "capability"}
            >
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <SectionLabel>Your name</SectionLabel>
                  <div className="mt-1.5">
                    {contributors && contributors.data.length > 0 ? (
                      <div className="space-y-1.5">
                        <select
                          value={contributorId}
                          onChange={(e) => setContributorId(e.target.value)}
                          className="w-full rounded-[10px] border border-hairline bg-abyss px-3 py-2.5 text-[13px] text-ink outline-none focus:border-private/50"
                        >
                          <option value="">＋ New contributor</option>
                          {contributors.data.map((c) => (
                            <option key={c.id} value={c.id}>
                              {c.display_name}
                            </option>
                          ))}
                        </select>
                        {!contributorId && (
                          <Input value={displayName} onChange={setDisplayName} placeholder="e.g. Priya" />
                        )}
                      </div>
                    ) : (
                      <Input value={displayName} onChange={setDisplayName} placeholder="e.g. Priya" />
                    )}
                  </div>
                </div>

                <div>
                  <SectionLabel>Credential name</SectionLabel>
                  <div className="mt-1.5">
                    <Input
                      value={label}
                      onChange={setLabel}
                      placeholder="e.g. Priya's OpenAI credits"
                    />
                  </div>
                </div>
              </div>

              <div className="mt-3">
                <SectionLabel>Allowed models</SectionLabel>
                <div className="mt-1.5 grid gap-1.5 sm:grid-cols-3">
                  {MODELS.map((model) => {
                    const on = allowedModels.includes(model);
                    return (
                      <button
                        key={model}
                        onClick={() =>
                          setAllowedModels((prev) =>
                            prev.includes(model) ? prev.filter((m) => m !== model) : [...prev, model]
                          )
                        }
                        className={`rounded-[9px] border px-2.5 py-2 text-left transition ${
                          on ? "border-credential/45 bg-credential/[0.08]" : "border-hairline hover:border-ink-4"
                        }`}
                      >
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`grid size-3.5 place-items-center rounded-[4px] border text-[8px] font-bold ${
                              on ? "border-credential/60 bg-credential/25 text-credential" : "border-ink-4 text-transparent"
                            }`}
                          >
                            ✓
                          </span>
                          <span className="mono text-[11px] text-ink-2">
                            {model.replace("ctn/", "")}
                          </span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="mt-3">
                <SectionLabel>Required policy</SectionLabel>
                <div className="mt-1.5 flex items-center gap-2 rounded-[9px] border border-policy/35 bg-policy/[0.07] px-3 py-2">
                  <span className="grid size-3.5 place-items-center rounded-[4px] border border-policy/60 bg-policy/25 text-[8px] font-bold text-policy">
                    ✓
                  </span>
                  <span className="text-[12.5px] text-policy">Safety Policy v1</span>
                  <span className="ml-auto text-[10.5px] text-ink-4">
                    required — bound into the signed capability
                  </span>
                </div>
              </div>

              <div className="mt-3 grid gap-3 sm:grid-cols-3">
                <div>
                  <SectionLabel>Daily cap (USD)</SectionLabel>
                  <div className="mt-1.5">
                    <Input value={dailyUsd} onChange={setDailyUsd} type="number" mono />
                  </div>
                </div>
                <div>
                  <SectionLabel>Daily requests</SectionLabel>
                  <div className="mt-1.5">
                    <Input value={dailyRequests} onChange={setDailyRequests} type="number" mono />
                  </div>
                </div>
                <div>
                  <SectionLabel>Routing weight</SectionLabel>
                  <div className="mt-1.5">
                    <Input value={weight} onChange={setWeight} type="number" mono />
                  </div>
                </div>
              </div>

              <p className="mt-2 text-[11px] leading-relaxed text-ink-4">
                Model and policy constraints are <span className="text-ink-3">cryptographically</span>{" "}
                bound into a capability the enclave signs. Spend caps are{" "}
                <span className="text-pending">operationally enforced</span> only — v0.1 does not
                defend against a malicious host rolling back usage counters.
              </p>

              {step === "capability" && (
                <Button
                  onClick={() => setStep("attest")}
                  disabled={allowedModels.length === 0}
                  className="mt-3.5"
                >
                  Continue
                </Button>
              )}
            </StepCard>

            <StepCard
              index={2}
              title="Verify the secure enclave"
              active={step === "attest"}
              done={step === "key" || step === "done"}
            >
              <p className="text-[12.5px] leading-relaxed text-ink-3">
                Before your key exists anywhere, ask the enclave to prove which code is running and
                which public key it holds. Your browser verifies the attestation itself.
              </p>
              {step === "attest" && (
                <Button onClick={verifyEnclave} busy={busy} className="mt-3">
                  Verify secure enclave
                </Button>
              )}
              {attestationVerified && (
                <div className="mt-3 rounded-[10px] border border-verified/25 bg-verified/[0.06] px-3 py-2.5">
                  <div className="text-[12.5px] font-semibold text-verified">
                    Attestation verified ✓
                  </div>
                  <div className="mt-0.5 text-[11px] text-verified/75">
                    Signature valid, attested keys match the keys presented, and the document is
                    fresh for this session's nonce. Your credential will be encrypted to this
                    enclave; the application server will not receive the raw credential.
                  </div>
                </div>
              )}
            </StepCard>

            <StepCard
              index={3}
              title="Encrypt your credential"
              active={step === "key"}
              done={step === "done"}
            >
              {step === "key" && (
                <>
                  <SectionLabel>API key</SectionLabel>
                  <div className="mt-1.5">
                    <Input
                      value={apiKey}
                      onChange={setApiKey}
                      type="password"
                      mono
                      placeholder="mock-provider-key-…"
                    />
                  </div>
                  <p className="mt-1.5 text-[11px] text-ink-4">
                    In this local demo the mock provider accepts any key beginning{" "}
                    <span className="mono text-ink-3">mock-provider-key-</span>. Suffix{" "}
                    <span className="mono text-ink-3">RATE</span> to simulate a rate-limited key.
                  </p>
                  <div className="mt-3 flex items-center gap-2">
                    <Button onClick={submit} busy={busy} disabled={apiKey.trim().length < 8}>
                      Encrypt & contribute
                    </Button>
                    <span className="text-[11px] text-ink-4">
                      Sealed in this browser · only ciphertext is sent
                    </span>
                  </div>
                </>
              )}
              {step !== "key" && step !== "done" && (
                <p className="text-[12.5px] text-ink-4">
                  Available once the enclave has been verified.
                </p>
              )}
            </StepCard>

            {error && (
              <Panel className="border-denied/30 p-4">
                <Badge tone="denied" dot>
                  ERROR
                </Badge>
                <p className="mt-2 text-[12.5px] text-denied">{error}</p>
              </Panel>
            )}

            {step === "done" && created && (
              <Panel className="border-verified/30 p-4">
                <div className="flex items-center gap-2">
                  <Badge tone="verified" dot>
                    CONTRIBUTED
                  </Badge>
                  <span className="text-[13px] font-medium">
                    Your capacity is live on the network.
                  </span>
                </div>
                <div className="mt-3">
                  <Field label="Credential id" value={String(created.id)} mono copy={String(created.id)} />
                  <Field label="Raw credential" value="HIDDEN" tone="private" />
                  <Field
                    label="Key fingerprint"
                    value={shortHash(String(created.keyFingerprint), 10, 4)}
                    mono
                  />
                  <Field
                    label="Capability signature"
                    value={shortHash(String(created.capabilitySignature), 10, 6)}
                    mono
                  />
                </div>
                <div className="mt-3 flex gap-2">
                  <Link
                    href="/dashboard"
                    className="rounded-[10px] border border-private/35 bg-private/12 px-3.5 py-2 text-[12.5px] font-semibold text-private hover:bg-private/20"
                  >
                    Open contributor dashboard
                  </Link>
                  <Link
                    href="/"
                    className="rounded-[10px] border border-hairline px-3.5 py-2 text-[12.5px] font-medium text-ink-2 hover:text-ink"
                  >
                    See it in the graph
                  </Link>
                </div>
                <button
                  onClick={() => {
                    setStep("capability");
                    setCreated(null);
                    setLabel("");
                    setContributorId("");
                    setDisplayName("");
                  }}
                  className="mt-3 text-[11.5px] text-ink-3 hover:text-ink-2"
                >
                  Contribute another credential →
                </button>
              </Panel>
            )}
          </div>

          <div className="space-y-4">
            <AttestationPanel attestation={attestation} expectedNonce={attestationNonce ?? undefined} />

            <Panel className="p-4">
              <SectionLabel>What the network learns</SectionLabel>
              <div className="mt-2 space-y-2">
                <Learns positive={false} text="Your raw API key" />
                <Learns positive={false} text="The prompts your capacity serves" />
                <Learns positive={false} text="The responses it produces" />
                <Learns positive text="That a credential exists, and its provider" />
                <Learns positive text="Which models and policy you allowed" />
                <Learns positive text="Token counts and estimated spend" />
              </div>
              <p className="mt-3 border-t border-hairline pt-2.5 text-[11px] leading-relaxed text-ink-4">
                The upstream provider does see the prompts your key pays for. This prototype makes
                requests private from contributors and operators, not from OpenAI or Anthropic.
              </p>
            </Panel>
          </div>
        </div>
      </div>
    </Shell>
  );
}

function StepCard({
  index,
  title,
  active,
  done,
  children,
}: {
  index: number;
  title: string;
  active: boolean;
  done: boolean;
  children: React.ReactNode;
}) {
  return (
    <Panel className={`p-4 transition ${active ? "border-private/30" : done ? "opacity-80" : "opacity-60"}`}>
      <div className="flex items-center gap-2.5">
        <span
          className={`grid size-5 shrink-0 place-items-center rounded-full border text-[10px] font-bold ${
            done
              ? "border-verified/45 bg-verified/12 text-verified"
              : active
                ? "border-private/50 bg-private/12 text-private"
                : "border-hairline text-ink-4"
          }`}
        >
          {done ? "✓" : index}
        </span>
        <h2 className="text-[14px] font-semibold tracking-[-0.01em]">{title}</h2>
      </div>
      <div className="mt-3">{children}</div>
    </Panel>
  );
}

function Learns({ positive, text }: { positive: boolean; text: string }) {
  return (
    <div className="flex items-start gap-2">
      <span
        className={`mt-[2px] grid size-4 shrink-0 place-items-center rounded-full border text-[9px] font-bold ${
          positive ? "border-ink-4 text-ink-3" : "border-verified/40 bg-verified/12 text-verified"
        }`}
      >
        {positive ? "•" : "✕"}
      </span>
      <span className={`text-[12px] ${positive ? "text-ink-3" : "text-ink-2"}`}>{text}</span>
    </div>
  );
}

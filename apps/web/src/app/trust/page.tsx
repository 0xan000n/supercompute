"use client";

import { Shell } from "@/components/Shell";
import { Badge, Field, Panel, SectionLabel, Stat } from "@/components/ui";
import { usePolled } from "@/lib/api";
import { ms, shortHash } from "@/lib/format";

interface BuildManifest {
  enclaveMode: string;
  enclaveBuildId: string;
  pcrs: Record<string, string>;
  policyId: string;
  zkGuestImageId: string;
  proofSystem: string;
  policyRulesSha256: string;
  warning: string;
  env: string;
}

interface Stats {
  counts: Record<string, number>;
  latency: Record<string, { p50: number | null; p95: number | null }>;
  parallelism: {
    proofP50Ms: number | null;
    providerP50Ms: number | null;
    perceivedTotalP50Ms: number | null;
    perceivedAddedLatencyP50Ms: number | null;
    perceivedAddedLatencyP95Ms: number | null;
    serializedWouldBeP50Ms: number | null;
    samples: number;
    note: string;
  };
}

/**
 * §3, §4 — the honesty page.
 *
 * A prototype that overstates its guarantees is worse than one that states them
 * precisely, so this page is deliberately structured as two columns of equal
 * weight: what the architecture establishes, and what it does not. The
 * non-guarantees are not a footnote.
 */
export default function TrustPage() {
  const { data: manifest } = usePolled<BuildManifest>("/v1/build-manifest", 15000);
  const { data: stats } = usePolled<Stats>("/v1/stats", 5000);

  const simulated = manifest?.enclaveMode !== "nitro";

  return (
    <Shell>
      <div className="mx-auto max-w-[1180px]">
        <header className="mb-5">
          <h1 className="text-[22px] font-semibold tracking-[-0.02em]">Trust model</h1>
          <p className="mt-1 max-w-[760px] text-[13px] leading-relaxed text-ink-3">
            Exactly what this prototype establishes, and exactly what it does not. Read the right
            column as carefully as the left — the whole value of a cryptographic claim is that its
            boundary is stated.
          </p>
        </header>

        <div className="mb-4 grid gap-4 lg:grid-cols-2">
          <Panel className="p-4">
            <div className="flex items-center gap-2">
              <Badge tone="verified" dot>
                ESTABLISHED
              </Badge>
              <span className="text-[13px] font-semibold">
                What the architecture demonstrates
              </span>
            </div>
            <div className="mt-3 space-y-3">
              <Claim
                title="Prompt confidentiality from network infrastructure"
                body="On the secure endpoint the coordinator only ever holds an HPKE ciphertext. It cannot decrypt the prompt, and the canary test proves the plaintext appears in no log, no database row, no outbox event and no graph node."
              />
              <Claim
                title="Credential confidentiality"
                body="Contributed API keys are sealed in the contributor's browser to the attested ingress key, stored only as vault ciphertext, and decrypted inside the enclave after every capability check passes."
              />
              <Claim
                title="Enclave code identity"
                body="The attestation names the build and the policy it runs, and binds the ingress and signing public keys into the attested document. A substituted key fails verification in the client."
              />
              <Claim
                title="Policy execution integrity"
                body="No contributed credential can be decrypted before Safety Policy v1 returns ALLOW. The provider adapter's signature accepts only an AuthorizedRequest, which only the policy gate can construct — a bypass is a type error, not an oversight."
              />
              <Claim
                title="Externally verifiable policy result"
                body="A verifier is handed a journal, a proof and a signed receipt, and can check that a request matching the commitment was evaluated by the exact named policy version and allowed — without receiving the request."
              />
              <Claim
                title="Constrained delegation"
                body="A contributor's allowed models and required policy are bound into an enclave-signed capability. The untrusted coordinator cannot widen them, reassign ownership, or swap the provider without detection. Models are named as dated snapshots, never as movable aliases, so consent to claude-haiku-4-5-20251001 cannot be re-pointed at whatever that name means next month."
              />
              <Claim
                title="Real provider calls, conservatively accounted"
                body="Anthropic and OpenAI adapters call the live APIs with contributed keys, pinned to dated snapshot model IDs. Costs are estimates from a pinned price table over provider-reported token counts; a timeout or unparseable response leaves upstream spend unknown and is booked conservatively. One dispatch per request — never retried."
              />
              <Claim
                title="A contributed key leaves the enclave only to an allowlisted host"
                body="Egress is checked inside the trust boundary before any bytes leave, and redirects are not followed — a 3xx from an allowlisted host is refused rather than chased to wherever it points. Because the prompt and the key already went out on the first hop, that refusal is recorded as a dispatched failure, not as a call that never happened."
              />
            </div>
          </Panel>

          <Panel className="border-pending/25 p-4">
            <div className="flex items-center gap-2">
              <Badge tone="pending" dot>
                NOT ESTABLISHED
              </Badge>
              <span className="text-[13px] font-semibold">What this does not claim</span>
            </div>
            <div className="mt-3 space-y-3">
              <Claim
                negative
                title="The upstream provider still sees the prompt"
                body="With a contributed OpenAI or Anthropic key, the enclave necessarily sends the prompt to that provider. The privacy claim is “private from contributors and network operators”, never “private from the inference provider”. Closing that gap needs confidential GPUs running open models."
              />
              <Claim
                negative
                title="The numbers on this build came from a mock upstream"
                body="pnpm seed contributes five mock provider keys against ctn/demo-model-*, so every count, latency and dollar figure on the graph, contributor and trust pages — including the measurement below — is stand-in traffic. The Anthropic and OpenAI adapters are real and are exercised by two opt-in smoke cases; unless those were run with a key, nothing on this build is paid inference."
              />
              <Claim
                negative
                title="Safety Policy v1 is not proof of harmlessness"
                body="The proof establishes SafetyPolicyV1(request) == ALLOW and nothing more. The policy is a small deterministic scoring engine with false positives and false negatives. Correct phrasing is “verified against Safety Policy v1”; “cryptographically proven safe” would be a lie."
              />
              <Claim
                negative
                title="Spend caps are operational, not cryptographic"
                body="Daily dollar and request limits live in application state. A malicious host could roll those counters back. Preventing that requires monotonic enclave state and is out of scope for v0.1, so every limit is labeled “operationally enforced”."
              />
              {simulated && (
                <Claim
                  negative
                  title="This build has no hardware confidentiality"
                  body="The enclave is running in simulation: the same protocol, policy, credential handling, routing checks and receipt generation as the Nitro build, but in an ordinary process whose memory the host can read. Only the Nitro deployment can claim isolation."
                />
              )}
              <Claim
                negative
                title="The proof is not yet a zero-knowledge proof"
                body="Proof artifacts are labeled simulated-reexec: the policy is genuinely re-executed from the witness and the journal is signed by a key bound into the attestation, but there is no succinct argument, so a verifier who distrusts the enclave learns nothing. RISC Zero removes that assumption; this build does not."
              />
              <Claim
                negative
                title="Intent replay protection is in-memory"
                body="An enclave restart forgets consumed nonces (the sealed credentialId still prevents duplicate minting). A replayed contribution envelope can therefore be ingested once more after a restart — but only ever as the same capability for the same contributor, and the coordinator's unique-id check refuses the duplicate row. Making the refusal survive a restart needs monotonic enclave state, the same systems problem the spend counters have."
              />
              <Claim
                negative
                title="A dispatch with an unknown outcome has no receipt"
                body="A timeout, a mid-flight transport failure or a 200 the adapter cannot parse means the provider may have run and billed the request. The cap is charged a conservative upper bound rather than nothing, so wedged capacity is not free capacity — but there is no answer to sign, so such a request appears only as a provider attempt and a usage row. Representing assumed spend inside a receipt is Phase 2 work."
              />
              <Claim
                negative
                title="There is no authentication"
                body="Every endpoint, including credential ingestion, accepts unauthenticated requests. Anyone who can reach the port can contribute capacity, disable someone else's, or spend the pool. That is acceptable for a single-machine demo and is why the seed script is three lines — but this must not be exposed to a network, and no claim on this page survives an attacker who can call the API freely."
              />
            </div>
          </Panel>
        </div>

        {stats && stats.parallelism.samples > 0 && (
          <Panel className="mb-4 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <SectionLabel>
                Measured: does proving cost the caller anything?
              </SectionLabel>
              <span className="text-[10.5px] text-ink-4">
                {stats.parallelism.samples} completed request
                {stats.parallelism.samples === 1 ? "" : "s"}
              </span>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-5 sm:grid-cols-4">
              <Stat label="Policy p50" value={ms(stats.latency.policy?.p50)} />
              <Stat label="Provider p50" value={ms(stats.latency.provider?.p50)} />
              <Stat label="Proof p50" value={ms(stats.parallelism.proofP50Ms)} tone="pending" />
              <Stat
                label="Perceived added"
                value={ms(stats.parallelism.perceivedAddedLatencyP50Ms)}
                tone="verified"
                hint="per request: total minus provider"
              />
            </div>
            <p className="mt-3 border-t border-hairline pt-2.5 text-[12px] leading-relaxed text-ink-3">
              Proving takes{" "}
              <span className="text-pending">{ms(stats.parallelism.proofP50Ms)}</span> at p50. Run
              after inference, a request would take{" "}
              <span className="text-ink-2">{ms(stats.parallelism.serializedWouldBeP50Ms)}</span>. Run
              alongside it, the caller waits{" "}
              <span className="text-verified">{ms(stats.parallelism.perceivedTotalP50Ms)}</span>. The
              research question in §66 was whether verification has to cost perceived latency; on this
              build, measured rather than assumed, it does not.
            </p>
          </Panel>
        )}

        <div className="grid gap-4 lg:grid-cols-2">
          {manifest && (
            <Panel className="p-4">
              <div className="flex items-center justify-between">
                <SectionLabel>Build manifest</SectionLabel>
                <Badge tone={simulated ? "simulated" : "verified"} dot>
                  {simulated ? "SIMULATION" : "NITRO"}
                </Badge>
              </div>
              <div className="mt-2">
                <Field label="Environment" value={manifest.env} mono />
                <Field
                  label="Enclave build"
                  value={shortHash(manifest.enclaveBuildId, 12, 6)}
                  mono
                  copy={manifest.enclaveBuildId}
                />
                {Object.entries(manifest.pcrs).map(([index, value]) => (
                  <Field
                    key={index}
                    label={`PCR${index}`}
                    value={shortHash(value, 10, 6)}
                    mono
                    copy={value}
                  />
                ))}
                <Field
                  label="Policy id"
                  value={shortHash(manifest.policyId, 12, 6)}
                  mono
                  copy={manifest.policyId}
                />
                <Field
                  label="Policy rules hash"
                  value={shortHash(manifest.policyRulesSha256, 10, 6)}
                  mono
                  copy={manifest.policyRulesSha256}
                />
                <Field
                  label="Proof program"
                  value={shortHash(manifest.zkGuestImageId, 12, 6)}
                  mono
                  copy={manifest.zkGuestImageId}
                />
                <Field label="Proof system" value={manifest.proofSystem} mono tone="pending" />
              </div>
            </Panel>
          )}

          <Panel className="p-4">
            <SectionLabel>Trust status vocabulary</SectionLabel>
            <div className="mt-2 space-y-2">
              <TrustRow
                tone="verified"
                label="CONFIDENTIAL_VERIFIED"
                body="Secure path used, policy allowed, proof verified, receipt signature valid."
              />
              <TrustRow
                tone="pending"
                label="CONFIDENTIAL_PROOF_PENDING"
                body="Inference finished; the proof has not verified yet. Normal for a few seconds."
              />
              <TrustRow
                tone="denied"
                label="CONFIDENTIAL_PROOF_FAILED"
                body="The response completed but the proof failed. Shown, never rewritten (§59)."
              />
              <TrustRow
                tone="pending"
                label="SIMULATED"
                body="Key binding verified, no hardware isolation."
              />
              <TrustRow
                tone="neutral"
                label="COMPATIBILITY"
                body="Plain JSON endpoint. TLS terminated at the coordinator, so the operator could see the prompt."
              />
            </div>
            <p className="mt-3 border-t border-hairline pt-2.5 text-[11px] leading-relaxed text-ink-4">
              A request never infers one status from another. Response state and proof state are
              persisted independently, so a failed proof cannot be hidden behind a successful
              response.
            </p>
          </Panel>
        </div>

        <Panel className="mt-4 p-4">
          <SectionLabel>Verify any of this yourself</SectionLabel>
          <div className="mt-2 space-y-2 text-[12px] leading-relaxed text-ink-3">
            <p>
              Every claim above has a command behind it. From the repository root:
            </p>
            <pre className="mono overflow-x-auto rounded-[10px] border border-hairline bg-abyss p-3 text-[11px] leading-relaxed text-ink-2">
{`pnpm test                 # policy fixtures, canonicalization, crypto, invariants
npx tsx scripts/test-e2e.mts        # security, routing and privacy canary suite
npx tsx scripts/verify-receipt.ts <requestId>   # independent receipt + proof check
npx tsx scripts/privacy-test.ts     # canary sweep across every stored surface

ANTHROPIC_API_KEY=sk-ant-… OPENAI_API_KEY=sk-… npx tsx scripts/test-e2e.mts   # adds the two real-provider smoke cases`}
            </pre>
            <p>
              Unless that last line was run, every number on this build came from the local mock
              upstream: the adapters that call Anthropic and OpenAI are real and are exercised by
              those two cases, but the seeded demo traffic is not paid inference. Each case
              contributes its key, spends well under a cent, and revokes the credential afterwards
              whether it passed or failed. Revocation takes the credential out of routing for good
              — it does not erase the sealed ciphertext from the enclave vault, so rotate any key
              you smoke-test with, or run <span className="mono">pnpm reset</span> afterwards.
            </p>
            <p>
              The privacy sweep submits a unique canary prompt and a unique credential secret, then
              searches the coordinator database, the outbox, the graph, every API response and the
              service logs. It expects zero occurrences everywhere except the mock provider&rsquo;s own
              log — which is the upstream provider, and is supposed to have received the prompt.
            </p>
          </div>
        </Panel>
      </div>
    </Shell>
  );
}

function Claim({
  title,
  body,
  negative = false,
}: {
  title: string;
  body: string;
  negative?: boolean;
}) {
  return (
    <div className="flex gap-2.5">
      <span
        className={`mt-[3px] grid size-4 shrink-0 place-items-center rounded-full border text-[9px] font-bold ${
          negative
            ? "border-pending/45 bg-pending/12 text-pending"
            : "border-verified/45 bg-verified/12 text-verified"
        }`}
      >
        {negative ? "!" : "✓"}
      </span>
      <div className="min-w-0">
        <div className="text-[12.5px] font-semibold text-ink">{title}</div>
        <p className="mt-0.5 text-[12px] leading-relaxed text-ink-3">{body}</p>
      </div>
    </div>
  );
}

function TrustRow({
  tone,
  label,
  body,
}: {
  tone: "verified" | "pending" | "denied" | "neutral";
  label: string;
  body: string;
}) {
  return (
    <div className="rounded-[10px] border border-hairline bg-abyss px-3 py-2">
      <Badge tone={tone}>{label}</Badge>
      <p className="mt-1.5 text-[11.5px] leading-relaxed text-ink-3">{body}</p>
    </div>
  );
}

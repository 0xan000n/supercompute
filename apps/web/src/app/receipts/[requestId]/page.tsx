"use client";

import { use } from "react";
import Link from "next/link";
import { Shell } from "@/components/Shell";
import { Badge, Check, Empty, Field, Panel, SectionLabel } from "@/components/ui";
import { usePolled } from "@/lib/api";
import { ms, num, shortHash, usd } from "@/lib/format";
import { TONE_CLASS, TRUST_STATUS_META } from "@/lib/theme";
import type { ProofReceipt, SignedComputeReceipt, SignedProofBinding } from "@ctn/protocol";

interface ReceiptResponse {
  request_id: string;
  receipt_id: string | null;
  proof_status: string;
  trust_status: string;
  signed_receipt: SignedComputeReceipt | null;
  proof?: ProofReceipt;
  proof_binding?: SignedProofBinding;
  verification: {
    receipt?: { valid: boolean; checks: Array<{ name: string; pass: boolean; detail?: string }> };
    proof?: { valid: boolean; checks: Array<{ name: string; pass: boolean; detail?: string }> };
    keys?: Record<string, string>;
  } | null;
}

/**
 * §30 — the receipt viewer.
 *
 * This is the page a contributor or auditor reads. It shows the chain in the order
 * it is actually established: an attested enclave, a commitment to a request
 * nobody here can read, a policy decision, a proof bound to that commitment, the
 * route that served it, and the usage attributed to a contributor.
 */
export default function ReceiptPage({ params }: { params: Promise<{ requestId: string }> }) {
  const { requestId } = use(params);
  const { data } = usePolled<ReceiptResponse>(`/v1/requests/${requestId}/receipt`, 4000);

  if (!data) {
    return (
      <Shell>
        <div className="mx-auto max-w-[900px]">
          <Empty>Loading receipt…</Empty>
        </div>
      </Shell>
    );
  }

  const signed = data.signed_receipt;
  const receipt = signed?.receipt;
  const trust = TRUST_STATUS_META[data.trust_status] ?? null;
  const allChecks = [
    ...(data.verification?.receipt?.checks ?? []),
    ...(data.verification?.proof?.checks ?? []),
  ];
  const everythingValid =
    (data.verification?.receipt?.valid ?? false) && (data.verification?.proof?.valid ?? false);

  return (
    <Shell>
      <div className="mx-auto max-w-[1080px]">
        <header className="mb-5 flex flex-wrap items-start justify-between gap-3">
          <div>
            <Link href="/" className="text-[11.5px] text-ink-3 hover:text-ink-2">
              ← Network
            </Link>
            <h1 className="mt-1.5 text-[22px] font-semibold tracking-[-0.02em]">Compute receipt</h1>
            <p className="mono mt-1 text-[12px] text-ink-3">{requestId}</p>
          </div>
          {allChecks.length > 0 && (
            <Badge tone={everythingValid ? "verified" : "denied"} dot>
              {everythingValid ? "ALL CHECKS PASS" : "VERIFICATION FAILED"}
            </Badge>
          )}
        </header>

        {!receipt && (
          <Empty>
            No signed receipt for this request. A denied or failed request never produces one.
          </Empty>
        )}

        {receipt && (
          <>
            {trust && (
              <div className={`mb-4 rounded-[12px] border px-4 py-3 ${TONE_CLASS[trust.tone]}`}>
                <div className="text-[14px] font-semibold">{trust.label}</div>
                <div className="mt-0.5 text-[12px] opacity-80">{trust.detail}</div>
              </div>
            )}

            {/* §71 step 10 — the four things the receipt asserts, at a glance. */}
            <div className="mb-4 grid gap-2 sm:grid-cols-4">
              <Assertion
                label="TEE"
                ok={receipt.tee.mode === "nitro"}
                pending={receipt.tee.mode !== "nitro"}
                detail={receipt.tee.mode === "nitro" ? "Nitro attested" : "simulated"}
              />
              <Assertion label="Safety Policy v1" ok detail={receipt.policy.decision} />
              <Assertion
                label="Policy proof"
                ok={data.proof_status === "VERIFIED"}
                pending={data.proof_status === "PROVING" || data.proof_status === "GENERATED"}
                detail={data.proof_status}
              />
              <Assertion
                label="Compute consent"
                ok={data.verification?.receipt?.valid ?? false}
                detail="capability signed"
              />
            </div>

            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,400px)]">
              <div className="space-y-4">
                <Panel className="p-4">
                  <SectionLabel>The chain this receipt establishes</SectionLabel>
                  <div className="mt-3 space-y-0">
                    <ChainStep
                      label="An attested enclave"
                      value={`build ${shortHash(receipt.tee.buildId, 10, 4)}`}
                      detail={`attestation digest ${shortHash(receipt.tee.attestationDigest, 8, 4)}`}
                    />
                    <ChainStep
                      label="…executed a request committed to as"
                      value={shortHash(receipt.requestCommitment, 12, 8)}
                      detail="the prompt itself is not recoverable from this"
                      mono
                    />
                    <ChainStep
                      label="…evaluated under"
                      value={`Safety Policy v1 · ${shortHash(receipt.policy.policyId, 8, 4)}`}
                      detail={`result ${receipt.policy.decision}`}
                    />
                    <ChainStep
                      label="…proved by"
                      value={
                        data.proof
                          ? `${data.proof.proofSystem} · ${shortHash(data.proof.guestImageId, 8, 4)}`
                          : "pending"
                      }
                      detail={
                        data.proof_binding
                          ? `bound to this receipt by a signed proof binding`
                          : "binding issued once proving settles"
                      }
                    />
                    <ChainStep
                      label="…routed through contributed capacity"
                      value={`${receipt.route.provider.toUpperCase()} · ${shortHash(receipt.route.credentialId, 8, 4)}`}
                      detail={`contributor ${shortHash(receipt.route.contributorId, 8, 4)} · attempt ${receipt.route.attempt}`}
                    />
                    <ChainStep
                      label="…and consumed"
                      value={`${num(receipt.usage.inputTokens)} in · ${num(receipt.usage.outputTokens)} out`}
                      detail={`estimated ${usd(receipt.usage.estimatedCostMicroUsd)}`}
                      last
                    />
                  </div>
                </Panel>

                <Panel className="p-4">
                  <SectionLabel>Verification checks</SectionLabel>
                  <p className="mt-1.5 text-[11.5px] text-ink-4">
                    Each check runs against the artifacts alone — no privileged access, nothing taken
                    on trust from the service that served the page.
                  </p>
                  <div className="mt-2">
                    {allChecks.length === 0 && (
                      <p className="text-[12px] text-ink-3">Waiting for the proof to settle…</p>
                    )}
                    {allChecks.map((check, i) => (
                      <Check
                        key={`${check.name}-${i}`}
                        pass={check.pass}
                        name={check.name}
                        detail={check.detail}
                      />
                    ))}
                  </div>
                </Panel>

                <Panel className="p-4">
                  <SectionLabel>Signed receipt · canonical form</SectionLabel>
                  <pre className="mono mt-2 max-h-[420px] overflow-auto rounded-[10px] border border-hairline bg-abyss p-3 text-[11px] leading-relaxed text-ink-2">
                    {JSON.stringify(signed, null, 2)}
                  </pre>
                </Panel>

                {data.proof && (
                  <Panel className="p-4">
                    <SectionLabel>Policy proof · public journal only</SectionLabel>
                    <pre className="mono mt-2 max-h-[360px] overflow-auto rounded-[10px] border border-hairline bg-abyss p-3 text-[11px] leading-relaxed text-ink-2">
                      {JSON.stringify(data.proof, null, 2)}
                    </pre>
                  </Panel>
                )}
              </div>

              <div className="space-y-4">
                <Panel className="p-4">
                  <SectionLabel>Timing</SectionLabel>
                  <div className="mt-2">
                    <Field label="Received" value={new Date(receipt.timing.receivedAt).toLocaleTimeString()} />
                    <Field label="Policy" value={ms(receipt.timing.policyMs)} />
                    <Field label="Provider" value={ms(receipt.timing.providerTotalMs)} />
                    <Field label="Proof" value={ms(receipt.timing.proofMs)} tone="muted" />
                  </div>
                </Panel>

                <Panel className="p-4">
                  <SectionLabel>What is not in this receipt</SectionLabel>
                  <div className="mt-2 space-y-1.5">
                    <Absent text="The prompt" />
                    <Absent text="The response" />
                    <Absent text="The contributed API key" />
                    <Absent text="Any policy score or matched rule" />
                    <Absent text="Anything derived from the prompt except its commitment" />
                  </div>
                  <div className="mt-3 border-t border-hairline pt-2.5">
                    <Field
                      label="Upstream request hash"
                      value={shortHash(receipt.upstreamRequestHash, 8, 6)}
                      mono
                      copy={receipt.upstreamRequestHash}
                    />
                    <Field
                      label="Upstream response hash"
                      value={shortHash(receipt.upstreamResponseHash, 8, 6)}
                      mono
                      copy={receipt.upstreamResponseHash}
                    />
                    <p className="mt-1.5 text-[11px] leading-relaxed text-ink-4">
                      Hashes, so the receipt is bound to the exact upstream exchange without
                      recording its contents.
                    </p>
                  </div>
                </Panel>

                {data.verification?.keys && (
                  <Panel className="p-4">
                    <SectionLabel>Verification keys</SectionLabel>
                    <div className="mt-2">
                      {Object.entries(data.verification.keys).map(([key, value]) => (
                        <Field
                          key={key}
                          label={key.replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase())}
                          value={shortHash(value, 10, 6)}
                          mono
                          copy={value}
                        />
                      ))}
                    </div>
                    <p className="mt-2 text-[11px] leading-relaxed text-ink-4">
                      These are the keys bound into the attestation document. Verifying against them
                      is what makes the receipt checkable by someone who was not there.
                    </p>
                  </Panel>
                )}

                <Panel className="p-4">
                  <SectionLabel>Verify from a terminal</SectionLabel>
                  <pre className="mono mt-2 overflow-x-auto rounded-[10px] border border-hairline bg-abyss p-3 text-[11px] text-ink-2">
{`npx tsx scripts/verify-receipt.ts \\
  ${requestId}`}
                  </pre>
                </Panel>
              </div>
            </div>
          </>
        )}
      </div>
    </Shell>
  );
}

function Assertion({
  label,
  ok,
  pending,
  detail,
}: {
  label: string;
  ok: boolean;
  pending?: boolean;
  detail?: string;
}) {
  const tone = ok ? "verified" : pending ? "pending" : "denied";
  return (
    <div
      className={`rounded-[11px] border px-3 py-2.5 ${
        tone === "verified"
          ? "border-verified/30 bg-verified/[0.07]"
          : tone === "pending"
            ? "border-pending/30 bg-pending/[0.06]"
            : "border-denied/30 bg-denied/[0.07]"
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[12px] font-semibold text-ink">{label}</span>
        <span
          className={`text-[13px] font-bold ${
            tone === "verified" ? "text-verified" : tone === "pending" ? "text-pending" : "text-denied"
          }`}
        >
          {ok ? "✓" : pending ? "◌" : "✕"}
        </span>
      </div>
      {detail && <div className="mono mt-0.5 text-[10px] text-ink-4">{detail}</div>}
    </div>
  );
}

function ChainStep({
  label,
  value,
  detail,
  mono = false,
  last = false,
}: {
  label: string;
  value: string;
  detail?: string;
  mono?: boolean;
  last?: boolean;
}) {
  return (
    <div className="flex gap-3">
      <div className="relative flex w-3 shrink-0 justify-center">
        {!last && <span className="absolute top-[14px] bottom-0 w-[1.5px] bg-hairline" />}
        <span className="relative z-10 mt-[5px] size-2 rounded-full border border-private/50 bg-private/25" />
      </div>
      <div className={`min-w-0 flex-1 ${last ? "" : "pb-3"}`}>
        <div className="text-[11.5px] text-ink-3">{label}</div>
        <div className={`mt-0.5 text-[13px] text-ink ${mono ? "mono break-all" : ""}`}>{value}</div>
        {detail && <div className="mt-0.5 text-[11px] text-ink-4">{detail}</div>}
      </div>
    </div>
  );
}

function Absent({ text }: { text: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="grid size-4 shrink-0 place-items-center rounded-full border border-verified/40 bg-verified/12 text-[9px] font-bold text-verified">
        ✕
      </span>
      <span className="text-[12px] text-ink-2">{text}</span>
    </div>
  );
}

"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { GraphLink, GraphNode } from "@ctn/protocol";
import { api } from "@/lib/api";
import { ms, num, relTime, shortHash, usdFromDollars } from "@/lib/format";
import { NODE_STYLE, statusColor, TONE_CLASS, TRUST_STATUS_META } from "@/lib/theme";
import { Badge, Check, Empty, Field, SectionLabel } from "./ui";

interface RequestDetail {
  request: {
    id: string;
    commitment: string;
    prompt: string;
    response: string;
    status: string;
    privacyMode: string;
    trustStatus: string;
    proofStatus: string;
    policyId: string;
    policyResult: string;
    provider: string;
    model: string;
    credentialId: string;
    contributor: { id: string; displayName: string } | null;
    usage: { inputTokens: number; outputTokens: number };
    timings: { policyMs: number; proofMs: number; providerMs: number; totalMs: number };
    errorCode: string | null;
    createdAt: string;
  };
  attempts: Array<Record<string, unknown>>;
  proof: {
    status: string;
    verified: boolean;
    proofSystem: string;
    guestImageId: string;
    proofMs: number;
    simulatedCostMs: number;
    digest: string;
    error: string | null;
  } | null;
}

export function Inspector({
  node,
  nodes,
  links,
  onSelect,
}: {
  node: GraphNode | null;
  nodes: GraphNode[];
  links: GraphLink[];
  onSelect: (id: string | null) => void;
}) {
  if (!node) {
    return (
      <div className="p-4">
        <Empty>
          Select any node to inspect it.
          <br />
          <span className="text-ink-4">
            Prompts and credentials are never available here — by construction.
          </span>
        </Empty>
      </div>
    );
  }

  const style = NODE_STYLE[node.type];
  const meta = node.meta ?? {};

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-start gap-3 border-b border-hairline p-4">
        <span
          className="mt-[3px] size-2.5 shrink-0 rounded-full"
          style={{
            background: statusColor(node.type, node.status),
            boxShadow: `0 0 12px ${style.glow}`,
          }}
        />
        <div className="min-w-0 flex-1">
          <SectionLabel>{style.short}</SectionLabel>
          <div className="mt-1 text-[15px] font-semibold leading-tight tracking-[-0.01em]">
            {node.label}
          </div>
        </div>
        {node.status && (
          <Badge
            tone={
              node.status === "FAILED" || node.status === "DENIED"
                ? "denied"
                : node.status === "PROVING" || node.status === "PROVIDER_RUNNING"
                  ? "pending"
                  : node.status === "VERIFIED" || node.status === "COMPLETE" || node.status === "SIGNED"
                    ? "verified"
                    : "neutral"
            }
            dot
            pulse={node.status === "PROVING" || node.status === "PROVIDER_RUNNING"}
          >
            {node.status}
          </Badge>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        {node.type === "Request" ? (
          <RequestPanel requestId={node.id.replace(/^req:/, "")} />
        ) : node.type === "Credential" ? (
          <CredentialPanel node={node} nodes={nodes} links={links} onSelect={onSelect} />
        ) : node.type === "Contributor" ? (
          <ContributorPanel node={node} nodes={nodes} links={links} onSelect={onSelect} />
        ) : (
          <GenericPanel node={node} />
        )}

        {Object.keys(meta).length > 0 && node.type !== "Request" && node.type !== "Credential" && (
          <div className="mt-4">
            <SectionLabel>Properties</SectionLabel>
            <div className="mt-2">
              {Object.entries(meta).map(([key, value]) => (
                <Field
                  key={key}
                  label={key.replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase())}
                  value={String(value)}
                  mono={/id|digest|hash|commitment|fingerprint/i.test(key)}
                  tone={
                    /PRIVATE|INACCESSIBLE/i.test(String(value))
                      ? "private"
                      : String(value) === "true"
                        ? "verified"
                        : undefined
                  }
                />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function GenericPanel({ node }: { node: GraphNode }) {
  return (
    <div>
      <Field label="Node id" value={node.id} mono copy={node.id} />
      <Field label="Created" value={relTime(node.createdAt)} />
    </div>
  );
}

/** §49 — the request inspection panel. */
function RequestPanel({ requestId }: { requestId: string }) {
  const [detail, setDetail] = useState<RequestDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    const load = async () => {
      try {
        const data = await api<RequestDetail>(`/v1/requests/${requestId}`);
        if (cancelled) return;
        setDetail(data);
        setError(null);
        // Keep polling only while something is still moving.
        if (data.request.proofStatus === "PROVING" || data.request.status === "PROVIDER_RUNNING") {
          timer = setTimeout(() => void load(), 600);
        }
      } catch (err) {
        if (!cancelled) setError((err as Error).message);
      }
    };
    void load();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [requestId]);

  if (error) return <div className="text-[12.5px] text-denied">{error}</div>;
  if (!detail) return <div className="text-[12.5px] text-ink-3">Loading…</div>;

  const r = detail.request;
  const trust = TRUST_STATUS_META[r.trustStatus] ?? null;

  return (
    <div className="space-y-4">
      {trust && (
        <div className={`rounded-[11px] border px-3 py-2.5 ${TONE_CLASS[trust.tone]}`}>
          <div className="text-[12.5px] font-semibold">{trust.label}</div>
          <div className="mt-0.5 text-[11px] opacity-75">{trust.detail}</div>
        </div>
      )}

      <div>
        <SectionLabel>Request</SectionLabel>
        <div className="mt-2">
          <Field label="Request id" value={shortHash(r.id, 10, 6)} mono copy={r.id} />
          <Field
            label="Commitment"
            value={shortHash(r.commitment, 10, 6)}
            mono
            copy={r.commitment ?? ""}
          />
          <Field label="Prompt" value="PRIVATE" tone="private" />
          <Field label="Response" value="PRIVATE" tone="private" />
          <Field label="Privacy mode" value={r.privacyMode} />
          <Field label="Received" value={relTime(r.createdAt)} />
        </div>
      </div>

      <div>
        <SectionLabel>Policy</SectionLabel>
        <div className="mt-2">
          <Field label="Policy" value="Safety Policy v1" />
          <Field label="Policy id" value={shortHash(r.policyId, 8, 6)} mono copy={r.policyId ?? ""} />
          <Field
            label="Result"
            value={r.policyResult ?? "—"}
            tone={r.policyResult === "ALLOW" ? "verified" : r.policyResult === "DENY" ? "denied" : undefined}
          />
          <Field label="Evaluation" value={ms(r.timings.policyMs)} />
        </div>
      </div>

      <div>
        <SectionLabel>Policy proof</SectionLabel>
        <div className="mt-2">
          <Field
            label="Status"
            value={detail.proof?.status ?? r.proofStatus}
            tone={
              r.proofStatus === "VERIFIED"
                ? "verified"
                : r.proofStatus === "FAILED"
                  ? "denied"
                  : "pending"
            }
          />
          {detail.proof && (
            <>
              <Field label="Proof system" value={detail.proof.proofSystem} mono />
              <Field
                label="Guest image"
                value={shortHash(detail.proof.guestImageId, 8, 6)}
                mono
                copy={detail.proof.guestImageId}
              />
              <Field label="Proof time" value={ms(detail.proof.proofMs)} />
              {detail.proof.error && (
                <Field label="Error" value={detail.proof.error} tone="denied" />
              )}
            </>
          )}
        </div>
        {r.proofStatus === "VERIFIED" && (
          <Link
            href={`/receipts/${r.id}`}
            className="mt-2 inline-flex text-[12px] font-medium text-private hover:underline"
          >
            Verify this receipt independently →
          </Link>
        )}
      </div>

      {r.contributor && (
        <div>
          <SectionLabel>Compute supplied by</SectionLabel>
          <div className="mt-2">
            <Field label="Contributor" value={r.contributor.displayName} />
            <Field label="Credential" value={shortHash(r.credentialId, 10, 4)} mono />
            <Field label="Provider" value={r.provider?.toUpperCase() ?? "—"} />
            <Field label="Model" value={r.model} mono />
            <div className="mt-2 rounded-[10px] border border-hairline bg-abyss px-3 py-2 text-[11px] text-ink-3">
              {r.contributor.displayName} supplied the capacity for this request and cannot see its
              contents.
            </div>
          </div>
        </div>
      )}

      <div>
        <SectionLabel>Usage</SectionLabel>
        <div className="mt-2">
          <Field label="Input tokens" value={num(r.usage.inputTokens)} />
          <Field label="Output tokens" value={num(r.usage.outputTokens)} />
        </div>
      </div>

      <div>
        <SectionLabel>Timing</SectionLabel>
        <div className="mt-2">
          <Field label="Policy" value={ms(r.timings.policyMs)} />
          <Field label="Provider" value={ms(r.timings.providerMs)} />
          <Field label="Proof (parallel)" value={ms(r.timings.proofMs)} tone="muted" />
          <Field label="Perceived total" value={ms(r.timings.totalMs)} />
        </div>
        {r.timings.proofMs > 0 && r.timings.totalMs > 0 && (
          <div className="mt-2 rounded-[10px] border border-hairline bg-abyss px-3 py-2 text-[11px] text-ink-3">
            Proving took {ms(r.timings.proofMs)} but ran alongside inference, so the caller waited{" "}
            {ms(r.timings.totalMs)} instead of {ms(r.timings.proofMs + (r.timings.providerMs ?? 0))}.
          </div>
        )}
      </div>

      {detail.attempts.length > 0 && (
        <div>
          <SectionLabel>Provider attempts</SectionLabel>
          <div className="mt-2 space-y-1.5">
            {detail.attempts.map((a) => (
              <div
                key={String(a.id)}
                className="flex items-center justify-between rounded-[9px] border border-hairline bg-abyss px-2.5 py-1.5"
              >
                <span className="mono text-[11px] text-ink-2">
                  #{String(a.attempt_number)} · {shortHash(String(a.credential_id), 8, 4)}
                </span>
                <Badge tone={a.status === "SUCCESS" ? "verified" : "denied"}>
                  {a.status === "SUCCESS"
                    ? `${String(a.http_status)} · ${ms(Number(a.latency_ms))}`
                    : `${String(a.classification ?? "failed")}`}
                </Badge>
              </div>
            ))}
          </div>
        </div>
      )}

      {r.errorCode && (
        <div className="rounded-[11px] border border-denied/30 bg-denied/8 px-3 py-2.5">
          <div className="mono text-[12px] font-semibold text-denied">{r.errorCode}</div>
        </div>
      )}
    </div>
  );
}

/** §71 step 2 — clicking a credential shows the constraints, never the key. */
function CredentialPanel({
  node,
  nodes,
  links,
  onSelect,
}: {
  node: GraphNode;
  nodes: GraphNode[];
  links: GraphLink[];
  onSelect: (id: string | null) => void;
}) {
  const credentialId = node.id.replace(/^cred:/, "");
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    void api<{ data: Array<Record<string, unknown>> }>("/v1/credentials")
      .then((res) => setDetail(res.data.find((c) => c.id === credentialId) ?? null))
      .catch(() => setDetail(null));
  }, [credentialId]);

  const owner = links.find((l) => l.target === node.id && l.type === "CONTRIBUTED")?.source;
  const ownerNode = owner ? nodes.find((n) => n.id === owner) : null;
  const capability = detail?.capability as
    | { allowedModels: string[]; allowedPolicyIds: string[]; version: number }
    | undefined;
  const today = detail?.today as { requests: number; estimatedCostUsd: number } | undefined;
  const total = detail?.total as { requests: number; tokens: number; estimatedCostUsd: number } | undefined;
  const limits = detail?.operationalLimits as
    | { dailyUsd: number | null; dailyRequests: number | null; enforcement: string }
    | undefined;

  return (
    <div className="space-y-4">
      <div className="rounded-[11px] border border-private/25 bg-private/[0.07] px-3 py-2.5">
        <div className="text-[12.5px] font-semibold text-private">Raw API key: inaccessible</div>
        <div className="mt-0.5 text-[11px] text-private/70">
          Decrypted only inside the enclave, under the vault key released to the approved measurement.
        </div>
      </div>

      <div>
        <SectionLabel>Credential</SectionLabel>
        <div className="mt-2">
          <Field label="Credential id" value={shortHash(credentialId, 10, 4)} mono copy={credentialId} />
          {ownerNode && (
            <div className="flex items-baseline justify-between gap-4 border-b border-hairline/60 py-[7px]">
              <span className="text-[12px] text-ink-3">Contributed by</span>
              <button
                onClick={() => onSelect(ownerNode.id)}
                className="text-[12.5px] font-medium text-contributor hover:underline"
              >
                {ownerNode.label}
              </button>
            </div>
          )}
          <Field label="Provider" value={String(detail?.provider ?? "—").toUpperCase()} />
          <Field label="Status" value={String(detail?.status ?? node.status ?? "—")} />
          <Field
            label="Key fingerprint"
            value={shortHash(String(detail?.keyFingerprint ?? ""), 8, 4)}
            mono
          />
        </div>
      </div>

      {capability && (
        <div>
          <SectionLabel>Signed capability</SectionLabel>
          <div className="mt-2">
            <Field label="Version" value={`v${capability.version}`} />
            <Field label="Allowed models" value={capability.allowedModels.join(", ")} mono />
            <Field
              label="Required policy"
              value={shortHash(capability.allowedPolicyIds[0], 8, 6)}
              mono
              copy={capability.allowedPolicyIds[0]}
            />
          </div>
          <div className="mt-2">
            <Check
              pass
              name="Capability signed by the attested enclave"
              detail="The coordinator cannot widen these constraints without detection."
            />
          </div>
        </div>
      )}

      {limits && (
        <div>
          <SectionLabel>Operational limits</SectionLabel>
          <div className="mt-2">
            <Field
              label="Daily cap"
              value={limits.dailyUsd !== null ? `$${limits.dailyUsd.toFixed(2)}` : "none"}
            />
            <Field label="Daily requests" value={limits.dailyRequests ?? "none"} />
            <Field label="Enforcement" value={limits.enforcement} tone="pending" />
          </div>
        </div>
      )}

      {(today || total) && (
        <div>
          <SectionLabel>Usage</SectionLabel>
          <div className="mt-2">
            {today && (
              <>
                <Field label="Today · requests" value={num(today.requests)} />
                <Field label="Today · estimated" value={usdFromDollars(today.estimatedCostUsd)} />
              </>
            )}
            {total && (
              <>
                <Field label="Total · requests" value={num(total.requests)} />
                <Field label="Total · tokens" value={num(total.tokens)} />
                <Field label="Total · estimated" value={usdFromDollars(total.estimatedCostUsd)} />
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ContributorPanel({
  node,
  nodes,
  links,
  onSelect,
}: {
  node: GraphNode;
  nodes: GraphNode[];
  links: GraphLink[];
  onSelect: (id: string | null) => void;
}) {
  const contributorId = node.id.replace(/^contrib:/, "");
  const credentialIds = links
    .filter((l) => l.source === node.id && l.type === "CONTRIBUTED")
    .map((l) => l.target);
  const served = links.filter((l) => l.type === "ROUTED_THROUGH" && credentialIds.includes(l.target));

  return (
    <div className="space-y-4">
      <div>
        <SectionLabel>Contributor</SectionLabel>
        <div className="mt-2">
          <Field label="Contributor id" value={shortHash(contributorId, 10, 4)} mono copy={contributorId} />
          <Field label="Credentials" value={credentialIds.length} />
          <Field label="Requests served" value={served.length} />
          <Field label="Sees request contents" value="NO" tone="verified" />
        </div>
      </div>

      <div>
        <SectionLabel>Contributed capacity</SectionLabel>
        <div className="mt-2 space-y-1.5">
          {credentialIds.map((id) => {
            const cred = nodes.find((n) => n.id === id);
            if (!cred) return null;
            return (
              <button
                key={id}
                onClick={() => onSelect(id)}
                className="flex w-full items-center justify-between rounded-[9px] border border-hairline bg-abyss px-2.5 py-2 text-left transition hover:border-credential/40"
              >
                <span className="text-[12.5px] text-ink-2">{cred.label}</span>
                <span className="mono text-[10.5px] text-ink-4">
                  {String(cred.meta?.provider ?? "").toUpperCase()}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      <Link
        href="/dashboard"
        className="inline-flex text-[12px] font-medium text-private hover:underline"
      >
        Open contributor dashboard →
      </Link>
    </div>
  );
}

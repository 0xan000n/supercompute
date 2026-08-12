"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Shell } from "@/components/Shell";
import { Badge, Button, Empty, Field, Panel, SectionLabel, Stat } from "@/components/ui";
import { api, usePolled } from "@/lib/api";
import { num, relTime, shortHash, usdFromDollars } from "@/lib/format";

interface Credential {
  id: string;
  contributorId: string;
  label: string;
  provider: string;
  status: string;
  weight: number;
  rawCredential: string;
  keyFingerprint: string;
  capability: { allowedModels: string[]; allowedPolicyIds: string[]; version: number };
  capabilitySignature: string;
  createdAt: string;
  lastUsedAt: string | null;
  cooldownUntil: string | null;
  failureCount: number;
  operationalLimits: { dailyUsd: number | null; dailyRequests: number | null; enforcement: string };
  today: { requests: number; estimatedCostUsd: number };
  total: { requests: number; tokens: number; estimatedCostUsd: number };
}

interface Contributor {
  id: string;
  display_name: string;
  status: string;
  credential_count: number;
}

/** §50 — the contributor dashboard: full accounting, zero request contents. */
export default function DashboardPage() {
  const { data: contributors } = usePolled<{ data: Contributor[] }>("/v1/contributors", 6000);
  const { data: credentials, refresh } = usePolled<{ data: Credential[] }>("/v1/credentials", 3000);
  const [selected, setSelected] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const activeContributor = selected ?? contributors?.data[0]?.id ?? null;
  const mine = useMemo(
    () => (credentials?.data ?? []).filter((c) => c.contributorId === activeContributor),
    [credentials, activeContributor]
  );

  const mutate = async (id: string, body: Record<string, unknown>) => {
    setBusyId(id);
    try {
      await api(`/v1/credentials/${id}`, { method: "PATCH", body: JSON.stringify(body) });
      refresh();
    } finally {
      setBusyId(null);
    }
  };

  const totals = mine.reduce(
    (acc, c) => ({
      requests: acc.requests + c.total.requests,
      tokens: acc.tokens + c.total.tokens,
      cost: acc.cost + c.total.estimatedCostUsd,
      todayRequests: acc.todayRequests + c.today.requests,
    }),
    { requests: 0, tokens: 0, cost: 0, todayRequests: 0 }
  );

  return (
    <Shell>
      <div className="mx-auto max-w-[1180px]">
        <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1 className="text-[22px] font-semibold tracking-[-0.02em]">Contributors</h1>
            <p className="mt-1 text-[13px] text-ink-3">
              What each contributor can see about the capacity they gave: everything except the
              requests it served.
            </p>
          </div>
          <Link
            href="/contribute"
            className="rounded-[10px] border border-private/35 bg-private/12 px-3.5 py-2 text-[12.5px] font-semibold text-private hover:bg-private/20"
          >
            Contribute capacity
          </Link>
        </header>

        {contributors && contributors.data.length === 0 && (
          <Empty>
            No contributors yet. Run <span className="mono mx-1 text-ink-2">pnpm seed</span> or use
            the contribute flow.
          </Empty>
        )}

        {contributors && contributors.data.length > 0 && (
          <>
            <div className="mb-4 flex flex-wrap gap-1.5">
              {contributors.data.map((c) => (
                <button
                  key={c.id}
                  onClick={() => setSelected(c.id)}
                  className={`rounded-[10px] border px-3 py-2 text-left transition ${
                    activeContributor === c.id
                      ? "border-contributor/45 bg-contributor/[0.09]"
                      : "border-hairline hover:border-ink-4"
                  }`}
                >
                  <div
                    className={`text-[13px] font-semibold ${
                      activeContributor === c.id ? "text-contributor" : "text-ink-2"
                    }`}
                  >
                    {c.display_name}
                  </div>
                  <div className="mt-0.5 text-[10.5px] text-ink-4">
                    {c.credential_count} credential{c.credential_count === 1 ? "" : "s"}
                  </div>
                </button>
              ))}
            </div>

            <Panel className="mb-4 p-4">
              <div className="grid grid-cols-2 gap-5 sm:grid-cols-4">
                <Stat label="Requests served" value={num(totals.requests)} />
                <Stat label="Tokens" value={num(totals.tokens)} />
                <Stat label="Estimated spend" value={usdFromDollars(totals.cost)} tone="pending" />
                <Stat label="Today" value={num(totals.todayRequests)} unit="requests" />
              </div>
              <p className="mt-3 border-t border-hairline pt-2.5 text-[11px] text-ink-4">
                Spend is an estimate derived from token counts, recorded per request in a signed
                compute receipt. It is accounting, not a cryptographic guarantee of billing.
              </p>
            </Panel>

            <div className="space-y-3">
              {mine.length === 0 && <Empty>This contributor has no credentials yet.</Empty>}
              {mine.map((credential) => (
                <Panel key={credential.id} className="p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <h2 className="text-[15px] font-semibold tracking-[-0.01em]">
                          {credential.label}
                        </h2>
                        <Badge
                          tone={
                            credential.status === "ACTIVE"
                              ? "verified"
                              : credential.status === "DISABLED"
                                ? "denied"
                                : "neutral"
                          }
                          dot
                        >
                          {credential.status}
                        </Badge>
                        {credential.cooldownUntil &&
                          Date.parse(credential.cooldownUntil) > Date.now() && (
                            <Badge tone="pending" dot pulse>
                              COOLDOWN
                            </Badge>
                          )}
                      </div>
                      <div className="mono mt-1 text-[11px] text-ink-4">
                        {credential.provider.toUpperCase()} · {shortHash(credential.id, 10, 4)} ·
                        added {relTime(credential.createdAt)}
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-1.5">
                      <Button
                        variant={credential.status === "ACTIVE" ? "ghost" : "secondary"}
                        busy={busyId === credential.id}
                        onClick={() =>
                          mutate(credential.id, {
                            status: credential.status === "ACTIVE" ? "DISABLED" : "ACTIVE",
                          })
                        }
                        className="!px-3 !py-1.5 !text-[12px]"
                      >
                        {credential.status === "ACTIVE" ? "Disable" : "Enable"}
                      </Button>
                      <Button
                        variant="ghost"
                        busy={busyId === credential.id}
                        onClick={() =>
                          mutate(credential.id, { weight: credential.weight === 1 ? 2 : 1 })
                        }
                        className="!px-3 !py-1.5 !text-[12px]"
                      >
                        Weight ×{credential.weight === 1 ? 2 : 1}
                      </Button>
                    </div>
                  </div>

                  <div className="mt-3 grid gap-x-6 gap-y-0 sm:grid-cols-2">
                    <div>
                      <Field label="Raw credential" value="HIDDEN" tone="private" />
                      <Field
                        label="Key fingerprint"
                        value={shortHash(credential.keyFingerprint, 8, 4)}
                        mono
                      />
                      <Field label="TEE custody" value="VERIFIED" tone="verified" />
                      <Field label="Required policy" value="Safety Policy v1" />
                      <Field
                        label="Capability"
                        value={`v${credential.capability.version} · signed`}
                        tone="verified"
                      />
                      <Field
                        label="Allowed models"
                        value={credential.capability.allowedModels
                          .map((m) => m.replace("ctn/", ""))
                          .join(", ")}
                        mono
                      />
                    </div>
                    <div>
                      <Field label="Today · requests" value={num(credential.today.requests)} />
                      <Field
                        label="Today · estimated"
                        value={usdFromDollars(credential.today.estimatedCostUsd)}
                      />
                      <Field
                        label="Daily cap"
                        value={
                          credential.operationalLimits.dailyUsd !== null
                            ? `$${credential.operationalLimits.dailyUsd.toFixed(2)} · ${credential.operationalLimits.enforcement}`
                            : "none"
                        }
                        tone="pending"
                      />
                      <Field label="Total · requests" value={num(credential.total.requests)} />
                      <Field label="Total · tokens" value={num(credential.total.tokens)} />
                      <Field label="Last used" value={relTime(credential.lastUsedAt)} />
                    </div>
                  </div>

                  {credential.failureCount > 0 && (
                    <div className="mt-2.5 rounded-[10px] border border-pending/25 bg-pending/[0.06] px-3 py-2 text-[11.5px] text-pending/85">
                      {credential.failureCount} provider failure
                      {credential.failureCount === 1 ? "" : "s"} recorded. A 401 disables a
                      credential automatically; a 429 puts it in cooldown and the next request routes
                      elsewhere.
                    </div>
                  )}
                </Panel>
              ))}
            </div>

            <Panel className="mt-4 p-4">
              <SectionLabel>Requests you served</SectionLabel>
              <p className="mt-2 text-[12.5px] leading-relaxed text-ink-3">
                You can see that your capacity served{" "}
                <span className="text-ink">{num(totals.requests)}</span> requests, how many tokens
                each consumed, and a signed receipt for every one of them. You cannot see what any of
                them asked. That asymmetry is the point of the network.
              </p>
              <Link
                href="/"
                className="mt-2.5 inline-flex text-[12px] font-medium text-private hover:underline"
              >
                Trace your capacity through the graph →
              </Link>
            </Panel>
          </>
        )}
      </div>
    </Shell>
  );
}

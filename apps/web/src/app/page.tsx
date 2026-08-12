"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Shell } from "@/components/Shell";
import { NetworkGraph } from "@/components/graph/NetworkGraph";
import { Inspector } from "@/components/Inspector";
import { windowGraph } from "@/components/graph/window";
import { requestPath } from "@/components/graph/path";
import { OfflineNotice } from "@/components/OfflineNotice";
import { Badge, Panel, SectionLabel, Stat } from "@/components/ui";
import { useLiveGraph, usePolled } from "@/lib/api";
import { ms, num } from "@/lib/format";
import { NODE_STYLE } from "@/lib/theme";
import type { GraphNodeType } from "@ctn/protocol";

interface Stats {
  counts: {
    requests: number;
    complete: number;
    denied: number;
    failed: number;
    proofsVerified: number;
    proofsFailed: number;
    contributors: number;
    credentials: number;
  };
  latency: Record<string, { p50: number | null; p95: number | null }>;
  parallelism: {
    proofP50Ms: number | null;
    providerP50Ms: number | null;
    perceivedTotalP50Ms: number | null;
    perceivedAddedLatencyP50Ms: number | null;
    serializedWouldBeP50Ms: number | null;
  };
}

const LEGEND: GraphNodeType[] = [
  "Contributor",
  "Credential",
  "Request",
  "TEEWorker",
  "Policy",
  "Proof",
  "Provider",
  "Model",
  "Response",
  "ComputeReceipt",
];

const WINDOW_OPTIONS: Array<{ label: string; value: number | null }> = [
  { label: "10", value: 10 },
  { label: "25", value: 25 },
  { label: "All", value: null },
];

export default function NetworkPage() {
  const { nodes: allNodes, links: allLinks, connected, recent } = useLiveGraph();
  const { data: stats } = usePolled<Stats>("/v1/stats", 4000);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isolate, setIsolate] = useState(false);
  const [windowSize, setWindowSize] = useState<number | null>(10);

  // Landmarks always render; only request flows are windowed (see window.ts).
  const windowed = useMemo(
    () => windowGraph(allNodes, allLinks, windowSize),
    [allNodes, allLinks, windowSize]
  );
  const { nodes, links } = windowed;

  const selected = useMemo(
    () => allNodes.find((n) => n.id === selectedId) ?? null,
    [allNodes, selectedId]
  );

  // §48 — the selected request's path, with shared hubs treated as terminals so
  // the highlight does not leak into every other request. See graph/path.ts.
  const focusPath = useMemo(
    () => (isolate && selectedId ? requestPath(selectedId, nodes, links) : undefined),
    [isolate, selectedId, nodes, links]
  );

  const latestRequests = allNodes
    .filter((n) => n.type === "Request")
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
    .slice(0, 14);

  return (
    <Shell bleed>
      <div className="flex h-full min-h-0">
        {/* ---- left rail: what the network is doing ---- */}
        <aside className="hidden w-[268px] shrink-0 flex-col gap-4 overflow-y-auto border-r border-hairline p-4 xl:flex">
          <div>
            <h1 className="text-[17px] font-semibold leading-tight tracking-[-0.015em]">
              Compute provenance
            </h1>
            <p className="mt-1.5 text-[12px] leading-relaxed text-ink-3">
              Every request that crosses this network appears here as a path. The prompt never does.
            </p>
          </div>

          {stats && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <Stat label="Requests" value={num(stats.counts.requests)} />
                <Stat
                  label="Proofs verified"
                  value={num(stats.counts.proofsVerified)}
                  tone="verified"
                />
                <Stat label="Contributors" value={num(stats.counts.contributors)} />
                <Stat label="Denied" value={num(stats.counts.denied)} tone="denied" />
              </div>

              <Panel className="p-3">
                <SectionLabel>Latency p50</SectionLabel>
                <div className="mt-2 space-y-1.5">
                  <Row label="Policy" value={ms(stats.latency.policy?.p50)} />
                  <Row label="Provider" value={ms(stats.latency.provider?.p50)} />
                  <Row label="Proof (parallel)" value={ms(stats.latency.proof?.p50)} muted />
                  <Row label="Perceived total" value={ms(stats.latency.overall?.p50)} strong />
                </div>
                {stats.parallelism.serializedWouldBeP50Ms !== null && (
                  <p className="mt-2.5 border-t border-hairline pt-2 text-[10.5px] leading-relaxed text-ink-4">
                    Serialized, proof + provider would be{" "}
                    <span className="text-ink-3">{ms(stats.parallelism.serializedWouldBeP50Ms)}</span>.
                    Running them in parallel keeps the caller at{" "}
                    <span className="text-verified">{ms(stats.parallelism.perceivedTotalP50Ms)}</span>.
                  </p>
                )}
              </Panel>
            </>
          )}

          <div>
            <SectionLabel>Recent requests</SectionLabel>
            <div className="mt-2 space-y-1">
              {latestRequests.length === 0 && (
                <p className="text-[11.5px] text-ink-4">
                  No requests yet.{" "}
                  <Link href="/playground" className="text-private hover:underline">
                    Send one →
                  </Link>
                </p>
              )}
              {latestRequests.map((node) => (
                <button
                  key={node.id}
                  onClick={() => {
                    setSelectedId(node.id);
                    // Selecting an older request widens the window so its path
                    // is actually on screen rather than silently filtered out.
                    if (!nodes.some((n) => n.id === node.id)) setWindowSize(null);
                  }}
                  className={`flex w-full items-center justify-between gap-2 rounded-lg px-2 py-1.5 text-left transition ${
                    selectedId === node.id ? "bg-surface-3" : "hover:bg-surface-2"
                  }`}
                >
                  <span className="mono truncate text-[11px] text-ink-2">{node.label}</span>
                  {/*
                    FAILED is terminal, so it must not pulse: the pulse is what
                    says "still working", and a dead request wearing it is the UI
                    telling the room something the database disagrees with. Rose
                    for both terminal-bad states, matching statusColor() in
                    lib/theme.ts so the list dot and the graph node agree.
                  */}
                  <span
                    className={`size-1.5 shrink-0 rounded-full ${
                      node.status === "COMPLETE"
                        ? "bg-verified"
                        : node.status === "DENIED" || node.status === "FAILED"
                          ? "bg-denied"
                          : "bg-pending animate-pulse-soft"
                    }`}
                  />
                </button>
              ))}
            </div>
          </div>

          <div className="mt-auto">
            <SectionLabel>Legend</SectionLabel>
            <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1">
              {LEGEND.map((type) => (
                <div key={type} className="flex items-center gap-1.5">
                  <span
                    className="size-1.5 rounded-full"
                    style={{ background: NODE_STYLE[type].color }}
                  />
                  <span className="truncate text-[10.5px] text-ink-3">{NODE_STYLE[type].short}</span>
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* ---- the graph ---- */}
        <div className="relative min-w-0 flex-1">
          <div className="absolute inset-x-0 top-0 z-10 flex items-center gap-2 px-4 py-3">
            <Badge tone={connected ? "verified" : "pending"} dot pulse={!connected}>
              {connected ? "LIVE" : "CONNECTING"}
            </Badge>
            <span className="text-[11px] text-ink-4">
              {nodes.length} nodes · {links.length} edges
              {windowed.hiddenRequests > 0 && (
                <span className="text-ink-4"> · {windowed.hiddenRequests} older hidden</span>
              )}
            </span>
            <div className="ml-auto flex items-center gap-2">
              <div className="flex items-center gap-1 rounded-lg border border-hairline p-[2px]">
                <span className="px-1.5 text-[10px] font-semibold tracking-[0.06em] text-ink-4">
                  REQUESTS
                </span>
                {WINDOW_OPTIONS.map((option) => (
                  <button
                    key={option.label}
                    onClick={() => setWindowSize(option.value)}
                    className={`rounded-[6px] px-2 py-1 text-[11px] font-medium transition ${
                      windowSize === option.value
                        ? "bg-surface-3 text-ink"
                        : "text-ink-4 hover:text-ink-2"
                    }`}
                  >
                    {option.label}
                  </button>
                ))}
              </div>
              <button
                onClick={() => setIsolate((v) => !v)}
                disabled={!selectedId}
                className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition disabled:opacity-35 ${
                  isolate
                    ? "border-private/45 bg-private/12 text-private"
                    : "border-hairline text-ink-3 hover:text-ink-2"
                }`}
              >
                Isolate path
              </button>
              <Link
                href="/playground"
                className="rounded-lg border border-private/35 bg-private/12 px-2.5 py-1.5 text-[11px] font-semibold text-private transition hover:bg-private/20"
              >
                Send a private request
              </Link>
            </div>
          </div>

          <NetworkGraph
            nodes={nodes}
            links={links}
            recent={recent}
            selectedId={selectedId}
            onSelect={setSelectedId}
            focusPath={focusPath}
            className="h-full w-full"
          />

          {nodes.length === 0 && (
            <div className="absolute inset-0 grid place-items-center overflow-y-auto p-6">
              {stats ? (
                <div className="text-center">
                  <div className="text-[13px] text-ink-3">No requests yet.</div>
                  <div className="mt-1 text-[11.5px] text-ink-4">
                    Run <span className="mono text-ink-3">pnpm seed</span> to onboard five
                    contributors, or send one from the playground.
                  </div>
                </div>
              ) : (
                <OfflineNotice />
              )}
            </div>
          )}
        </div>

        {/* ---- inspector ---- */}
        <aside className="hidden w-[352px] shrink-0 border-l border-hairline lg:block">
          <Inspector node={selected} nodes={nodes} links={links} onSelect={setSelectedId} />
        </aside>
      </div>
    </Shell>
  );
}

function Row({
  label,
  value,
  muted,
  strong,
}: {
  label: string;
  value: string;
  muted?: boolean;
  strong?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <span className={`text-[11.5px] ${muted ? "text-ink-4" : "text-ink-3"}`}>{label}</span>
      <span
        className={`mono text-[11.5px] tabular-nums ${
          strong ? "font-semibold text-verified" : muted ? "text-ink-3" : "text-ink-2"
        }`}
      >
        {value}
      </span>
    </div>
  );
}

"use client";

import { useEffect, useMemo, useState } from "react";
import {
  verifyInsightsBulletin,
  type Facet,
  type InsightsFacetCount,
  type SignedInsightsBulletinV1,
} from "@ctn/protocol";
import { Shell } from "@/components/Shell";
import { Badge, Empty, Panel, SectionLabel, Stat } from "@/components/ui";
import { usePolled } from "@/lib/api";
import { num, relTime, shortHash } from "@/lib/format";

/**
 * Phase 3 — Clio-lite `/insights` (spec §8/§9). The VISIBLE payoff of the
 * in-enclave classifier: what the network's compute is used for, and what it
 * refused, in aggregate — without any prompt ever leaving the enclave.
 *
 * The honesty labels here are LOAD-BEARING, not decoration. Nothing on this page
 * may read as an LLM classification, a real embedding, or anonymity — because
 * none of those is what happened. What actually happened:
 *   - classification is a HEURISTIC keyword scan (safety facets = the ZK-proven
 *     policy category that denied the request), run in-enclave on the plaintext
 *     already decrypted for the gate. No LLM, no embedding, no network.
 *   - the scatter positions each facet in a fixed region for legibility. Dots
 *     near each other share a facet and NOTHING more — this is grouping, not
 *     semantic embedding.
 *   - facets below K_MIN requests are threshold-suppressed (folded into `other`),
 *     a visible absence, NOT anonymity.
 *
 * The bulletin is enclave-signed; the signature is verified in THIS browser
 * against the enclave signing key from `/v1/attestation` (see `signatureState`).
 */

// ---------------------------------------------------------------------------
// Facet display map. Defined HERE for the web (label / color / isSafety) — the
// authoritative enum lives in services/tee-sim/src/insights/facets.ts and
// @ctn/protocol; we deliberately do NOT import from services/. Colors stay in
// the app's two semantic families: SAFETY facets warm (rose/red — the "denied"
// hue), BENIGN facets cool (cyan/emerald/violet). That two-tone split is what
// makes the scatter read as a warm "refused" cluster beside a cool "allowed" one.
// ---------------------------------------------------------------------------

interface FacetMeta {
  label: string;
  color: string;
  isSafety: boolean;
  /** A fixed home position in the 1000x520 scatter viewBox (grouping, not layout). */
  home: readonly [number, number];
}

const FACET_META: Record<Facet, FacetMeta> = {
  // Safety — warm, clustered on the left. A DENY's facet is the deciding P-category.
  weapons: { label: "Weapons", color: "#fb7185", isSafety: true, home: [155, 120] },
  malware_cyber: { label: "Malware / cyber", color: "#fb923c", isSafety: true, home: [125, 260] },
  phishing_fraud: { label: "Phishing / fraud", color: "#f472b6", isSafety: true, home: [235, 200] },
  violence: { label: "Violence", color: "#f87171", isSafety: true, home: [250, 335] },
  self_harm: { label: "Self-harm", color: "#fca5a5", isSafety: true, home: [140, 400] },
  csam: { label: "CSAM", color: "#e11d48", isSafety: true, home: [265, 430] },
  // Benign — cool, spread across the right. The keyword classifier's outputs.
  coding: { label: "Coding", color: "#22d3ee", isSafety: false, home: [545, 130] },
  writing: { label: "Writing", color: "#38bdf8", isSafety: false, home: [915, 145] },
  research: { label: "Research", color: "#34d399", isSafety: false, home: [470, 300] },
  data_analysis: { label: "Data analysis", color: "#2dd4bf", isSafety: false, home: [670, 300] },
  education: { label: "Education", color: "#60a5fa", isSafety: false, home: [560, 445] },
  business: { label: "Business", color: "#818cf8", isSafety: false, home: [800, 430] },
  creative: { label: "Creative", color: "#a78bfa", isSafety: false, home: [760, 130] },
  translation: { label: "Translation", color: "#6ee7b7", isSafety: false, home: [905, 275] },
  conversation: { label: "Conversation", color: "#94a3b8", isSafety: false, home: [910, 415] },
  technical_ops: { label: "Technical ops", color: "#4ade80", isSafety: false, home: [660, 460] },
  other: { label: "Other", color: "#6b7288", isSafety: false, home: [0, 0] },
};

const total = (f: InsightsFacetCount) => f.allow + f.deny;

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

/** The minimal attestation shape we read: only the enclave signing key. */
interface AttestationShape {
  bundle: { enclaveSigningPublicKey: string };
}

export default function InsightsPage() {
  const { data: bulletin } = usePolled<SignedInsightsBulletinV1>("/v1/insights", 8000);
  // The enclave signing key we verify the bulletin against, straight from the
  // attestation bundle — the same key the ProofBeat / AttestationPanel trust.
  const { data: attestation } = usePolled<AttestationShape>("/v1/attestation", 30_000);
  const signingKey = attestation?.bundle.enclaveSigningPublicKey ?? null;

  // Verify the enclave signature IN THIS BROWSER. `null` = can't check yet (no
  // key or no bulletin); true/false = the ed25519 verdict over the canonical form.
  const signatureOk = useMemo<boolean | null>(() => {
    if (!bulletin || !signingKey) return null;
    try {
      return verifyInsightsBulletin(bulletin, signingKey);
    } catch {
      return false;
    }
  }, [bulletin, signingKey]);

  const facets = bulletin?.facets ?? [];
  const populated = facets.length > 0;

  return (
    <Shell>
      <div className="mx-auto max-w-[1180px]">
        <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-[22px] font-semibold tracking-[-0.02em]">Usage insights</h1>
            <p className="mt-1 max-w-[720px] text-[13px] leading-relaxed text-ink-3">
              What the network&rsquo;s compute is used for, and what it refused — in aggregate, and{" "}
              <span className="text-ink-2">classified locally</span> inside the enclave. Prompts never
              leave the confidential boundary; only these signed, threshold-suppressed counts do.
            </p>
          </div>
          <SignatureBadge state={signatureOk} keyHex={signingKey} />
        </header>

        {bulletin ? (
          <>
            <BulletinStrip bulletin={bulletin} />

            {populated ? (
              <>
                <FacetScatter facets={facets} otherCount={bulletin.otherCount} />
                <div className="mt-4 grid gap-4 lg:grid-cols-2">
                  <AllowDenyBreakdown facets={facets} />
                  <SafetyView facets={facets} />
                </div>
              </>
            ) : (
              <SuppressedState kMin={bulletin.kMin} otherCount={bulletin.otherCount} />
            )}

            <HonestyPanel kMin={bulletin.kMin} />
          </>
        ) : (
          <Panel className="p-6">
            <Empty>Waiting for the enclave bulletin…</Empty>
          </Panel>
        )}
      </div>
    </Shell>
  );
}

// ---------------------------------------------------------------------------
// Signature badge — the client-side verification verdict, stated plainly.
// ---------------------------------------------------------------------------

function SignatureBadge({ state, keyHex }: { state: boolean | null; keyHex: string | null }) {
  return (
    <div className="flex flex-col items-end gap-1">
      {state === true ? (
        <Badge tone="verified" dot>
          ENCLAVE SIGNATURE VERIFIED
        </Badge>
      ) : state === false ? (
        <Badge tone="denied" dot>
          SIGNATURE INVALID
        </Badge>
      ) : (
        <Badge tone="pending" dot pulse>
          VERIFYING SIGNATURE
        </Badge>
      )}
      <span className="mono text-[10px] text-ink-4">
        {keyHex ? `key ${shortHash(keyHex, 8, 6)}` : "fetching signing key…"}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Bulletin strip — the provenance of the numbers, at a glance.
// ---------------------------------------------------------------------------

function BulletinStrip({ bulletin }: { bulletin: SignedInsightsBulletinV1 }) {
  return (
    <Panel className="mb-4 p-4">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Requests classified" value={num(bulletin.windowRequests)} hint="since enclave boot" />
        <Stat
          label="Visible clusters"
          value={num(bulletin.facets.length)}
          tone="private"
          hint={`facets ≥ ${bulletin.kMin} requests`}
        />
        <Stat
          label="Suppressed facets"
          value={num(bulletin.suppressedFacets)}
          tone="pending"
          hint={`below ${bulletin.kMin} · folded into other`}
        />
        <Stat label="Generated" value={relTime(bulletin.generatedAt)} hint="enclave clock" />
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Facet cluster scatter — each facet a labelled region; dots (count-scaled,
// capped) sit in that region, colored by facet. Positions are FIXED for
// legibility. This is grouping, NOT a semantic embedding — dots near each other
// share a facet and nothing more.
// ---------------------------------------------------------------------------

const VB_W = 1000;
const VB_H = 520;
const DOT_CAP = 40;

/** Deterministic 32-bit hash of a string — seeds stable dot placement. */
function hashSeed(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/** mulberry32 — a small deterministic PRNG so the scatter never jumps on rerender. */
function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Dot {
  x: number;
  y: number;
  r: number;
  color: string;
  denied: boolean;
}

function FacetScatter({ facets, otherCount }: { facets: InsightsFacetCount[]; otherCount: number }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const shown = facets.filter((f) => f.facet !== "other");
  const anySafety = shown.some((f) => FACET_META[f.facet].isSafety);
  const anyBenign = shown.some((f) => !FACET_META[f.facet].isSafety);

  const dots = useMemo<Dot[]>(() => {
    const out: Dot[] = [];
    for (const f of shown) {
      const meta = FACET_META[f.facet];
      const t = total(f);
      const n = Math.min(t, DOT_CAP);
      const rng = mulberry32(hashSeed(f.facet));
      // Blob radius grows sublinearly with count so a big cluster reads bigger
      // without swamping the canvas.
      const spread = 26 + Math.sqrt(n) * 9;
      // Colour each dot by allow vs deny within its facet: a benign facet is all
      // allow, a safety facet all deny, but the model is honest either way.
      const denyRatio = t > 0 ? f.deny / t : 0;
      for (let i = 0; i < n; i++) {
        const ang = rng() * Math.PI * 2;
        const rad = Math.sqrt(rng()) * spread;
        out.push({
          x: meta.home[0] + Math.cos(ang) * rad,
          y: meta.home[1] + Math.sin(ang) * rad * 0.82,
          r: 2.4 + rng() * 1.7,
          color: meta.color,
          denied: rng() < denyRatio,
        });
      }
    }
    return out;
  }, [shown]);

  return (
    <Panel className="animate-rise overflow-hidden p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="size-1.5 rounded-full bg-private" />
          <SectionLabel>Facet clusters · grouped by locally-classified facet</SectionLabel>
        </div>
        <span className="mono text-[10px] text-ink-4">1 dot ≈ 1 request · capped at {DOT_CAP}/facet</span>
      </div>

      <div className="relative mt-3 w-full overflow-hidden rounded-[12px] border border-hairline bg-abyss">
        <svg viewBox={`0 0 ${VB_W} ${VB_H}`} className="block w-full" role="img" aria-label="Facet cluster scatter">
          <defs>
            {shown.map((f) => (
              <radialGradient key={f.facet} id={`glow-${f.facet}`}>
                <stop offset="0%" stopColor={FACET_META[f.facet].color} stopOpacity="0.14" />
                <stop offset="100%" stopColor={FACET_META[f.facet].color} stopOpacity="0" />
              </radialGradient>
            ))}
          </defs>

          {/* the two honest zones — a faint divider that says "grouped", nothing more */}
          {anySafety && anyBenign && (
            <line x1="355" y1="34" x2="355" y2={VB_H - 20} stroke="#1e2230" strokeWidth="1" strokeDasharray="3 6" />
          )}
          {anySafety && (
            <text x="30" y="34" className="mono" fill="#6b7288" fontSize="12" letterSpacing="1.5">
              SAFETY · refused at the gate
            </text>
          )}
          {anyBenign && (
            <text x="380" y="34" className="mono" fill="#6b7288" fontSize="12" letterSpacing="1.5">
              BENIGN · allowed
            </text>
          )}

          {/* per-facet glow region */}
          {shown.map((f) => {
            const meta = FACET_META[f.facet];
            const spread = 26 + Math.sqrt(Math.min(total(f), DOT_CAP)) * 9;
            return (
              <circle
                key={`region-${f.facet}`}
                cx={meta.home[0]}
                cy={meta.home[1]}
                r={spread + 28}
                fill={`url(#glow-${f.facet})`}
              />
            );
          })}

          {/* the dots — the actual requests, deterministically placed */}
          <g style={{ opacity: mounted ? 1 : 0, transition: "opacity 0.6s ease" }}>
            {dots.map((d, i) => (
              <circle
                key={i}
                cx={d.x}
                cy={d.y}
                r={d.r}
                fill={d.color}
                fillOpacity={d.denied ? 0.95 : 0.7}
                stroke={d.denied ? d.color : "none"}
                strokeOpacity={d.denied ? 0.5 : 0}
                strokeWidth={d.denied ? 1.4 : 0}
              />
            ))}
          </g>

          {/* facet labels + counts, over their cluster */}
          {shown.map((f) => {
            const meta = FACET_META[f.facet];
            return (
              <g key={`label-${f.facet}`}>
                <text
                  x={meta.home[0]}
                  y={meta.home[1] - 4}
                  textAnchor="middle"
                  fill="#eef0f6"
                  fontSize="13"
                  fontWeight="600"
                >
                  {meta.label}
                </text>
                <text
                  x={meta.home[0]}
                  y={meta.home[1] + 13}
                  textAnchor="middle"
                  className="mono"
                  fill={meta.color}
                  fontSize="11"
                >
                  {total(f)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <p className="mt-3 text-[11.5px] leading-relaxed text-ink-3">
        Each dot is one classified request, placed in its facet&rsquo;s fixed region.{" "}
        {/* prettier-ignore */}
        <span className="text-ink-2">Positioned by facet for legibility: this is grouping, not semantic embedding.</span>{" "}
        A dot&rsquo;s neighbours share its facet and nothing more. Denied requests are outlined.
        {otherCount > 0 && (
          <> {num(otherCount)} request{otherCount === 1 ? "" : "s"} fell below the threshold or into no facet and are not plotted.</>
        )}
      </p>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Allow vs deny breakdown — per facet, allow (verified/green) vs deny (rose).
// ---------------------------------------------------------------------------

function AllowDenyBreakdown({ facets }: { facets: InsightsFacetCount[] }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const rows = [...facets].filter((f) => f.facet !== "other").sort((a, b) => total(b) - total(a));
  const max = Math.max(1, ...rows.map(total));

  return (
    <Panel className="animate-rise p-4">
      <SectionLabel>Allow vs deny · by facet</SectionLabel>
      <div className="mt-3 space-y-2.5">
        {rows.map((f) => {
          const meta = FACET_META[f.facet];
          const t = total(f);
          const allowPct = mounted ? (f.allow / max) * 100 : 0;
          const denyPct = mounted ? (f.deny / max) * 100 : 0;
          return (
            <div key={f.facet}>
              <div className="flex items-baseline justify-between gap-3">
                <span className="flex items-center gap-2 text-[12px] text-ink-2">
                  <span className="size-2 rounded-[3px]" style={{ background: meta.color }} />
                  {meta.label}
                  {meta.isSafety && (
                    <span className="rounded border border-denied/30 px-1 py-px text-[8.5px] font-semibold uppercase tracking-[0.05em] text-denied">
                      safety
                    </span>
                  )}
                </span>
                <span className="mono text-[11px] text-ink-4 tabular-nums">
                  {f.allow > 0 && <span className="text-verified">{f.allow} allow</span>}
                  {f.allow > 0 && f.deny > 0 && " · "}
                  {f.deny > 0 && <span className="text-denied">{f.deny} deny</span>}
                </span>
              </div>
              <div className="mt-1 flex h-[7px] w-full overflow-hidden rounded-full bg-surface-3">
                <span
                  className="h-full bg-verified/80"
                  style={{ width: `${allowPct}%`, transition: "width 0.7s cubic-bezier(0.22,1,0.36,1)" }}
                  aria-label={`${f.allow} allowed`}
                />
                <span
                  className="h-full bg-denied/80"
                  style={{ width: `${denyPct}%`, transition: "width 0.7s cubic-bezier(0.22,1,0.36,1)" }}
                  aria-label={`${f.deny} denied`}
                />
              </div>
            </div>
          );
        })}
      </div>
      <p className="mt-3 text-[11px] leading-relaxed text-ink-4">
        Bars are scaled to the busiest facet ({max} request{max === 1 ? "" : "s"}). Benign facets are
        keyword-classified over allowed prompts; safety facets are the policy category that denied the
        request.
      </p>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Safety view — the deny categories in aggregate: "what the network refused,
// by category" — the safety story, made visible.
// ---------------------------------------------------------------------------

function SafetyView({ facets }: { facets: InsightsFacetCount[] }) {
  const safety = facets.filter((f) => FACET_META[f.facet].isSafety && f.deny > 0).sort((a, b) => b.deny - a.deny);
  const refused = safety.reduce((n, f) => n + f.deny, 0);

  return (
    <Panel className="animate-rise p-4">
      <div className="flex items-center justify-between gap-3">
        <SectionLabel>What the network refused · by category</SectionLabel>
        {refused > 0 && (
          <Badge tone="denied">
            {num(refused)} refused
          </Badge>
        )}
      </div>

      {safety.length > 0 ? (
        <div className="mt-3 grid gap-2">
          {safety.map((f) => {
            const meta = FACET_META[f.facet];
            return (
              <div
                key={f.facet}
                className="flex items-center justify-between gap-3 rounded-[10px] border border-denied/20 bg-denied/[0.05] px-3 py-2.5"
              >
                <span className="flex items-center gap-2.5 text-[12.5px] text-ink">
                  <span className="size-2.5 rounded-full" style={{ background: meta.color }} />
                  {meta.label}
                </span>
                <span className="mono text-[13px] font-semibold text-denied tabular-nums">{f.deny}</span>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="mt-3">
          <Empty>No denials cleared the threshold in this window.</Empty>
        </div>
      )}

      <p className="mt-3 text-[11px] leading-relaxed text-ink-4">
        Each refusal is proved: the facet is the ZK-proven policy category that denied the request, so
        this view is <span className="text-ink-3">as good as the policy engine</span> — obfuscation-resistant,
        not semantically complete.
      </p>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Empty / suppressed state — honest, never a broken page.
// ---------------------------------------------------------------------------

function SuppressedState({ kMin, otherCount }: { kMin: number; otherCount: number }) {
  return (
    <Panel className="animate-rise border-pending/25 p-6">
      <div className="flex items-center gap-2">
        <Badge tone="pending" dot>
          ALL CLUSTERS SUPPRESSED
        </Badge>
      </div>
      <h2 className="mt-3 text-[15px] font-semibold text-ink">Not enough traffic yet</h2>
      <p className="mt-2 max-w-[640px] text-[12.5px] leading-relaxed text-ink-3">
        Every facet so far is below the threshold, so no cluster is shown. Clusters below {kMin}{" "}
        requests are suppressed and folded into <span className="mono text-ink-2">other</span>
        {otherCount > 0 && (
          <> ({num(otherCount)} request{otherCount === 1 ? "" : "s"} counted there)</>
        )}
        . This is <span className="text-pending">threshold suppression, not anonymity</span>: it is a
        visible absence, not a claim that individual requests cannot be inferred. Send more varied
        traffic (or run <span className="mono text-ink-2">pnpm seed</span>) and the clusters appear
        once any facet reaches {kMin}.
      </p>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Honesty panel — always visible, equal weight (spec §9). Every claim here is
// checkable against the code; nothing overstates what the classifier does.
// ---------------------------------------------------------------------------

function HonestyPanel({ kMin }: { kMin: number }) {
  return (
    <Panel flat className="mt-4 border-hairline p-4">
      <div className="flex items-center gap-2">
        <span className="size-1.5 rounded-full bg-ink-3" />
        <SectionLabel>How to read this honestly</SectionLabel>
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <HonestyItem title="Classified locally, in the enclave">
          Every prompt is classified <span className="text-ink-2">inside the enclave</span> on the
          plaintext already decrypted for the gate — <span className="text-ink-2">prompts never leave</span>{" "}
          the confidential boundary. Only these closed-enum facet labels and integer counts do.
        </HonestyItem>
        <HonestyItem title="Heuristic keyword classifier, not an LLM">
          The classifier is a deterministic keyword scan (safety facets are the policy category that
          denied the request). It is <span className="text-ink-2">not an LLM</span> and not a learned
          model — facets are approximate and can be wrong.
        </HonestyItem>
        <HonestyItem title="Grouping, not semantic embedding">
          The scatter positions each facet in a fixed region for legibility. Dots near each other share
          a facet and nothing more:{" "}
          {/* prettier-ignore */}
          <span className="text-ink-2">this is grouping, not semantic embedding</span>. Real local
          embeddings would be a post-prototype upgrade.
        </HonestyItem>
        <HonestyItem title="Threshold suppression, not anonymity">
          Facets below {kMin} requests are folded into <span className="mono text-ink-2">other</span> —{" "}
          <span className="text-ink-2">threshold suppression, not anonymity</span>. A determined
          operator with side information could still infer; suppression only makes small clusters a
          visible absence.
        </HonestyItem>
      </div>
      <p className="mt-3 border-t border-hairline pt-3 text-[11px] leading-relaxed text-ink-4">
        The safety facets are as good as the policy engine and no better — same categories, same
        limits. Nothing on this page weakens the prompt-never-leaves guarantee: the bulletin is
        enclave-signed, and the signature is verified in your browser against the attested signing key.
      </p>
    </Panel>
  );
}

function HonestyItem({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-[10px] border border-hairline bg-abyss px-3 py-2.5">
      <div className="text-[12px] font-semibold text-ink">{title}</div>
      <p className="mt-1 text-[11.5px] leading-relaxed text-ink-3">{children}</p>
    </div>
  );
}

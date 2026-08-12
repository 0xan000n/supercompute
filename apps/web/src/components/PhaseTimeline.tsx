"use client";

import { ms } from "@/lib/format";

export type PhaseState = "idle" | "active" | "done" | "failed" | "skipped";

export interface Phase {
  id: string;
  label: string;
  state: PhaseState;
  detail?: string;
  durationMs?: number;
  /** Phases marked parallel render as a bracketed pair (§26). */
  parallel?: boolean;
}

/**
 * §51 — the live phase list. Two phases run concurrently after policy ALLOW
 * (proving and inference), and the bracket makes that visible rather than
 * described, because "proving does not add latency" is the whole point of §66.
 */
export function PhaseTimeline({ phases }: { phases: Phase[] }) {
  return (
    <div className="relative">
      {phases.map((phase, i) => {
        const prev = phases[i - 1];
        const next = phases[i + 1];
        const startsParallel = phase.parallel && !prev?.parallel;
        const endsParallel = phase.parallel && !next?.parallel;

        return (
          <div key={phase.id} className="relative flex gap-3">
            {/* rail */}
            <div className="relative flex w-4 shrink-0 justify-center">
              {i < phases.length - 1 && (
                <span
                  className={`absolute top-[18px] bottom-0 w-[1.5px] ${
                    phase.state === "done"
                      ? "bg-verified/35"
                      : phase.state === "failed"
                        ? "bg-denied/35"
                        : "bg-hairline"
                  }`}
                />
              )}
              <Marker state={phase.state} />
              {phase.parallel && (
                <span
                  className={`absolute left-[-10px] w-[8px] border-private/45 ${
                    startsParallel
                      ? "top-[8px] h-[10px] rounded-tl-[4px] border-t-[1.5px] border-l-[1.5px]"
                      : endsParallel
                        ? "top-[8px] h-[10px] rounded-bl-[4px] border-b-[1.5px] border-l-[1.5px]"
                        : "top-0 bottom-0 border-l-[1.5px]"
                  }`}
                />
              )}
            </div>

            <div className={`min-w-0 flex-1 pb-3.5 ${i === phases.length - 1 ? "pb-0" : ""}`}>
              <div className="flex items-baseline justify-between gap-3">
                <span
                  className={`text-[13px] font-medium leading-5 ${
                    phase.state === "idle"
                      ? "text-ink-4"
                      : phase.state === "failed"
                        ? "text-denied"
                        : phase.state === "skipped"
                          ? "text-ink-4 line-through"
                          : phase.state === "active"
                            ? "text-ink"
                            : "text-ink-2"
                  }`}
                >
                  {phase.label}
                </span>
                {phase.durationMs !== undefined && phase.state !== "idle" && (
                  <span className="mono shrink-0 text-[10.5px] tabular-nums text-ink-4">
                    {ms(phase.durationMs)}
                  </span>
                )}
              </div>
              {phase.detail && phase.state !== "idle" && (
                <div
                  className={`mt-0.5 text-[11px] leading-relaxed ${
                    phase.state === "failed" ? "text-denied/80" : "text-ink-4"
                  }`}
                >
                  {phase.detail}
                </div>
              )}
              {phase.state === "active" && (
                <div className="sweep mt-1.5 h-[2px] rounded-full bg-hairline text-private">
                  <span className="sweep-bar" />
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Marker({ state }: { state: PhaseState }) {
  if (state === "active") {
    return (
      <span className="relative mt-[3px] grid size-4 shrink-0 place-items-center">
        <span className="absolute size-4 rounded-full border-[1.5px] border-pending/30" />
        <span
          className="absolute size-4 rounded-full border-[1.5px] border-pending border-t-transparent"
          style={{ animation: "ctn-spin 0.8s linear infinite" }}
        />
      </span>
    );
  }
  const cls =
    state === "done"
      ? "border-verified/50 bg-verified/15 text-verified"
      : state === "failed"
        ? "border-denied/50 bg-denied/15 text-denied"
        : state === "skipped"
          ? "border-hairline text-ink-4"
          : "border-hairline text-ink-4";
  return (
    <span
      className={`relative z-10 mt-[3px] grid size-4 shrink-0 place-items-center rounded-full border bg-void text-[9px] font-bold ${cls}`}
    >
      {state === "done" ? "✓" : state === "failed" ? "✕" : state === "skipped" ? "–" : ""}
    </span>
  );
}

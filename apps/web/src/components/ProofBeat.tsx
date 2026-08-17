"use client";

import { useMemo, useState } from "react";
import { fromB64, type ProofArtifactWireV1, type SignedProofBindingV2 } from "@ctn/protocol";
import { verifyReceipt, type VerifyResult } from "@ctn/verify";
import { Badge, Button, Check, CopyText, Panel, SectionLabel } from "@/components/ui";
import { ms, shortHash } from "@/lib/format";

/**
 * ProofBeat — the playground's proof "money shot" (Phase 2b §7, Task 6).
 *
 * It renders the five honest states of a gated request's proof lifecycle:
 *   gate verdict → QUEUED (waiting to prove) → PROVING (the wow) → VERIFIED ✓,
 * plus the PROVER_UNAVAILABLE system-failure state, distinct from a policy DENY
 * and from a provider failure.
 *
 * # The one honesty invariant that governs everything here
 *
 * The ONLY thing ever shown as "verified" is the coordinator's DELEGATED seal:
 * a proof whose server-side `prover/verify` re-run passed (proof_status
 * VERIFIED, proof_verified true). See {@link sealVerifiedByCoordinator} — it is
 * the sole source of every "VERIFIED ✓" claim on this surface.
 *
 * The browser's own `verifyReceipt` runs the STRUCTURAL / journal checks locally
 * (Task 5 = NO-GO on in-browser seal verification: risc0 STARK seals need the
 * full pinned verifier, so the seal is delegated). Its `ok:true` means "every
 * LOCAL check passed" — NECESSARY, NOT SUFFICIENT — and is NEVER upgraded to
 * "verified" on its own. It is rendered under "structural checks (run in your
 * browser)", with image-id / seal / rules-digest explicitly marked verified by
 * the coordinator.
 */

/** The pinned release this browser build checks receipts against — mirrors
 *  `prover/release.json` (imageId ddb7dc…, POLICY_ID_V2). The seal is delegated;
 *  these values pin the STRUCTURAL identity the local checks compare to. */
export const PINNED_RELEASE = {
  imageIdHex: "ddb7dc544e1425640ad3af8e7b3b48afa21499a0b371ce4a59fdb4d8594d5331",
  policyId: "0x1f74ba4f2353012cd26f5d3279625c3b45e927eeb341f0ee4b72124b056a7db2",
  rulesDigest: "0x9f85ba59fd1429f10c373efc56d69aefa255a01a08df3ab6bd8e1ccecd3f93ea",
  journalVersion: 1,
  receiptCodec: "bincode-v1",
  risc0Version: "3.0.6",
} as const;

export type ProofStatus =
  | "QUEUED"
  | "PROVING"
  | "GENERATED"
  | "VERIFIED"
  | "FAILED"
  | "NOT_REQUIRED";

export interface DecodedJournal {
  protocolVersion: number;
  requestCommitment: string;
  policyId: string;
  decision: "ALLOW" | "DENY";
  proofNonce: string;
}

/** The `/v1/requests/:id/proof` projection the playground polls. */
export interface ProofPoll {
  proof_status: ProofStatus | string;
  proof_verified?: boolean;
  proof_ms?: number;
  guest_image_id?: string;
  artifact_digest?: string;
  decoded_journal?: DecodedJournal | Record<string, unknown> | null;
  /** The real receipt, base64 — the browser decodes this to run local checks. */
  artifact?: ProofArtifactWireV1 | null;
  binding?: SignedProofBindingV2 | null;
  /** The coordinator's DELEGATED seal authority: a server-side prover/verify re-run. */
  verification?: { valid: boolean; checks: Array<{ name: string; pass: boolean; detail?: string }> } | null;
  error?: string;
}

/**
 * The single source of every "VERIFIED ✓" claim on this surface. A proof is
 * only ever "verified" when the COORDINATOR's delegated `prover/verify` seal
 * passed server-side. A browser-local `verifyReceipt` ok is NEVER routed here.
 */
export function sealVerifiedByCoordinator(proof: ProofPoll | null | undefined): boolean {
  return proof?.proof_status === "VERIFIED" && proof?.proof_verified === true;
}

export interface ProofBeatProps {
  /** The gate verdict — set as soon as the completion (or denial) lands. */
  decision: "ALLOW" | "DENY" | null;
  /** The internal executor gate cost (~57 ms). Shown labelled, NOT as latency. */
  gateWallMs?: number;
  commitment?: string;
  /** The proof projection (null until the first poll returns). */
  proof: ProofPoll | null;
  /** Live wall time since proving began — the PROVING elapsed timer. */
  proofElapsedMs: number;
  /**
   * A system failure (PROVER_UNAVAILABLE). This is NOT a policy decision and NOT
   * a provider failure — the gate itself could not run, so nothing was decided.
   */
  systemFailure?: { code: string; message?: string } | null;
}

export function ProofBeat({
  decision,
  gateWallMs,
  commitment,
  proof,
  proofElapsedMs,
  systemFailure,
}: ProofBeatProps) {
  // ---- PROVER_UNAVAILABLE: its own honest system-failure state. ----
  if (systemFailure) {
    return (
      <Panel className="border-pending/30 p-4">
        <div className="flex items-center gap-2">
          <Badge tone="simulated" dot pulse>
            SYSTEM UNAVAILABLE
          </Badge>
          <span className="mono text-[11px] text-pending">{systemFailure.code}</span>
        </div>
        <p className="mt-2.5 text-[12.5px] leading-relaxed text-ink-2">
          The executor that gates every request could not be reached, so{" "}
          <span className="text-ink">no decision was made</span> and no provider was called. The
          request failed closed.
        </p>
        <div className="mt-2.5 rounded-[10px] border border-hairline bg-abyss px-3 py-2.5 text-[11.5px] leading-relaxed text-ink-3">
          This is a system failure, not a policy <span className="text-denied">DENY</span> and not a
          provider error. It is recorded as an infrastructure fault and kept out of the denial
          metrics — the network never manufactures a decision it did not actually make.
        </div>
      </Panel>
    );
  }

  if (!decision) return null;

  const status = (proof?.proof_status ?? "QUEUED") as ProofStatus;
  const verified = sealVerifiedByCoordinator(proof);
  const isDeny = decision === "DENY";

  return (
    <Panel className="animate-rise overflow-hidden p-0">
      {/* ---- Gate verdict header ---- */}
      <div
        className={`flex flex-wrap items-center gap-x-3 gap-y-2 border-b px-4 py-3 ${
          isDeny ? "border-denied/20 bg-denied/[0.04]" : "border-verified/20 bg-verified/[0.04]"
        }`}
      >
        <Badge tone={isDeny ? "denied" : "verified"} dot>
          {isDeny ? "DENY" : "ALLOW"}
        </Badge>
        <span className="text-[12.5px] text-ink-2">
          {isDeny
            ? "Stopped at the gate — no credential decrypted, no provider called."
            : "Cleared Safety Policy v1 at the gate."}
        </span>
        {gateWallMs !== undefined && gateWallMs > 0 && (
          <span
            className="mono ml-auto shrink-0 text-[10.5px] tabular-nums text-ink-4"
            title="The executor's internal gate cost. This is not your browser round-trip time."
          >
            gate {ms(gateWallMs)} · internal
          </span>
        )}
      </div>

      <div className="p-4">
        {isDeny && (
          <p className="mb-3.5 text-[12px] leading-relaxed text-ink-3">
            The network recorded the commitment and the decision, not the prompt. The denial reason,
            matched rules and category scores are deliberately withheld (§33) — they would leak
            information about the prompt. The request stopped here,{" "}
            <span className="text-ink-2">and it is still being proved below.</span>
          </p>
        )}

        {/* ---- Proof lifecycle ---- */}
        {status === "FAILED" ? (
          <ProofFailed error={proof?.error} />
        ) : verified ? (
          <ProofVerified proof={proof!} decision={decision} commitment={commitment} />
        ) : status === "GENERATED" ? (
          <ProofGenerated imageId={proof?.guest_image_id} />
        ) : status === "PROVING" ? (
          <ProofProving imageId={proof?.guest_image_id} elapsedMs={proofElapsedMs} />
        ) : (
          <ProofQueued />
        )}
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// QUEUED — "waiting to prove". Deliberately calm: NO cryptography is running.
// ---------------------------------------------------------------------------

function ProofQueued() {
  return (
    <div>
      <div className="flex items-center gap-2.5">
        <span className="grid size-7 place-items-center rounded-full border border-hairline bg-surface-2">
          <span className="size-1.5 animate-pulse-soft rounded-full bg-ink-3" />
        </span>
        <div>
          <div className="text-[13px] font-medium text-ink">Waiting to prove</div>
          <div className="text-[11px] text-ink-4">Enqueued · the prover has not started yet</div>
        </div>
      </div>
      <p className="mt-3 text-[11.5px] leading-relaxed text-ink-3">
        The decision is signed and the proof is queued behind the prover.{" "}
        <span className="text-ink-2">No cryptography is running yet</span>, and queue time is never
        counted as proving time.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// PROVING — the wow. Honest: a real STARK, a live elapsed timer, the real
// ImageID, an indeterminate shimmer. No ETA, no percentage — proving time is
// genuinely variable, so a progress bar would be a lie.
// ---------------------------------------------------------------------------

function ProofProving({ imageId, elapsedMs }: { imageId?: string; elapsedMs: number }) {
  const image = imageId ?? PINNED_RELEASE.imageIdHex;
  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="size-1.5 animate-pulse-soft rounded-full bg-proof" />
        <SectionLabel className="text-proof">Generating zero-knowledge proof</SectionLabel>
      </div>

      {/* live elapsed timer — the heartbeat of a real prove */}
      <div className="mt-3 flex items-baseline gap-3">
        <span className="mono text-[38px] font-semibold leading-none tabular-nums text-ink animate-pulse-soft">
          {clock(elapsedMs)}
        </span>
        <span className="text-[11px] text-ink-4">elapsed · proving</span>
      </div>

      {/* indeterminate sweep — motion that means "work in flight", not progress */}
      <div className="sweep mt-3 h-[3px] rounded-full bg-hairline text-proof">
        <span className="sweep-bar" />
      </div>

      {/* the real ImageID being proved against — the cryptography, made concrete */}
      <div className="mt-3.5 rounded-[10px] border border-hairline bg-abyss px-3 py-2.5">
        <div className="flex items-center justify-between gap-3">
          <span className="text-[10.5px] uppercase tracking-[0.08em] text-ink-4">
            Proving against guest image
          </span>
          <Badge tone="private" className="shrink-0">
            pinned
          </Badge>
        </div>
        <div className="mono mt-1.5 text-[11px] leading-relaxed text-private break-all">
          <CopyText text={image}>{image}</CopyText>
        </div>
      </div>

      <p className="mt-3 text-[11.5px] leading-relaxed text-ink-3">
        No progress bar and no ETA: a real STARK&rsquo;s proving time cannot be predicted. The answer
        is already in your browser — this proof is generated{" "}
        <span className="text-ink-2">after the fact</span> and adds no latency to your request.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// GENERATED — receipt exists, seal not yet verified. Distinct from PROVING and
// from VERIFIED: the coordinator is now running prover/verify server-side.
// ---------------------------------------------------------------------------

function ProofGenerated({ imageId }: { imageId?: string }) {
  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="size-1.5 animate-pulse-soft rounded-full bg-pending" />
        <SectionLabel className="text-pending">Receipt generated</SectionLabel>
      </div>
      <p className="mt-2.5 text-[12px] leading-relaxed text-ink-2">
        The STARK receipt exists. The coordinator is now verifying its seal against the pinned
        release — it is <span className="text-ink">not verified yet</span>.
      </p>
      <div className="sweep mt-3 h-[3px] rounded-full bg-hairline text-pending">
        <span className="sweep-bar" />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// FAILED — the proof did not verify. Not a DENY, not PROVER_UNAVAILABLE.
// ---------------------------------------------------------------------------

function ProofFailed({ error }: { error?: string }) {
  return (
    <div>
      <div className="flex items-center gap-2">
        <Badge tone="denied" dot>
          PROOF FAILED
        </Badge>
      </div>
      <p className="mt-2.5 text-[12px] leading-relaxed text-ink-2">
        The proof did not pass verification against the pinned release. It is recorded as a failed
        proof (visible absence) — never a fake <span className="text-verified">VERIFIED</span>.
      </p>
      {error && (
        <div className="mono mt-2.5 rounded-[10px] border border-denied/25 bg-denied/[0.06] px-3 py-2 text-[10.5px] leading-relaxed text-denied break-all">
          {error}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// VERIFIED ✓ — the coordinator's delegated seal passed. The only "verified"
// claim on this surface. Expands into the honest local-vs-delegated inspector.
// ---------------------------------------------------------------------------

function ProofVerified({
  proof,
  decision,
  commitment,
}: {
  proof: ProofPoll;
  decision: "ALLOW" | "DENY";
  commitment?: string;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Badge tone="verified" dot>
          VERIFIED ✓
        </Badge>
        {proof.proof_ms !== undefined && (
          <span className="mono text-[10.5px] tabular-nums text-ink-4">
            proved in {ms(proof.proof_ms)}
          </span>
        )}
      </div>
      <p className="mt-2.5 text-[12px] leading-relaxed text-ink-2">
        The cryptographic seal was verified by the coordinator against the pinned release, and the
        journal is bound to your request commitment.
      </p>

      <Button variant="secondary" onClick={() => setOpen((v) => !v)} className="mt-3 w-full">
        {open ? "Hide proof inspector" : "Inspect proof · verify via coordinator"}
      </Button>

      {open && <ProofInspector proof={proof} decision={decision} commitment={commitment} />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// The inspector — runs @ctn/verify LOCALLY for structural/journal checks, and
// honestly separates them from the checks the coordinator verifies (delegated).
// ---------------------------------------------------------------------------

function ProofInspector({
  proof,
  decision,
  commitment,
}: {
  proof: ProofPoll;
  decision: "ALLOW" | "DENY";
  commitment?: string;
}) {
  const journal = (proof.decoded_journal ?? null) as DecodedJournal | null;

  // Run the browser-local verifier over the real receipt bytes. This checks
  // structure + journal against the pinned manifest; it does NOT check the seal
  // (delegated — see the module doc). `local.ok` is NEVER shown as "verified".
  const local: VerifyResult | null = useMemo(() => {
    if (!proof.artifact?.receiptB64) return null;
    try {
      const bytes = fromB64(proof.artifact.receiptB64);
      return verifyReceipt(bytes, PINNED_RELEASE, {
        commitment: journal?.requestCommitment ?? commitment,
        decision,
        proofNonce: journal?.proofNonce,
      });
    } catch {
      return null;
    }
  }, [proof.artifact?.receiptB64, journal?.requestCommitment, journal?.proofNonce, commitment, decision]);

  // The coordinator's server-side prover/verify result, keyed by check name, so
  // the delegated checks can show the seal authority's verdict beside the label.
  const delegatedByName = useMemo(() => {
    const map = new Map<string, boolean>();
    for (const c of proof.verification?.checks ?? []) map.set(c.name, c.pass);
    return map;
  }, [proof.verification]);

  const localChecks = (local?.checks ?? []).filter((c) => !c.delegated);
  const delegatedChecks = (local?.checks ?? []).filter((c) => c.delegated);

  return (
    <div className="mt-3.5 space-y-3.5 border-t border-hairline pt-3.5">
      {/* honest framing, stated up front */}
      <div className="rounded-[10px] border border-hairline bg-abyss px-3 py-2.5 text-[11px] leading-relaxed text-ink-3">
        Structural checks run <span className="text-ink-2">in your browser</span>. The cryptographic
        seal is verified by the <span className="text-verified">coordinator</span> against the pinned
        release — and you can re-run <span className="mono text-private">prover/verify</span>{" "}
        yourself.
      </div>

      {/* LOCAL structural/journal checks */}
      <div>
        <SectionLabel>Structural checks · run in your browser</SectionLabel>
        <div className="mt-1.5">
          {localChecks.length > 0 ? (
            localChecks.map((c) => (
              <Check key={c.name} pass={c.ok} name={c.name} detail={c.detail} />
            ))
          ) : (
            <div className="py-2 text-[11.5px] text-ink-4">
              Receipt bytes unavailable in this view — the coordinator&rsquo;s verification is shown
              below.
            </div>
          )}
        </div>
        {local && (
          <p className="mt-1 text-[10.5px] leading-relaxed text-ink-4">
            {local.ok ? "All local structural checks passed" : "A local structural check failed"} —
            necessary, not sufficient. It is never the seal; the seal is the coordinator&rsquo;s
            verdict below.
          </p>
        )}
      </div>

      {/* DELEGATED checks — the seal authority is the coordinator */}
      <div>
        <SectionLabel>Verified by the coordinator · delegated seal</SectionLabel>
        <div className="mt-1.5">
          {delegatedChecks.map((c) => {
            const serverPass = delegatedByName.get(c.name);
            const pass = serverPass ?? proof.verification?.valid ?? false;
            return (
              <div key={c.name} className="flex items-start gap-2.5 py-[6px]">
                <span
                  className={`mt-[2px] grid size-4 shrink-0 place-items-center rounded-full border text-[9px] font-bold ${
                    pass
                      ? "border-verified/40 bg-verified/12 text-verified"
                      : "border-pending/40 text-pending"
                  }`}
                >
                  {pass ? "✓" : "◌"}
                </span>
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5 text-[12.5px] text-ink-2">
                    {c.name}
                    <span className="rounded border border-private/30 px-1 py-px text-[8.5px] font-semibold uppercase tracking-[0.06em] text-private">
                      coordinator
                    </span>
                  </div>
                  <div className="mono mt-0.5 text-[10.5px] text-ink-4">{c.detail}</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* the five-field public journal — everything the proof reveals */}
      {journal && (
        <div>
          <SectionLabel>Public journal · everything the proof reveals</SectionLabel>
          <div className="mono mt-1.5 rounded-[10px] border border-hairline bg-abyss p-3 text-[11px] leading-relaxed">
            <JournalRow k="protocolVersion" v={String(journal.protocolVersion)} />
            <JournalRow k="decision" v={journal.decision} tone={journal.decision === "DENY" ? "denied" : "verified"} />
            <JournalRow k="policyId" v={journal.policyId} copy />
            <JournalRow k="requestCommitment" v={journal.requestCommitment} copy />
            <JournalRow k="proofNonce" v={journal.proofNonce} copy />
          </div>
          <p className="mt-1 text-[10.5px] text-ink-4">
            No prompt, no scores, no matched phrases, no reason. Five fields, nothing else.
          </p>
        </div>
      )}

      {/* image id + digests */}
      <div>
        <SectionLabel>Image &amp; digests</SectionLabel>
        <div className="mt-1.5 rounded-[10px] border border-hairline bg-abyss p-3">
          <JournalRow
            k="imageId"
            v={proof.guest_image_id ?? PINNED_RELEASE.imageIdHex}
            copy
            mono
          />
          {proof.artifact_digest && <JournalRow k="artifactDigest" v={proof.artifact_digest} copy mono />}
          {proof.binding?.binding?.decisionReceiptDigest && (
            <JournalRow k="decisionReceiptDigest" v={proof.binding.binding.decisionReceiptDigest} copy mono />
          )}
        </div>
      </div>
    </div>
  );
}

function JournalRow({
  k,
  v,
  copy,
  mono,
  tone,
}: {
  k: string;
  v: string;
  copy?: boolean;
  mono?: boolean;
  tone?: "verified" | "denied";
}) {
  const toneClass = tone === "verified" ? "text-verified" : tone === "denied" ? "text-denied" : "text-ink-2";
  const shown = mono ? shortHash(v, 10, 8) : v;
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-hairline/50 py-[5px] last:border-0">
      <span className="shrink-0 text-ink-4">{k}</span>
      <span className={`text-right break-all ${toneClass}`}>
        {copy ? <CopyText text={v}>{shown}</CopyText> : shown}
      </span>
    </div>
  );
}

/** mm:ss.d — an honest elapsed clock (deciseconds so it visibly ticks). */
function clock(elapsedMs: number): string {
  const total = Math.max(0, elapsedMs);
  const m = Math.floor(total / 60000);
  const s = Math.floor((total % 60000) / 1000);
  const d = Math.floor((total % 1000) / 100);
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}.${d}`;
}

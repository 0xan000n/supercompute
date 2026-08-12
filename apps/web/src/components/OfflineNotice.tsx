"use client";

import { COORDINATOR } from "@/lib/api";

/**
 * What the hosted build shows when no coordinator is reachable.
 *
 * This matters more than a typical empty state. The confidential service holds an
 * ingress key it generates at boot and never persists, and it decrypts prompts in
 * memory — so it deliberately does not run on ephemeral serverless infrastructure.
 * A visitor to the deployed site therefore sees no data, and without an
 * explanation that reads as a broken app rather than a design decision.
 */
export function OfflineNotice({ compact = false }: { compact?: boolean }) {
  if (compact) {
    return (
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-hairline bg-surface/60 px-5 py-2">
        <span className="text-[11.5px] text-ink-2">
          No coordinator reachable at <span className="mono text-ink-3">{COORDINATOR}</span>.
        </span>
        <span className="text-[11.5px] text-ink-4">
          The confidential service runs locally by design — see below to connect one.
        </span>
      </div>
    );
  }

  return (
    <section className="panel mx-auto max-w-[620px] p-5">
      <div className="flex items-center gap-2">
        <span className="size-1.5 rounded-full bg-pending" />
        <h2 className="text-[14px] font-semibold tracking-[-0.01em]">Backend not connected</h2>
      </div>

      <p className="mt-2.5 text-[12.5px] leading-relaxed text-ink-3">
        This is the hosted interface. The confidential service that decrypts requests is not
        running here, and that is deliberate: it generates an ingress key at boot, never persists
        it, and holds plaintext only in memory. Putting it on ephemeral serverless infrastructure
        would mean storing that key somewhere the platform can read — which would defeat the
        property the whole system exists to demonstrate.
      </p>

      <div className="mt-4">
        <div className="label-xs">Run the real thing</div>
        <pre className="mono mt-2 overflow-x-auto rounded-[10px] border border-hairline bg-abyss p-3 text-[11.5px] leading-relaxed text-ink-2">
{`git clone <repo> && cd compute-trust-network
pnpm install
pnpm dev      # coordinator, confidential service, mock provider, web
pnpm seed     # five contributors and some traffic`}
        </pre>
      </div>

      <div className="mt-3.5">
        <div className="label-xs">Or point this page at a coordinator</div>
        <pre className="mono mt-2 overflow-x-auto rounded-[10px] border border-hairline bg-abyss p-3 text-[11.5px] leading-relaxed text-ink-2">
{`NEXT_PUBLIC_COORDINATOR_URL=https://your-tunnel.example`}
        </pre>
        <p className="mt-2 text-[11px] leading-relaxed text-ink-4">
          A tunnel to a coordinator on your own machine keeps the enclave key where it belongs, so
          every guarantee still holds while the link is shareable.
        </p>
      </div>

      <p className="mt-4 border-t border-hairline pt-3 text-[11.5px] leading-relaxed text-ink-3">
        The <span className="text-ink-2">Trust Model</span> page reads without a backend and is the
        best place to start — it states what this architecture establishes and, at equal length,
        what it does not.
      </p>
    </section>
  );
}

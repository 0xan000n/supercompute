"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { usePolled } from "@/lib/api";
import { Badge } from "./ui";
import { OfflineNotice } from "./OfflineNotice";
import { shortHash } from "@/lib/format";

const NAV = [
  { href: "/", label: "Network" },
  { href: "/playground", label: "Playground" },
  { href: "/contribute", label: "Contribute" },
  { href: "/dashboard", label: "Contributors" },
  { href: "/policy", label: "Policy Lab" },
  { href: "/trust", label: "Trust Model" },
];

interface BuildManifest {
  enclaveMode: string;
  enclaveBuildId: string;
  policyId: string;
  zkGuestImageId: string;
  proofSystem: string;
  warning: string;
}

export function Shell({ children, bleed = false }: { children: React.ReactNode; bleed?: boolean }) {
  const pathname = usePathname();
  const { data: manifest, error } = usePolled<BuildManifest>("/v1/build-manifest", 20000);
  // Distinguish "not asked yet" from "asked and nothing answered": only the
  // latter should tell the visitor the backend is absent.
  const offline = manifest === null && error !== null;

  return (
    <div className="flex h-dvh flex-col overflow-hidden">
      {/*
        Rule 10 — simulation mode must be visually distinguishable from hardware.
        This banner is the first thing on the page and never conditionally hidden.
      */}
      {manifest && manifest.enclaveMode !== "nitro" && (
        <div className="flex items-center justify-center gap-2 border-b border-pending/25 bg-pending/[0.07] px-4 py-[7px] text-center">
          <span className="size-1.5 rounded-full bg-pending animate-pulse-soft" />
          <span className="text-[11px] font-semibold tracking-[0.04em] text-pending">
            SIMULATED TEE — NO HARDWARE CONFIDENTIALITY
          </span>
          <span className="hidden text-[11px] text-pending/70 sm:inline">
            · key binding and policy execution are real; hardware isolation is not
          </span>
        </div>
      )}

      <header className="sticky top-0 z-40 border-b border-hairline bg-void/85 backdrop-blur-xl">
        <div className="flex h-14 items-center gap-6 px-5">
          <Link href="/" className="group flex items-center gap-2.5 shrink-0">
            <Mark />
            <div className="leading-none">
              <div className="text-[14px] font-semibold tracking-[-0.015em]">Supercompute</div>
              <div className="mt-[3px] text-[10px] text-ink-4">compute trust network · v0.1</div>
            </div>
          </Link>

          <nav className="flex items-center gap-0.5 overflow-x-auto">
            {NAV.map((item) => {
              const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`relative whitespace-nowrap rounded-lg px-3 py-1.5 text-[12.5px] font-medium outline-none transition duration-200 focus-visible:ring-2 focus-visible:ring-private/50 ${
                    active ? "text-ink bg-surface-2" : "text-ink-3 hover:text-ink-2 hover:bg-surface/60"
                  }`}
                >
                  {item.label}
                  {active && (
                    <span className="absolute inset-x-3 -bottom-[9px] h-[2px] rounded-full bg-private" />
                  )}
                </Link>
              );
            })}
          </nav>

          <div className="ml-auto flex items-center gap-2.5">
            {manifest ? (
              <>
                <div className="hidden items-center gap-2 lg:flex">
                  <span className="label-xs">Policy</span>
                  <span className="mono text-[11px] text-ink-2">{shortHash(manifest.policyId, 6, 4)}</span>
                </div>
                <div className="hidden items-center gap-2 xl:flex">
                  <span className="label-xs">Enclave</span>
                  <span className="mono text-[11px] text-ink-2">
                    {manifest.enclaveBuildId.slice(0, 8)}
                  </span>
                </div>
                <Badge tone={manifest.enclaveMode === "nitro" ? "verified" : "simulated"} dot>
                  {manifest.enclaveMode === "nitro" ? "NITRO" : "SIMULATION"}
                </Badge>
              </>
            ) : (
              <Badge tone="denied" dot>
                ENCLAVE OFFLINE
              </Badge>
            )}
          </div>
        </div>
      </header>

      {offline && <OfflineNotice compact />}

      <main id="main" className={bleed ? "min-h-0 flex-1" : "min-h-0 flex-1 overflow-y-auto px-5 py-7"}>
        {children}
      </main>
    </div>
  );
}

function Mark() {
  return (
    <svg width="26" height="26" viewBox="0 0 26 26" fill="none" className="shrink-0">
      <defs>
        <linearGradient id="ctn-mark" x1="0" y1="0" x2="26" y2="26">
          <stop stopColor="#22d3ee" />
          <stop offset="1" stopColor="#a78bfa" />
        </linearGradient>
      </defs>
      {/* A shield made of three linked nodes: contributed capacity under constraint. */}
      <path
        d="M13 2.2l8.2 3.1v7.2c0 5-3.4 9.2-8.2 11.3-4.8-2.1-8.2-6.3-8.2-11.3V5.3L13 2.2z"
        stroke="url(#ctn-mark)"
        strokeWidth="1.4"
        fill="rgba(34,211,238,0.07)"
      />
      <circle cx="13" cy="9.4" r="2.1" fill="#22d3ee" />
      <circle cx="9.1" cy="15.4" r="1.7" fill="#a78bfa" />
      <circle cx="16.9" cy="15.4" r="1.7" fill="#34d399" />
      <path d="M13 9.4L9.1 15.4M13 9.4l3.9 6M9.1 15.4h7.8" stroke="url(#ctn-mark)" strokeWidth="0.9" />
    </svg>
  );
}

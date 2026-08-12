"use client";

import { useState, type ReactNode } from "react";

export function Panel({
  children,
  className = "",
  flat = false,
}: {
  children: ReactNode;
  className?: string;
  flat?: boolean;
}) {
  return <div className={`${flat ? "panel-flat" : "panel"} ${className}`}>{children}</div>;
}

export function SectionLabel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`label-xs ${className}`}>{children}</div>;
}

/** Key/value row used across every inspector. Values are monospaced when hashy. */
export function Field({
  label,
  value,
  mono = false,
  tone,
  copy,
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
  tone?: "verified" | "pending" | "denied" | "private" | "muted";
  copy?: string;
}) {
  const toneClass =
    tone === "verified"
      ? "text-verified"
      : tone === "pending"
        ? "text-pending"
        : tone === "denied"
          ? "text-denied"
          : tone === "private"
            ? "text-private"
            : tone === "muted"
              ? "text-ink-3"
              : "text-ink";
  return (
    <div className="flex items-baseline justify-between gap-4 py-[7px] border-b border-hairline/60 last:border-0">
      <span className="text-[12px] text-ink-3 shrink-0">{label}</span>
      <span className={`text-[12.5px] text-right ${mono ? "mono" : ""} ${toneClass} min-w-0 break-all`}>
        {copy ? <CopyText text={copy}>{value}</CopyText> : value}
      </span>
    </div>
  );
}

export function CopyText({ text, children }: { text: string; children: ReactNode }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        void navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
      className="hover:text-private transition inline-flex items-center gap-1.5 text-right"
      title="Copy"
    >
      {children}
      <span className={`text-[9px] ${copied ? "text-verified" : "text-ink-4"}`}>
        {copied ? "COPIED" : "⧉"}
      </span>
    </button>
  );
}

export type BadgeTone = "verified" | "pending" | "denied" | "private" | "neutral" | "simulated";

const BADGE: Record<BadgeTone, string> = {
  verified: "text-verified bg-verified/10 border-verified/25",
  pending: "text-pending bg-pending/10 border-pending/25",
  denied: "text-denied bg-denied/10 border-denied/25",
  private: "text-private bg-private/10 border-private/25",
  simulated: "text-pending bg-pending/8 border-pending/25",
  neutral: "text-ink-2 bg-surface-2 border-hairline",
};

export function Badge({
  children,
  tone = "neutral",
  dot = false,
  pulse = false,
  className = "",
}: {
  children: ReactNode;
  tone?: BadgeTone;
  dot?: boolean;
  pulse?: boolean;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-[3px] text-[10.5px] font-semibold tracking-[0.02em] ${BADGE[tone]} ${className}`}
    >
      {dot && (
        <span
          className={`size-1.5 rounded-full bg-current ${pulse ? "animate-pulse-soft" : ""}`}
        />
      )}
      {children}
    </span>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  disabled,
  busy,
  className = "",
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger" | "secondary";
  disabled?: boolean;
  busy?: boolean;
  className?: string;
  type?: "button" | "submit";
}) {
  // Pressed feedback and a visible focus ring: the first makes the control feel
  // physical, the second is an accessibility requirement rather than a nicety.
  const base =
    "relative inline-flex items-center justify-center gap-2 rounded-[10px] px-4 py-2.5 text-[13px] font-semibold transition-all duration-200 " +
    "active:translate-y-[1px] active:scale-[0.985] " +
    "outline-none focus-visible:ring-2 focus-visible:ring-private/55 focus-visible:ring-offset-2 focus-visible:ring-offset-void " +
    "disabled:opacity-40 disabled:cursor-not-allowed disabled:active:translate-y-0 disabled:active:scale-100";
  const variants = {
    primary:
      "bg-private/15 text-private border border-private/35 hover:bg-private/22 hover:border-private/55 shadow-[0_0_24px_-8px_rgba(34,211,238,0.5)]",
    secondary: "bg-surface-3 text-ink border border-hairline hover:bg-surface-3/70 hover:border-ink-4",
    ghost: "text-ink-2 hover:text-ink hover:bg-surface-2 border border-transparent",
    danger: "bg-denied/12 text-denied border border-denied/30 hover:bg-denied/20",
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || busy}
      className={`${base} ${variants[variant]} ${className}`}
    >
      {busy && (
        <span
          className="size-3.5 rounded-full border-[1.5px] border-current border-t-transparent"
          style={{ animation: "ctn-spin 0.7s linear infinite" }}
        />
      )}
      {children}
    </button>
  );
}

export function Input({
  value,
  onChange,
  placeholder,
  type = "text",
  mono = false,
  className = "",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  mono?: boolean;
  className?: string;
}) {
  return (
    <input
      type={type}
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      className={`w-full rounded-[10px] bg-abyss border border-hairline px-3 py-2.5 text-[13px] text-ink placeholder:text-ink-4 outline-none transition focus:border-private/50 focus:ring-2 focus:ring-private/12 ${mono ? "mono" : ""} ${className}`}
    />
  );
}

export function Textarea({
  value,
  onChange,
  placeholder,
  rows = 5,
  className = "",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  rows?: number;
  className?: string;
}) {
  return (
    <textarea
      value={value}
      rows={rows}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      className={`w-full resize-none rounded-[10px] bg-abyss border border-hairline px-3.5 py-3 text-[13.5px] leading-relaxed text-ink placeholder:text-ink-4 outline-none transition focus:border-private/50 focus:ring-2 focus:ring-private/12 ${className}`}
    />
  );
}

/** A verification check row — the visual vocabulary for "this was checked". */
export function Check({
  pass,
  name,
  detail,
  pending,
}: {
  pass: boolean;
  name: string;
  detail?: string;
  pending?: boolean;
}) {
  return (
    <div className="flex items-start gap-2.5 py-[6px]">
      <span
        className={`mt-[2px] grid size-4 shrink-0 place-items-center rounded-full border text-[9px] font-bold ${
          pending
            ? "border-pending/40 text-pending"
            : pass
              ? "border-verified/40 bg-verified/12 text-verified"
              : "border-denied/40 bg-denied/12 text-denied"
        }`}
      >
        {pending ? "◌" : pass ? "✓" : "✕"}
      </span>
      <div className="min-w-0">
        <div className={`text-[12.5px] ${pass || pending ? "text-ink-2" : "text-denied"}`}>{name}</div>
        {detail && <div className="mono mt-0.5 text-[10.5px] text-ink-4 break-all">{detail}</div>}
      </div>
    </div>
  );
}

export function Stat({
  label,
  value,
  unit,
  tone,
  hint,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  tone?: "verified" | "pending" | "denied" | "private";
  hint?: string;
}) {
  const toneClass =
    tone === "verified"
      ? "text-verified"
      : tone === "pending"
        ? "text-pending"
        : tone === "denied"
          ? "text-denied"
          : tone === "private"
            ? "text-private"
            : "text-ink";
  return (
    <div className="min-w-0">
      <SectionLabel>{label}</SectionLabel>
      <div className={`mt-1.5 flex items-baseline gap-1 ${toneClass}`}>
        <span className="text-[26px] font-semibold leading-none tracking-[-0.02em] tabular-nums">
          {value}
        </span>
        {unit && <span className="text-[12px] text-ink-3">{unit}</span>}
      </div>
      {hint && <div className="mt-1 text-[11px] text-ink-4">{hint}</div>}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="grid place-items-center rounded-[12px] border border-dashed border-hairline px-6 py-10 text-center text-[12.5px] text-ink-3">
      {children}
    </div>
  );
}

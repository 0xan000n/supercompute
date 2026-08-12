import type { GraphNodeType } from "@ctn/protocol";

export interface NodeStyle {
  color: string;
  glow: string;
  radius: number;
  shape: "circle" | "square" | "diamond" | "hex";
  short: string;
}

export const NODE_STYLE: Record<GraphNodeType, NodeStyle> = {
  Contributor: { color: "#a78bfa", glow: "rgba(167,139,250,0.55)", radius: 13, shape: "circle", short: "Contributor" },
  Credential: { color: "#fbbf24", glow: "rgba(251,191,36,0.55)", radius: 11, shape: "hex", short: "Credential" },
  Request: { color: "#22d3ee", glow: "rgba(34,211,238,0.65)", radius: 12, shape: "circle", short: "Request" },
  TEEWorker: { color: "#60a5fa", glow: "rgba(96,165,250,0.6)", radius: 15, shape: "square", short: "TEE" },
  Policy: { color: "#34d399", glow: "rgba(52,211,153,0.55)", radius: 13, shape: "diamond", short: "Policy" },
  Proof: { color: "#6ee7b7", glow: "rgba(110,231,183,0.6)", radius: 11, shape: "diamond", short: "Proof" },
  ProviderAttempt: { color: "#94a3b8", glow: "rgba(148,163,184,0.4)", radius: 7, shape: "circle", short: "Attempt" },
  Provider: { color: "#fb7185", glow: "rgba(251,113,133,0.55)", radius: 14, shape: "square", short: "Provider" },
  Model: { color: "#94a3b8", glow: "rgba(148,163,184,0.45)", radius: 10, shape: "hex", short: "Model" },
  Response: { color: "#2dd4bf", glow: "rgba(45,212,191,0.55)", radius: 10, shape: "circle", short: "Response" },
  ComputeReceipt: { color: "#fcd34d", glow: "rgba(252,211,77,0.55)", radius: 10, shape: "hex", short: "Receipt" },
};

/** Status overrides: a failed proof must never render in the verified color. */
export function statusColor(type: GraphNodeType, status?: string): string {
  if (status === "FAILED" || status === "DENIED") return "#fb7185";
  if (status === "PROVING" || status === "RECEIVED" || status === "ROUTING" || status === "PROVIDER_RUNNING") {
    return "#fbbf24";
  }
  if (status === "DISABLED" || status === "DELETED") return "#6b7288";
  if (status === "SIMULATED") return "#fbbf24";
  return NODE_STYLE[type].color;
}

export const TRUST_STATUS_META: Record<
  string,
  { label: string; tone: "verified" | "pending" | "denied" | "simulated" | "compat"; detail: string }
> = {
  CONFIDENTIAL_VERIFIED: {
    label: "Confidential · Verified",
    tone: "verified",
    detail: "Secure path used, policy allowed, proof verified, receipt signature valid.",
  },
  CONFIDENTIAL_PROOF_PENDING: {
    label: "Confidential · Proof pending",
    tone: "pending",
    detail: "Inference completed; the policy proof has not finished verifying yet.",
  },
  CONFIDENTIAL_PROOF_FAILED: {
    label: "Confidential · Proof failed",
    tone: "denied",
    detail: "Inference completed but the policy proof failed. This is shown, not hidden.",
  },
  SIMULATED: {
    label: "Simulated TEE",
    tone: "simulated",
    detail: "Key binding verified, but no hardware isolation. Not a confidentiality claim.",
  },
  COMPATIBILITY: {
    label: "Compatibility mode",
    tone: "compat",
    detail: "TLS terminated at the coordinator, so the operator could see this prompt.",
  },
};

export const TONE_CLASS: Record<string, string> = {
  verified: "text-verified border-verified/30 bg-verified/10",
  pending: "text-pending border-pending/30 bg-pending/10",
  denied: "text-denied border-denied/30 bg-denied/10",
  simulated: "text-pending border-pending/30 bg-pending/10",
  compat: "text-ink-2 border-hairline bg-surface-2",
};

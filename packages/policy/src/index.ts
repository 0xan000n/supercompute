import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { evaluate, type PolicyRules, type PolicyEvaluation } from "./engine.js";

export * from "./engine.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
/** packages/policy/src -> repo root/policy/v1 */
const POLICY_DIR = join(__dirname, "..", "..", "..", "policy", "v1");

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
const enc = new TextEncoder();

export interface PolicyPackage {
  manifest: Record<string, unknown>;
  rules: PolicyRules;
  rulesBytes: Uint8Array;
  /** §24 — identifies the exact compiled policy program (simulated guest). */
  guestImageId: string;
  /** §24 — policy_id = SHA256(canonical_manifest || rules_bytes || guest_image_id). */
  policyId: string;
}

let cached: PolicyPackage | null = null;

/** JCS-ish canonical serialization for the manifest, matching protocol/canonical. */
function canonical(value: unknown): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") return String(value);
  if (t === "string") return JSON.stringify((value as string).normalize("NFC"));
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (t === "object") {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .filter((k) => o[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(",")}}`;
  }
  throw new Error("uncanonicalizable");
}

export function loadPolicyPackage(dir = POLICY_DIR): PolicyPackage {
  if (cached && dir === POLICY_DIR) return cached;

  const manifestRaw = readFileSync(join(dir, "manifest.json"), "utf8");
  const rulesRaw = readFileSync(join(dir, "rules.json"), "utf8");
  const manifest = JSON.parse(manifestRaw) as Record<string, unknown>;
  const rules = JSON.parse(rulesRaw) as PolicyRules;

  const rulesBytes = enc.encode(rulesRaw);
  const canonManifest = enc.encode(canonical(manifest));

  // guest image id: identifies the exact policy program that will re-execute.
  const guestBuf = new Uint8Array(enc.encode("ctn-policy-v1-guest\0").length + rulesBytes.length);
  const guestPrefix = enc.encode("ctn-policy-v1-guest\0");
  guestBuf.set(guestPrefix, 0);
  guestBuf.set(rulesBytes, guestPrefix.length);
  const guestImageId = "0x" + toHex(sha256(guestBuf));

  // policy_id = SHA256(canonical_manifest || rules_bytes || guest_image_id)
  const gidBytes = enc.encode(guestImageId);
  const idBuf = new Uint8Array(canonManifest.length + rulesBytes.length + gidBytes.length);
  idBuf.set(canonManifest, 0);
  idBuf.set(rulesBytes, canonManifest.length);
  idBuf.set(gidBytes, canonManifest.length + rulesBytes.length);
  const policyId = "0x" + toHex(sha256(idBuf));

  const pkg: PolicyPackage = { manifest, rules, rulesBytes, guestImageId, policyId };
  if (dir === POLICY_DIR) cached = pkg;
  return pkg;
}

/** Extract the text a policy evaluates: the concatenation of all message contents. */
export function requestText(messages: Array<{ role: string; content: string }>): string {
  return messages.map((m) => m.content).join("\n");
}

export function evaluateRequest(
  messages: Array<{ role: string; content: string }>,
  pkg = loadPolicyPackage()
): PolicyEvaluation {
  return evaluate(pkg.rules, requestText(messages));
}

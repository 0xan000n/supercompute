/**
 * §53, §54 — the mandatory privacy tests.
 *
 *   npx tsx scripts/privacy-test.ts
 *
 * Submits a unique canary prompt and contributes a credential with a unique
 * secret, then searches every surface the network persists or exposes for either
 * string. The expected result is zero occurrences everywhere except the mock
 * provider's own received-log — which plays the upstream provider, and is
 * *supposed* to have the prompt. That single expected hit is what makes the test
 * meaningful: it proves the enclave really did decrypt and really did call
 * upstream, while no intermediary saw either value.
 */
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { ComputeTrustClient } from "@ctn/client";

const BASE = process.env.CTN_COORDINATOR_URL ?? "http://127.0.0.1:4200";
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const DATA_DIR = join(root, ".data");

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

const client = new ComputeTrustClient(BASE);
let failures = 0;

function report(name: string, occurrences: number, expected: number): void {
  const ok = occurrences === expected;
  if (!ok) failures += 1;
  const mark = ok ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
  const detail =
    expected === 0
      ? `${occurrences} occurrence(s)`
      : `${occurrences} occurrence(s), expected ${expected}`;
  console.log(`  ${mark} ${name.padEnd(46)} ${DIM}${detail}${RESET}`);
}

/** Counts occurrences in a file's raw bytes — catches values inside a DB page too. */
function countInFile(path: string, needle: string): number {
  if (!existsSync(path)) return 0;
  const text = readFileSync(path).toString("binary");
  return text.split(needle).length - 1;
}

function countInDir(dir: string, needle: string, skip: string[] = []): number {
  if (!existsSync(dir)) return 0;
  let total = 0;
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (skip.some((s) => entry.includes(s))) continue;
    if (statSync(path).isDirectory()) total += countInDir(path, needle, skip);
    else total += countInFile(path, needle);
  }
  return total;
}

async function countInApi(path: string, needle: string): Promise<number> {
  const res = await fetch(`${BASE}${path}`);
  const text = await res.text();
  return text.split(needle).length - 1;
}

async function main(): Promise<void> {
  console.log("");
  console.log("Privacy canary sweep");
  console.log(`${DIM}coordinator ${BASE}${RESET}`);

  // ---------------------------------------------------------------- §54 prompt
  const canary = `CANARY_PRIVATE_PROMPT_${randomUUID().replace(/-/g, "").toUpperCase()}`;
  console.log("");
  console.log(`§54 Prompt privacy  ${DIM}${canary.slice(0, 34)}…${RESET}`);

  const completion = await client.completion({
    model: "ctn/demo-model-a",
    messages: [{ role: "user", content: `Summarize this token verbatim: ${canary}` }],
  });
  // Let the projector drain and the proof settle before searching.
  await client.waitForProof(completion.requestId, 30_000);
  await new Promise((r) => setTimeout(r, 800));

  report("coordinator database", countInFile(join(DATA_DIR, "coordinator.sqlite"), canary), 0);
  report(
    "database WAL / journal",
    countInFile(join(DATA_DIR, "coordinator.sqlite-wal"), canary) +
      countInFile(join(DATA_DIR, "coordinator.sqlite-shm"), canary),
    0
  );
  report("graph projection API", await countInApi("/v1/graph", canary), 0);
  report("request detail API", await countInApi(`/v1/requests/${completion.requestId}`, canary), 0);
  report("receipt API", await countInApi(`/v1/requests/${completion.requestId}/receipt`, canary), 0);
  report("proof API", await countInApi(`/v1/requests/${completion.requestId}/proof`, canary), 0);
  report("request list API", await countInApi("/v1/requests?limit=100", canary), 0);
  report("stats API", await countInApi("/v1/stats", canary), 0);
  report(
    "vault + enclave state on disk",
    countInFile(join(DATA_DIR, "wrapped-dek.json"), canary) +
      countInFile(join(DATA_DIR, "sim-kms-master.key"), canary),
    0
  );
  report(
    "all other files under .data/",
    countInDir(DATA_DIR, canary, ["mock-provider-received.log"]),
    0
  );

  // The one place it MUST appear: the upstream provider.
  const upstream = countInFile(join(DATA_DIR, "mock-provider-received.log"), canary);
  const ok = upstream > 0;
  if (!ok) failures += 1;
  console.log(
    `  ${ok ? GREEN + "✓" + RESET : RED + "✗" + RESET} ${"upstream provider received it (expected)".padEnd(46)} ${DIM}${upstream} occurrence(s)${RESET}`
  );
  console.log(
    `  ${DIM}   ↳ proves the enclave decrypted and called upstream, while no intermediary saw it${RESET}`
  );

  // ------------------------------------------------------------ §53 credential
  const secretTag = `SECRET_TEST_KEY_${randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase()}`;
  const secret = `mock-provider-key-${secretTag}`;
  console.log("");
  console.log(`§53 Provider-key privacy  ${DIM}${secretTag}${RESET}`);

  const contributor = (await (
    await fetch(`${BASE}/v1/contributors`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ displayName: `CanaryTest ${secretTag.slice(-4)}` }),
    })
  ).json()) as { id: string };

  const credential = (await client.contributeCredential({
    contributorId: contributor.id,
    label: `Canary credential ${secretTag.slice(-4)}`,
    provider: "mock",
    apiKey: secret,
    allowedModels: ["ctn/demo-model-a"],
    operationalLimits: { dailyUsd: 1, dailyRequests: 5 },
  })) as { id: string };

  await new Promise((r) => setTimeout(r, 600));

  report("coordinator database", countInFile(join(DATA_DIR, "coordinator.sqlite"), secretTag), 0);
  report(
    "database WAL / journal",
    countInFile(join(DATA_DIR, "coordinator.sqlite-wal"), secretTag) +
      countInFile(join(DATA_DIR, "coordinator.sqlite-shm"), secretTag),
    0
  );
  report("graph projection API", await countInApi("/v1/graph", secretTag), 0);
  report("credential list API", await countInApi("/v1/credentials", secretTag), 0);
  report("vault ciphertext on disk", countInDir(DATA_DIR, secretTag, ["mock-provider-received.log"]), 0);

  // Clean up so the demo network is not left with a throwaway credential enabled.
  await fetch(`${BASE}/v1/credentials/${credential.id}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ status: "DISABLED" }),
  });

  console.log("");
  console.log(
    `${DIM}Note: service stdout is not searched here because it is not persisted. safe-log()${RESET}`
  );
  console.log(
    `${DIM}redacts the forbidden field set at the boundary, and its unit tests assert that.${RESET}`
  );

  console.log("");
  if (failures === 0) {
    console.log(`${GREEN}Privacy sweep passed.${RESET} No canary leaked to any intermediary surface.`);
    console.log("");
    process.exit(0);
  }
  console.log(`${RED}${failures} surface(s) failed.${RESET}`);
  console.log(
    `${YELLOW}A leak here is a real privacy defect, not a flaky test — investigate before demoing.${RESET}`
  );
  console.log("");
  process.exit(1);
}

main().catch((err) => {
  console.error(`${RED}error:${RESET} ${(err as Error).message}`);
  process.exit(1);
});

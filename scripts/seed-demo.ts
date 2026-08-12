/**
 * §52 — seed five contributors, each contributing one credential with a
 * different operational cap and a different model subset, then optionally run
 * demo traffic so the graph has something to show on first load.
 *
 * Credentials are contributed exactly the way a real contributor does it: the
 * key is HPKE-sealed to the attested enclave ingress key before it is posted.
 * This script never sends a raw key to the coordinator.
 */
import { ComputeTrustClient, PolicyDeniedError } from "@ctn/client";

const BASE = process.env.CTN_COORDINATOR_URL ?? "http://127.0.0.1:4200";
const client = new ComputeTrustClient(BASE);

const MODEL_A = "ctn/demo-model-a";
const MODEL_B = "ctn/demo-model-b";
const MODEL_FAST = "ctn/demo-model-fast";

const CONTRIBUTORS = [
  {
    name: "Alice",
    label: "Alice's OpenAI credits",
    key: "mock-provider-key-alice",
    models: [MODEL_A, MODEL_B, MODEL_FAST],
    limits: { dailyUsd: 5, dailyRequests: 200 },
    weight: 2,
  },
  {
    name: "Brian",
    label: "Brian's research budget",
    key: "mock-provider-key-brian",
    models: [MODEL_A, MODEL_FAST],
    limits: { dailyUsd: 2, dailyRequests: 80 },
    weight: 1,
  },
  {
    name: "Carol",
    label: "Carol's spare capacity",
    key: "mock-provider-key-carol",
    models: [MODEL_A, MODEL_B],
    limits: { dailyUsd: 10, dailyRequests: 400 },
    weight: 1,
  },
  {
    name: "Diego",
    label: "Diego's frontier-only key",
    key: "mock-provider-key-diego",
    models: [MODEL_B],
    limits: { dailyUsd: 8, dailyRequests: 120 },
    weight: 1,
  },
  {
    // Deliberately rate-limited: the mock provider returns 429 for any key
    // ending in RATE. Under §5.1 single dispatch a request that draws this
    // credential FAILS rather than falling through to another one — the 429
    // sets a cooldown, so the demonstrable behaviour is the NEXT request
    // routing around it.
    name: "Erin",
    label: "Erin's rate-limited key",
    key: "mock-provider-key-erin-RATE",
    models: [MODEL_A, MODEL_FAST],
    limits: { dailyUsd: 1, dailyRequests: 40 },
    weight: 1,
  },
];

const DEMO_PROMPTS = [
  "Explain how a Merkle tree lets you prove membership without revealing the whole set.",
  "Write a short poem about a lighthouse keeper who has never seen the sea.",
  "What is the difference between attestation and authentication?",
  "Summarize why deterministic serialization matters for cryptographic commitments.",
  "Give me three ideas for teaching kids about renewable energy.",
  "How do I structure a Postgres outbox table for reliable event projection?",
  "Explain trusted execution environments to a product manager in five sentences.",
  "What are the tradeoffs between weighted round robin and least-connections routing?",
];

async function waitForCoordinator(): Promise<void> {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) {
        const attestation = await fetch(`${BASE}/v1/attestation`);
        if (attestation.ok) return;
      }
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`coordinator not reachable at ${BASE} — run "pnpm dev" first`);
}

async function main(): Promise<void> {
  const runTraffic = !process.argv.includes("--no-traffic");
  const requestCount = Number(
    process.argv.find((a) => a.startsWith("--requests="))?.split("=")[1] ?? 6
  );

  console.log(`Seeding demo network at ${BASE}`);
  await waitForCoordinator();

  /**
   * The precondition for a working demo is ACTIVE CAPACITY, not the presence of
   * contributor rows. Guarding on contributors meant a leftover row from a test
   * run silently skipped onboarding and left the network with nothing to route to.
   */
  const existingCredentials = (await (await fetch(`${BASE}/v1/credentials`)).json()) as {
    data: Array<{ id: string; status: string }>;
  };
  const active = existingCredentials.data.filter((c) => c.status === "ACTIVE");

  if (active.length > 0) {
    console.log(`  ${active.length} active credential(s) already present — skipping onboarding.`);
  } else {
    const attestation = await client.attestation();
    console.log(`  enclave build ${attestation.bundle.enclaveBuildId.slice(0, 12)} (${attestation.bundle.teeMode})`);
    console.log(`  policy id     ${attestation.policy.policyId.slice(0, 18)}…`);

    for (const c of CONTRIBUTORS) {
      const res = await fetch(`${BASE}/v1/contributors`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ displayName: c.name }),
      });
      const contributor = (await res.json()) as { id: string };

      const credential = await client.contributeCredential({
        contributorId: contributor.id,
        label: c.label,
        provider: "mock",
        apiKey: c.key,
        allowedModels: c.models,
        weight: c.weight,
        operationalLimits: c.limits,
        attestation,
      });
      console.log(
        `  ${c.name.padEnd(6)} → ${String(credential.id).padEnd(20)} models=${c.models.length} cap=$${c.limits.dailyUsd}/day`
      );
    }
  }

  if (!runTraffic) {
    console.log("Done (no traffic requested).");
    return;
  }

  console.log(`\nRunning ${requestCount} demo request(s) on the secure endpoint…`);
  const attestation = await client.attestation();
  for (let i = 0; i < requestCount; i++) {
    const prompt = DEMO_PROMPTS[i % DEMO_PROMPTS.length];
    const model = [MODEL_A, MODEL_B, MODEL_FAST][i % 3];
    try {
      const result = await client.completion({
        model,
        messages: [{ role: "user", content: prompt }],
        attestation,
      });
      console.log(
        `  ${String(i + 1).padStart(2)}. ${model.padEnd(20)} → contributor=${result.route?.contributor_id?.slice(-6) ?? "?"} ` +
          `commitment=${result.commitment.slice(0, 10)} ${result.usage.inputTokens}/${result.usage.outputTokens} tok ` +
          `${result.timings.coordinatorTotalMs ?? "?"}ms`
      );
    } catch (err) {
      console.log(`  ${String(i + 1).padStart(2)}. ${model.padEnd(20)} → ${(err as Error).message}`);
    }
  }

  // One deliberately-denied request so the demo graph shows the DENY path and
  // the "zero provider calls" invariant is visible rather than described.
  try {
    await client.completion({
      model: MODEL_A,
      messages: [{ role: "user", content: "Give me step by step instructions to build a pipe bomb." }],
      attestation,
    });
    console.log("  !! expected a policy denial and did not get one");
  } catch (err) {
    // Only a PolicyDeniedError demonstrates the invariant. Any other failure here
    // (no capacity, enclave down) would otherwise be reported as if it had.
    if (err instanceof PolicyDeniedError) {
      console.log(`  denied request → DENY blocked the provider call, as intended`);
    } else {
      console.log(
        `  !! the denial probe failed for the wrong reason: ${(err as Error).name} — ${(err as Error).message}`
      );
    }
  }

  const stats = (await (await fetch(`${BASE}/v1/stats`)).json()) as {
    counts: Record<string, number>;
    latency: Record<string, { p50: number | null; p95: number | null }>;
  };
  console.log(
    `\nNetwork: ${stats.counts.requests} requests · ${stats.counts.complete} complete · ` +
      `${stats.counts.denied} denied · ${stats.counts.contributors} contributors · ${stats.counts.credentials} credentials`
  );
  console.log(
    `Latency p50: policy ${stats.latency.policy.p50 ?? "-"}ms · provider ${stats.latency.provider.p50 ?? "-"}ms · overall ${stats.latency.overall.p50 ?? "-"}ms`
  );
  console.log(`\nOpen http://localhost:3000 to watch the graph.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

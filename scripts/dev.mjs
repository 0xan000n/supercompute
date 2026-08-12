#!/usr/bin/env node
/**
 * §62 — one-command local startup. Replaces docker compose for this prototype:
 * every service is a Node process, so there is nothing to install but pnpm.
 *
 * Services: mock-provider, tee-sim, coordinator, web.
 */
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const only = process.argv.slice(2).filter((a) => !a.startsWith("-"));

const services = [
  { name: "mock-provider", cwd: join(root, "services/mock-provider"), cmd: ["pnpm", "start"], color: "\x1b[35m" },
  { name: "tee-sim", cwd: join(root, "services/tee-sim"), cmd: ["pnpm", "start"], color: "\x1b[36m" },
  { name: "coordinator", cwd: join(root, "services/coordinator"), cmd: ["pnpm", "start"], color: "\x1b[32m" },
  { name: "web", cwd: join(root, "apps/web"), cmd: ["pnpm", "dev"], color: "\x1b[33m" },
].filter((s) => only.length === 0 || only.includes(s.name));

const env = {
  ...process.env,
  CTN_ENV: process.env.CTN_ENV ?? "local",
  TEE_MODE: "simulation",
  COORDINATOR_PORT: process.env.COORDINATOR_PORT ?? "4200",
  TEE_PORT: process.env.TEE_PORT ?? "4400",
  MOCK_PROVIDER_PORT: process.env.MOCK_PROVIDER_PORT ?? "4300",
  MOCK_PROVIDER_URL: process.env.MOCK_PROVIDER_URL ?? "http://127.0.0.1:4300",
  TEE_URL: process.env.TEE_URL ?? "http://127.0.0.1:4400",
  // §20 — the enclave egress allowlist. The local mock provider must be listed
  // explicitly; nothing reaches the network without appearing here.
  CTN_EGRESS_ALLOWLIST: process.env.CTN_EGRESS_ALLOWLIST ?? "127.0.0.1:4300",
};

const children = [];
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";

for (const service of services) {
  const child = spawn(service.cmd[0], service.cmd.slice(1), {
    cwd: service.cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.push(child);

  const prefix = `${service.color}${service.name.padEnd(14)}${RESET}${DIM}│${RESET} `;
  const pipe = (stream, isErr) => {
    let buffer = "";
    stream.on("data", (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (line.trim().length === 0) continue;
        (isErr ? process.stderr : process.stdout).write(`${prefix}${line}\n`);
      }
    });
  };
  pipe(child.stdout, false);
  pipe(child.stderr, true);

  child.on("exit", (code) => {
    process.stdout.write(`${prefix}exited with code ${code}\n`);
  });
}

const shutdown = () => {
  for (const child of children) child.kill("SIGTERM");
  setTimeout(() => process.exit(0), 300);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

console.log("");
console.log("  Compute Trust Network — local development");
console.log("  ────────────────────────────────────────");
console.log("  web          http://localhost:3000");
console.log("  coordinator  http://127.0.0.1:4200");
console.log("  tee-sim      http://127.0.0.1:4400  (SIMULATED TEE)");
console.log("  mock         http://127.0.0.1:4300");
console.log("");

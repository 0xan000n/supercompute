#!/usr/bin/env node
/** Wipes local state so `pnpm seed` starts from an empty network. */
import { rmSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dataDir = join(dirname(fileURLToPath(import.meta.url)), "..", ".data");
if (existsSync(dataDir)) {
  rmSync(dataDir, { recursive: true, force: true });
  console.log("removed .data/ (database, vault, mock provider log)");
} else {
  console.log(".data/ already clean");
}
console.log("restart `pnpm dev` so the enclave re-provisions its vault, then `pnpm seed`.");

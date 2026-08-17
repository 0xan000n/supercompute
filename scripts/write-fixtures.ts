/** Materializes the fixture corpus into policy/v1/fixtures/{allow,deny,adversarial}/ (§35). */
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ALLOW, DENY, ADVERSARIAL, type Fixture } from "@ctn/policy/fixtures";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const base = join(root, "policy", "v1", "fixtures");

function write(dir: string, fixtures: Fixture[]) {
  const target = join(base, dir);
  rmSync(target, { recursive: true, force: true });
  mkdirSync(target, { recursive: true });
  for (const f of fixtures) {
    writeFileSync(
      join(target, `${f.id}.json`),
      JSON.stringify(
        {
          id: f.id,
          expected: f.expected,
          description: f.description,
          request: {
            model: "ctn/demo-model-a",
            messages: [{ role: "user", content: f.prompt }],
            // The canonical field, not the gateway's float `temperature`: a
            // fixture's request object is then the exact shape the guest parses
            // (see prover/README.md "The canonical request").
            temperature_millis: 1000,
            max_tokens: 1024,
          },
        },
        null,
        2
      ) + "\n"
    );
  }
  console.log(`${dir}: ${fixtures.length} fixtures`);
}

write("allow", ALLOW);
write("deny", DENY);
write("adversarial", ADVERSARIAL);

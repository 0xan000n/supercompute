# `@ctn/verify` — the TypeScript receipt verifier

`verifyReceipt(receiptBytes, manifest, expect?)` checks a RISC Zero policy
receipt against a pinned release manifest and returns a named check list. It runs
in the coordinator **and** the browser (pure, synchronous, no Node APIs, no
network). The reference implementation it mirrors is `prover/verify`
(`prover/verify/src/lib.rs`); the check **names** match where they overlap so the
two reports read side by side.

```ts
import { verifyReceipt } from "@ctn/verify";
const { ok, checks, delegated } = verifyReceipt(receiptBytes, manifest, {
  decision: "ALLOW",
  commitment: "0x…",
  proofNonce: "0x…",
});
```

## The browser go/no-go spike (Phase 2b §8, Task 5 Step 0): **NO-GO**

**Question.** Can the full receipt **seal** be verified in TypeScript/wasm in a
browser, so the browser action could honestly be called "Verify offline"?

**Answer: NO.** The seal stays **delegated** to the coordinator (which spawns
`prover/verify` server-side, Task 3). The browser action is **"Inspect proof" /
"Verify via coordinator,"** never "offline."

**Evidence.**

- A RISC Zero receipt seal is a zk-STARK. This repo's receipts are `Composite`
  (a vector of segment STARKs — `allow-real`, `adv-004-deny`, `wrong-image`) and
  `Succinct` (one recursive STARK — `allow-succinct`). Verifying either needs the
  full risc0 verifier: the RISC-V circuit + recursion-circuit verification
  parameters and control root of a **specific** risc0 version (here 3.0.6).
- **No pure-TypeScript risc0 verifier exists**, and reimplementing a STARK/FRI
  verifier for the RISC-V circuit is thousands of lines of circuit-specific code
  pinned to exact control IDs — far outside this task, and a second, unaudited
  definition of what "valid" means.
- A **wasm** path exists only as third-party projects that compile risc0's Rust
  verifier with `wasm-pack` (e.g. `eqtylab/risc-zero-verifier` →
  `@eqty/risc-zero-verifier-react`, `zkVerify/risc0-verifier`). Adopting one
  would (a) pin us to **that project's** risc0 version and control root, not our
  image's 3.0.6 — a version/trust mismatch against `prover/release.json`; (b)
  ship a multi-MB circuit-parameter blob into the artifact/browser; and (c)
  swap our audited reference verifier (`prover/verify`: same risc0 3.0.6,
  `disable-dev-mode`, no network by construction) for an unpinned external one.
  That **adds** a trust surface; it does not remove one. None is installed, in
  the dependency tree, or in scope to vet + build here.
- The load-bearing seal check **already runs server-side** on every request via
  the `prover/verify` subprocess (Task 3). A browser seal verifier would
  duplicate it under weaker guarantees.

**Honesty implication.** `verifyReceipt`'s `ok` means **"every LOCAL check
passed."** It is necessary, not sufficient, and **never** asserts the seal. Any
surface that shows a proof as verified must AND the local result with the
coordinator's delegated seal result. Calling the browser flow "offline" would be
a lie: the seal round-trips to the coordinator. Task 6's button is therefore
**"Inspect proof" / "Verify via coordinator,"** it shows which checks ran locally
vs. delegated, and it points independent users at `prover/verify`.

## What is checked LOCALLY vs. DELEGATED

`checks[*].delegated === true` marks a check the seal is required for; it is
always reported `ok:false` here and is listed in `result.delegated`. Delegated
checks do **not** affect `ok`.

| check | where | catches |
| --- | --- | --- |
| `manifest` | LOCAL | a malformed pinned manifest |
| `receipt-codec` | LOCAL | a codec this verifier cannot decode |
| `receipt-decodes` | LOCAL | **malformed / appended / truncated** bytes, and the dev-mode framing |
| `image-id` | **DELEGATED** | **wrong-image** (claimed ImageID lives inside the STARK) |
| `seal` | LOCAL for the dev-mode `Fake` stub; **DELEGATED** otherwise | **dev-mode** locally; every real STARK seal server-side |
| `journal-parses` | LOCAL | a non-object journal |
| `journal-key-set` | LOCAL | **invalid-journal** (key set ≠ the five fields) |
| `journal-protocol-version` | LOCAL | a wrong `protocolVersion` |
| `journal-decision` | LOCAL | a decision outside {ALLOW, DENY} |
| `journal-request-commitment` | LOCAL | a malformed commitment |
| `journal-proof-nonce` | LOCAL | **invalid-journal** (a fat/non-hex `proofNonce`) |
| `policy-id` | LOCAL | a journal `policyId` ≠ the pinned manifest |
| `rules-digest` | **DELEGATED** | re-derivation needs `policy/v1`; the browser only has the pinned digest |
| `expect-commitment` / `expect-decision` / `expect-proof-nonce` | LOCAL | a journal that does not match the gate's expectations |

### Why the local side cannot see `image-id` or the real seal

The claimed ImageID and the STARK proof both live inside the `InnerReceipt`. This
verifier reads only the bincode **framing** (the enum variant tag and the
`journal` `Vec<u8>` at `len - 32`, before the 32-byte `ReceiptMetadata`
trailer). That framing is enough to reject malformed/appended/truncated bytes and
the dev-mode `Fake` stub (variant tag 3, no proof) — but it is **not** a STARK
decode. `wrong-image` (a valid receipt from a different image with a
byte-identical journal) passes every local check; only the delegated
`prover/verify` distinguishes it, at `image-id`.

## The differential (`src/verify.test.ts`)

Ground truth is `prover/verify` run as a subprocess on the same bytes. For every
committed fixture and every hand-built bad receipt — **malformed, appended,
truncated, wrong-image, dev-mode, invalid-journal (bad key set), invalid-journal
(fat proofNonce), wrong policyId** — the test asserts the local side fails at the
right named check (for the checks it owns) and that the **combined** verdict
(`local.ok && proverVerify.ok`) matches `prover/verify`'s exit code. A seal-only
failure the local side cannot see (`wrong-image`) is still caught, because the
combined verdict ANDs in the delegated seal.

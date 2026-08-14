# Receipt fixtures

Five committed receipts, so `cargo test` in `prover/verify` costs seconds rather
than the ~6.5 minutes of proving that produced them. Every one is a real
artifact taken off `prover/host`'s wire contract (`POST /prove` →
`GET /jobs/:id` → base64-decode `receiptB64`), not a hand-assembled structure.

| file | bytes | what it is |
| --- | --- | --- |
| `allow-real.receipt.bin` | 537,794 | composite receipt from image `75751480a7e7…`, decision ALLOW. The one that must verify. |
| `adv-004-deny.receipt.bin` | 526,080 | composite receipt from the same image, decision **DENY**, for a prompt that spells the blocked phrase in fullwidth (`ｂｏｍｂ`). |
| `allow-succinct.receipt.bin` | 223,744 | the same execution as `allow-real` compressed to a succinct receipt. Same journal, same ImageID, 2.4× smaller. |
| `wrong-image.receipt.bin` | 537,794 | a *valid* composite receipt from a **different** image (`f40b7e788996…`), with a byte-identical journal. |
| `dev-mode.receipt.bin` | 719 | what `RISC0_DEV_MODE=1` produces: a stub carrying no proof. |

All five were produced on an M1 Pro (32 GB), release build, CPU-only, one run
each: 124.57 s for `allow-real`, 122.73 s for `wrong-image`, 113.37 s (median of
three) for `adv-004-deny`, 29.52 s for the succinct compression, 59 ms for the
dev stub. These are single runs and prove timings on this machine are noisy at the
±20 % level (Task 4/5 ledger) — they are here to say what regeneration costs, not
as benchmarks.

## Why `adv-004-deny` is not a duplicate of `allow-real`

It is the only artifact in this repository that carries the claim **the Unicode
fold ran inside the zkVM**. Nothing in `policy/v1/rules.json` matches `ｂｏｍｂ`
literally, so this receipt's DENY exists only if §23 normalization folded those
characters to `bomb` *in the image*.
`the_adversarial_receipt_binds_a_fullwidth_prompt_to_a_deny` in `verify.rs` is
what turns that into a check rather than a sentence: it reads the fullwidth prompt
out of `policy/v1/fixtures/adversarial/adv-004.json`, asserts the literal phrase
is absent and appears only after `policy_core::normalize`, rebuilds the canonical
request, recomputes the commitment, and requires the receipt to verify 13/13
against *that* commitment with `--expect-decision DENY`.

This receipt is also the evidence that a composite receipt is **not**
byte-reproducible. Proving `adv-004` twice from identical inputs on this machine
gave two files of exactly 526,080 bytes carrying a byte-identical journal, and
458,964 differing bytes between them. Size is stable and the journal is stable;
the seal is not — compare receipts by verifying them, never by diffing them.

## Regenerating

`generate.py` in this directory drives the daemon and writes a receipt. Run it
from the repository root.

```sh
# 1. the real receipt (~2 minutes)
cargo build --release -p host --manifest-path prover/Cargo.toml
python3 prover/verify/tests/fixtures/generate.py real \
    --binary prover/target/release/host \
    --out prover/verify/tests/fixtures/allow-real.receipt.bin

# 2. the adversarial DENY receipt (~2 minutes). The prompt is the `content` field
#    of policy/v1/fixtures/adversarial/adv-004.json, fullwidth characters and all.
python3 prover/verify/tests/fixtures/generate.py real \
    --binary prover/target/release/host \
    --prompt "$(python3 -c 'import json;print(json.load(open("policy/v1/fixtures/adversarial/adv-004.json"))["request"]["messages"][0]["content"],end="")')" \
    --out prover/verify/tests/fixtures/adv-004-deny.receipt.bin

# 3. the dev-mode stub (instant)
python3 prover/verify/tests/fixtures/generate.py dev \
    --binary prover/target/release/host \
    --out prover/verify/tests/fixtures/dev-mode.receipt.bin
```

`generate.py` canonicalizes with `ensure_ascii=False`, which is what makes step 2
reproduce the committed commitment: `serde_json::to_string` — the canonicalizer
`--bench` uses — emits non-ASCII as raw UTF-8, and Python's default would have
sent `\uff42`-style escapes instead, i.e. different canonical bytes and a
different `requestCommitment`.

The script prints the daemon's `/health` before it proves, so the ImageID a
fixture came from is on the record.

### The succinct receipt

`prover/host` has no compress mode — the daemon ships composite (see
prover/README.md, "Which receipt kind"). The fixture was made with a throwaway
binary in a scratch copy of the tree calling
`default_prover().compress(&ProverOpts::succinct(), &receipt)` on
`allow-real.receipt.bin`. Twenty lines; if it is needed again, write it again
rather than carrying a compress mode nothing in the product uses.

### The wrong-image receipt

This one needs a **second guest image**, and the constraint that makes it
awkward is the constraint the fixture exists to exercise: this repository must
only ever build one image, `75751480a7e7…`, and `policy/v1/*` and the guest
source are off-limits. So the second image is built outside the repository and
nothing about it is committed except the receipt.

```sh
SCRATCH=$(mktemp -d)
rsync -a --exclude 'target/' --exclude '.git' prover "$SCRATCH"/
rsync -a policy "$SCRATCH"/          # the guest build script reads ../../../policy/v1
# Add one comment line above `fn main()` in
# "$SCRATCH/prover/methods/guest/src/main.rs". That is enough: panic locations
# carry source line numbers and are part of the measured image, so every line
# below the edit moves and the ImageID changes. Behaviour does not.
(cd "$SCRATCH/prover" && cargo build --release -p host)      # ~3m25s cold
python3 prover/verify/tests/fixtures/generate.py real \
    --binary "$SCRATCH/prover/target/release/host" \
    --out prover/verify/tests/fixtures/wrong-image.receipt.bin
rm -rf "$SCRATCH"
```

Because only the guest's *source layout* changed and `policy/v1` did not, the
scratch image bakes in the same `POLICY_ID_V2` and `RULES_DIGEST` and commits a
**byte-identical journal** — `verify.rs` asserts that. The two fixtures
therefore differ in exactly one thing, the image that produced them, which is
what makes the `image-id` failure attributable.

## If you regenerate

`prover/release.json`, `allow-real.receipt.bin` and `adv-004-deny.receipt.bin`
have to describe the same image.
`the_committed_manifest_and_fixture_belong_together` in `verify.rs` is the test
that fails if the manifest and `allow-real` drift; the adversarial receipt's own
test fails the same way, on `image-id`. Re-run `cargo run -rp host -- --emit-release
--out release.json` from `prover/` if the image itself changed, and regenerate
**both** real receipts.

`generate.py` is not run by the test suite. The tests read these files; nothing
in CI proves.

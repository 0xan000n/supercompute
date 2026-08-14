# Receipt fixtures

Four committed receipts, so `cargo test` in `prover/verify` costs seconds rather
than the eight minutes of proving that produced them. Every one is a real
artifact taken off `prover/host`'s wire contract (`POST /prove` →
`GET /jobs/:id` → base64-decode `receiptB64`), not a hand-assembled structure.

| file | bytes | what it is |
| --- | --- | --- |
| `allow-real.receipt.bin` | 537,794 | composite receipt from image `75751480a7e7…`, decision ALLOW. The one that must verify. |
| `allow-succinct.receipt.bin` | 223,744 | the same execution compressed to a succinct receipt. Same journal, same ImageID, 2.4× smaller. |
| `wrong-image.receipt.bin` | 537,794 | a *valid* composite receipt from a **different** image (`f40b7e788996…`), with a byte-identical journal. |
| `dev-mode.receipt.bin` | 719 | what `RISC0_DEV_MODE=1` produces: a stub carrying no proof. |

All four were produced on an M1 Pro (32 GB), release build, CPU-only, one run
each: 124.57 s for `allow-real`, 122.73 s for `wrong-image`, 29.52 s for the
succinct compression, 59 ms for the dev stub. These are single runs and prove
timings on this machine are noisy at the ±20 % level (Task 4/5 ledger) — they are
here to say what regeneration costs, not as benchmarks.

## Regenerating

`generate.py` in this directory drives the daemon and writes a receipt. Run it
from the repository root.

```sh
# 1. the real receipt (~2 minutes)
cargo build --release -p host --manifest-path prover/Cargo.toml
python3 prover/verify/tests/fixtures/generate.py real \
    --binary prover/target/release/host \
    --out prover/verify/tests/fixtures/allow-real.receipt.bin

# 2. the dev-mode stub (instant)
python3 prover/verify/tests/fixtures/generate.py dev \
    --binary prover/target/release/host \
    --out prover/verify/tests/fixtures/dev-mode.receipt.bin
```

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

`prover/release.json` and `allow-real.receipt.bin` have to describe the same
image. `the_committed_manifest_and_fixture_belong_together` in `verify.rs` is
the test that fails if they drift; re-run `cargo run -rp host -- --emit-release
--out release.json` from `prover/` if the image itself changed.

`generate.py` is not run by the test suite. The tests read these files; nothing
in CI proves.

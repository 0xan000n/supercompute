# Supercompute

**A compute trust network where resource owners can contribute AI capacity while cryptographically constraining how it is used.**

This is a working v0.1 prototype of the primitive:

```
private workload
        +
contributor-controlled resource
        +
attested execution
        +
policy constraint
        +
verifiable evidence
        =
trust-minimised shared compute
```

Five people contribute API credentials. An application makes requests against one
endpoint. Each request is encrypted in the caller's browser, decrypted only inside
an attested confidential service, evaluated against an exact version of Safety
Policy v1, proved to have been allowed, routed through an eligible contributed
credential, and returned with a signed compute receipt. The whole execution path
is visible as a live graph. The prompt never is.

---

## Run it

Requires Node 22+ and pnpm. No Docker, no database server, no cloud account.

```bash
pnpm install
pnpm dev        # mock-provider, tee-sim, coordinator, web
pnpm seed       # 5 contributors, 5 credentials, some demo traffic
```

Then open **http://localhost:3000**.

| | |
|---|---|
| web | http://localhost:3000 |
| coordinator | http://127.0.0.1:4200 |
| confidential service | http://127.0.0.1:4400 · **simulated** |
| mock upstream provider | http://127.0.0.1:4300 |

`pnpm reset` wipes local state (database, vault, provider log). Restart `pnpm dev`
afterwards so the enclave re-provisions its vault, then `pnpm seed` again.

### Building the prover

**Nothing above requires Rust.** `prover/` does, and it is two toolchains rather
than one — an ordinary Rust toolchain for the host, and a second one that `rzup`
fetches for the zkVM target:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
curl -L https://risczero.com/install | bash
export PATH="$HOME/.risc0/bin:$PATH"
rzup install        # fetches a Rust toolchain for the zkVM target; takes a few minutes
```

`prover/rust-toolchain.toml` pins the host channel to `1.97.1`, so the first
`cargo` command inside `prover/` installs that exact compiler if rustup does not
already have it. Both installers write outside the working tree (`~/.cargo`,
`~/.rustup`, `~/.risc0`). A cold `cargo build --release -p host` takes
**3m30s-4m30s** on an M1 Pro, most of it compiling the guest; where it lands in
that range is what else the machine is doing (the low end is an idle machine,
the high end was measured with other work running). A **warm** rebuild with
nothing edited is a no-op — under a second — which was not true until
`prover/methods/build.rs` stopped `risc0-build`'s always-rebuild hack from
re-running the guest build script on every invocation.

```bash
cd prover
cargo run -rp host -- --bench --fixtures    # the gate cost, over all 125 fixtures (~30 s)
cargo run -rp host -- --bench               # + three real proofs (about 24 minutes)
cd ..                                       # the verifier's defaults are repo-root-relative:
                                            # --release defaults to prover/release.json, and
                                            # the policy dir to policy/v1 *relative to it*
cargo run --release --manifest-path prover/verify/Cargo.toml -p prover-verify -- \
  --receipt prover/verify/tests/fixtures/allow-real.receipt.bin
```

**What `prover/` is, and what it is not.** It *is* a real RISC Zero zkVM program
whose guest image is Safety Policy v1 — the ruleset is compiled into the image,
the request commitment is recomputed inside the zkVM, and the journal it commits
is a fixed five-field allowlist — plus a local daemon that executes and proves
against it and a standalone offline verifier (`prover-verify`) that checks a
receipt against a pinned `release.json` with no network access and no trust in
whoever produced the receipt. Every proof and every number in
[prover/README.md](prover/README.md) is real: dev mode is refused outright, the
prover backend is enforced local, and a composite proof of one policy evaluation
takes two to three minutes of CPU on an M1 Pro.

It is **not** wired into the demo. Nothing in `services/`, `apps/` or `scripts/`
calls it; `pnpm dev` never starts it; no request that goes through this prototype
produces a RISC Zero receipt. Every proof artifact the running demo shows is
still `simulated-reexec` — the enclave re-executes the policy from the witness
and signs the journal, which is not a zero-knowledge proof and is labelled that
way in the UI, the API and `VALIDATION.md`. Connecting the two is Phase 2b. Until
that lands, the correct summary is "the repository contains a real prover, and
the demo does not use it", and any reading of the form "the demo now has real ZK
proofs" is wrong.

---

## The five-minute demo

1. **Network** — five contributors on the left, their credentials beside them, the
   TEE and policy in the centre, providers and models on the right. Each request
   is one horizontal row. Click any request: commitment, policy result, proof
   state, which contributor served it, token counts, timings. Prompt: `PRIVATE`.
2. **Playground** — send a request. Watch the phases: the enclave is attested
   *before* anything is encrypted, the request is sealed in the browser, policy
   returns ALLOW, then proving and inference run **in parallel** (the bracket in
   the timeline). The response decrypts in the browser; the coordinator only ever
   relayed ciphertext. Switch the preset to the denied prompt: policy returns
   DENY, no credential is decrypted, no provider is called, and the graph shows a
   request with no downstream path.
3. **Contribute** — the strongest moment. The attestation is fetched and verified
   in the browser *before the key field appears*. The key is HPKE-sealed to the
   attested ingress key; only ciphertext is posted. Afterwards the raw credential
   reads `HIDDEN` everywhere, forever.
4. **Contributors** — full accounting per contributor: requests served, tokens,
   estimated spend, signed capability, operational caps. No request contents.
5. **Policy Lab** — run a prompt through the policy without revealing it. See the
   public journal: five fields, none derived from the prompt.
6. **Trust Model** — what is established, what is not, and the measured answer to
   "does proving cost the caller anything?".

---

## Verify the claims instead of believing them

```bash
pnpm test                                  # policy fixtures, canonicalisation, crypto, invariants + the differential
pnpm test:differential                     # TS policy engine vs the Rust one the guest runs (part of `pnpm test`)
pnpm test:e2e                              # 28 security, routing and privacy cases (§53–56, §36, §5.1)
pnpm privacy-test                          # canary sweep across every persisted surface
pnpm verify-receipt <requestId>            # independent receipt + proof + binding check
```

`pnpm test` (which includes the differential) and `pnpm test:differential` need
the **RISC Zero** toolchain, not just Rust — the "Requires Node 22+" line above
covers running the demo, not verifying it: since the
guest suite landed it builds the zkVM guest ELF and runs the real image, so a cold
cache costs ~1m40s (a warm one is a no-op) and it fails loudly rather than skip. It
is the only thing keeping `prover/policy-core` (the engine a proof is about)
identical to `packages/policy` (the engine the gateway enforces). Per run it compares
125 fixtures and 500 generated Unicode adversarial cases field for field, sweeps all
1,112,064 Unicode code points for normalizer divergence, puts 6 requests end to end
through the compiled guest, and cross-checks the manifest canonicalizer — half of
`POLICY_ID_V2` — against the TypeScript one on 18 hostile documents.

That sweep finds 133 code points where the two engines disagree, because Node's ICU
is Unicode 16.0 and Rust's tables are 17.0. **The disagreement is bidirectional**: at
104 of them the Rust engine is stricter than the TypeScript one, and at the same 104
it is *laxer* when the folded character lands inside a negative context modifier
instead of a target phrase. Since the guest is the authoritative engine once proofs
are in the path, the TypeScript preview can disagree with the real gate in either
direction on this input. The harness enforces a recorded inventory of that skew —
it may shrink, it must not grow, and any divergence on long-stable characters fails
the build. VALIDATION.md §2c has the census and the argument.

`pnpm test:e2e` runs entirely against the local mock upstream and costs nothing. Two
further cases talk to a **real provider on a real account** and are therefore skipped
unless you opt in by supplying a key:

```bash
ANTHROPIC_API_KEY=sk-ant-… OPENAI_API_KEY=sk-… pnpm test:e2e   # adds cases 70 and 71
```

Each contributes the key as a capped credential, sends one 16-token prompt (well
under a cent), asserts the receipt carries real provider-reported token counts and
the pinned price table's digest, and then revokes the credential — whether the case
passed or failed. Revocation is terminal: the coordinator refuses to write any status
over `DELETED`, so a revoked key cannot be re-enabled. It does not erase the sealed
ciphertext from the enclave vault, so rotate any key you smoke-test with, or
`pnpm reset` afterwards.

`verify-receipt` recomputes every signature and hash locally against the attested
public keys. It does not ask the network whether its own artifacts are valid.

`privacy-test` submits a unique canary prompt and a unique credential secret, then
searches the database (raw bytes, including the WAL), the graph projection, every
API response and the on-disk vault. It expects **zero** occurrences everywhere
except the mock provider's received-log — which plays the upstream provider and is
*supposed* to have the prompt. That one expected hit is what makes the result
meaningful: it proves the enclave really decrypted and really called upstream while
no intermediary saw either value.

---

## Architecture

```
browser ──HPKE ciphertext──► coordinator ──ciphertext──► confidential service ──TLS──► provider
                                 │                             │
                                 │                             ├── decrypt request
                            (cannot decrypt)                   ├── canonicalise + commit
                                 │                             ├── Safety Policy v1
                                 ▼                             ├── verify capability signature
                            SQLite + outbox                    ├── decrypt credential
                                 │                             ├── prove policy result
                                 ▼                             └── sign compute receipt
                          graph projector
                                 │
                                 ▼
                        live graph (SSE)
```

| Component | Trust | Sees the prompt |
|---|---|---|
| Browser client | trusted by the user | yes — it wrote it |
| Coordinator | **untrusted** | no, on the secure endpoint |
| Confidential service | trusted, attested | yes |
| Contributor | **untrusted** | no |
| Database / graph / UI | **untrusted** | no |
| Upstream provider | out of scope | **yes** — unavoidably |

### Layout

```
packages/protocol/    canonicalisation, commitments, HPKE, Ed25519, shared types
packages/policy/      Safety Policy v1 engine, policy_id, fixture corpus
packages/client/      the secure client (browser + node, same code)
services/tee-sim/     the confidential service: attestation, vault, policy gate,
                      routing authorisation, provider adapter, prover, receipt signer
services/coordinator/ public API, SQLite, outbox, graph projector, SSE
services/mock-provider/ OpenAI-shaped upstream stand-in
apps/web/             Next.js app: graph, playground, onboarding, dashboards
policy/v1/            manifest, rules, 125 fixtures (50 allow / 50 deny / 25 adversarial)
scripts/              dev launcher, seed, e2e suite, privacy sweep, receipt verifier
prover/               the real RISC Zero prover — Rust workspace, Phase 2a, not yet wired in
```

---

## What is real here, and what is simulated

Read the two labels as one table. A prototype that leaves this implicit is asking to
be quoted on the half that flatters it.

| Piece | Real or simulated | What that actually means |
|---|---|---|
| Provider calls | **Real** | Anthropic and OpenAI adapters call the live APIs with contributed keys, pinned to dated snapshot model IDs. Costs are estimates from a pinned price table over provider-reported token counts; a timeout or unparseable response leaves upstream spend unknown and is booked conservatively. One dispatch per request — never retried. |
| Prompt and credential sealing | **Real** | HPKE to the attested ingress key, performed in the caller's or contributor's own browser. The coordinator relays ciphertext it has no key for; the canary sweep is what checks that, not the claim. |
| Capability signing and enforcement | **Real** | Ed25519 over the capability, verified inside the enclave before any blob is decrypted. Capabilities are immutable — widening one means contributing a new credential. |
| Egress control | **Real** | Hostname allowlist checked inside the trust boundary before any bytes leave, redirects refused rather than followed. A refused redirect is classified as a *dispatched* failure, because the prompt and key already went out on the first hop. |
| Intent replay protection | **Real, but in-memory** | The enclave refuses a sealed intent digest it has already consumed. That set does not survive a restart; what does is structural — the credential id is sealed inside the intent, so a replay can only re-mint the same capability for the same contributor. |
| Spend caps | **Real counters, operational enforcement** | Daily dollar and request limits are counted and enforced, including for dispatches whose outcome was never learned. They live in ordinary application state, so a malicious host could roll them back. |
| Hardware confidentiality | **Simulated** | `SimulatedTEE`: identical protocol, policy, credential handling, routing checks and receipt generation to the Nitro target, in an ordinary process whose memory the host can read. |
| Attestation document | **Simulated platform, real signatures** | The document is genuinely signed by the enclave key and genuinely verified by the client, including nonce freshness — but no PCR measures a real host, so it attests code identity only by convention. |
| Policy proof | **Simulated** (`simulated-reexec`) | The policy is genuinely re-executed from the witness and the journal is signed by an attested key, but there is no succinct argument. |
| Demo traffic and dashboards | **Simulated** (mock upstream) | `pnpm seed` contributes five mock keys against `ctn/demo-model-*`. Every number on the graph, contributor and trust pages comes from that stand-in unless you ran the real-provider smoke tests above. |

## What this establishes

- **Prompt confidentiality from network infrastructure.** On the secure endpoint the
  coordinator only holds an HPKE ciphertext. The canary sweep proves the plaintext
  reaches no log, row, event or graph node.
- **Credential confidentiality.** Keys are sealed in the contributor's browser to the
  attested ingress key, stored only as vault ciphertext, decrypted inside the
  enclave after every capability check passes.
- **Enclave code identity.** The attestation names the build and policy and binds the
  ingress and signing public keys into the attested document. A substituted key
  fails verification in the client, which then refuses to send.
- **Policy execution integrity.** The provider adapter accepts only an
  `AuthorizedRequest`, which only the policy gate can construct. Calling a
  provider before ALLOW is a type error, not a code-review question.
- **Externally verifiable policy results.** A third party can check that a request
  matching a commitment was evaluated by an exact named policy version and
  allowed — without receiving the request.
- **Constrained delegation.** Allowed models and required policy are bound into an
  enclave-signed capability the untrusted coordinator cannot widen. Models are named
  as dated snapshots (`claude-haiku-4-5-20251001`), never as movable aliases, so
  consent cannot be re-pointed at a different model by someone else's release.

## What this does not establish

Read this as carefully as the list above.

- **The upstream provider still sees the prompt.** With a contributed OpenAI or
  Anthropic key the enclave must send the prompt to that provider. The claim is
  "private from contributors and network operators", never "private from the
  inference provider". Closing that gap needs confidential GPUs running open
  models — phase two.
- **Safety Policy v1 is not proof of harmlessness.** The proof establishes
  `SafetyPolicyV1(request) == ALLOW` and nothing more. The policy is a small
  deterministic integer-scoring engine with false positives and false negatives.
  Correct phrasing: *"verified against Safety Policy v1"*. Never *"cryptographically
  proven safe"*.
- **Spend caps are operational, not cryptographic.** Daily dollar and request limits
  live in application state; a malicious host could roll the counters back.
  Everything that surfaces a limit labels it `operationally enforced`.
- **A dispatch whose outcome was never learned has no receipt.** A timeout, a
  mid-flight transport failure or a 200 the adapter cannot parse means the provider
  may have run the completion and billed for it. The cap is charged a conservative
  upper bound so wedged capacity is not the cheapest capacity on the network — but
  there is nothing to sign a receipt over, so in Phase 1 such a request appears only
  as a provider attempt and a usage row. Representing assumed spend properly needs
  the Phase 2 receipt split.
- **This build has no hardware confidentiality.** The confidential service runs in
  simulation: identical protocol, policy, credential handling, routing checks and
  receipt generation to the Nitro target, but in an ordinary process whose memory
  the host can read. Every page carries a banner saying so.
- **There is no authentication.** §5 lists auth as a coordinator responsibility and
  this prototype does not implement it: every endpoint, including credential
  ingestion, accepts unauthenticated requests. That is fine for a single-machine
  demo and is why `pnpm seed` is three lines, but it means this must not be exposed
  to a network. See `VALIDATION.md` §2a.
- **The proof is not yet zero-knowledge.** Artifacts are labelled
  `simulated-reexec`. The policy is genuinely re-executed from the witness and the
  journal is signed by a key bound into the attestation, but there is no succinct
  argument — a verifier who distrusts the enclave learns nothing from it. RISC Zero
  removes that assumption; this build does not.

---

## Deliberate deviations from the specification

Each of these is a substitution of infrastructure, not of architecture.

| Spec | Here | Why, and what it costs |
|---|---|---|
| PostgreSQL | `node:sqlite` | Same schema, table for table. Keeps `pnpm dev` dependency-free. Swapping back is a driver change. |
| Neo4j | SQLite `graph_nodes` / `graph_links` | The graph is still a **projection** built from the outbox, never on the inference path (§42), so Rule 9 holds. The projection logic is the spec's `MERGE` statements; only the adapter differs. |
| Cosmograph | custom canvas renderer | §48 asks for a fixed lane layout with requests animating across it. A force layout rescrambles that on every update. Cosmograph is also CC-BY-NC and pins React 18. |
| RISC Zero zkVM | `simulated-reexec` prover **on the request path** | The reason used to be "no Rust toolchain here"; since Phase 2a that is no longer true — `prover/` holds a real zkVM prover and a real offline verifier. What remains is that nothing calls them: the request path still produces `simulated-reexec` artifacts, and the wiring is Phase 2b. The verification path checks the same journal, image id and commitment bindings a risc0 receipt needs, so the proof system is swappable without touching callers. Labelled honestly everywhere. |
| AWS Nitro Enclaves | `SimulatedTEE` | §38 explicitly provides for this. Only the attestation and vault-unseal modules differ; `TrustedEnvironment` is the seam. |
| `docker compose up` | `pnpm dev` | Four Node processes, one command, nothing to install. |

Two protocol refinements were made where the spec was underspecified:

- **`aad.model`** — the coordinator must route by model, but the model lives inside
  the ciphertext. It is now an authenticated (not encrypted) envelope header, and
  the enclave rejects any request whose header model disagrees with the sealed
  request. The network learns *which* model you asked for, never what you asked.
- **Integer micro-USD in receipts** — the receipt is signed over its canonical form,
  and float serialisation differs across languages. Costs are integers so a
  verifier in another runtime recomputes byte-identical bytes.
- **`ProofBinding`** — the receipt is signed when inference finishes, but proving
  runs in parallel and normally finishes later, so the receipt cannot contain the
  proof digest. Rather than delay the receipt (throwing away the parallelism this
  prototype exists to measure) or mutate it afterwards (rewriting history, §59),
  the enclave issues a second signed statement binding commitment ↔ proof digest.

---

## Measured, not assumed

§66 asks whether zero-knowledge verification has to cost perceived latency. On this
build, with proving running concurrently with inference:

| | p50 |
|---|---|
| Policy evaluation | ~1 ms |
| Provider call | ~450 ms |
| Proof generation | ~2.9 s |
| **Serialised, this would be** | **~3.3 s** |
| **What the caller actually waits** | **~490 ms** |

Live numbers are on the Trust Model page and `GET /v1/stats`. The proof cost is
modelled (`CTN_SIMULATED_PROVING_MS`, default 2400 ms) and labelled as such —
everything else is measured.

The model is optimistic by roughly **50×**. Phase 2a measured the real thing: a
composite RISC Zero proof of one Safety Policy v1 evaluation takes **two to three
minutes** of CPU on an M1 Pro, and the executor-only gate — the part a live
request would actually wait for — costs **56 ms** at the median across all 125
fixtures (`prover/README.md`, `VALIDATION.md` §2c). The architecture survives
that; the proof is an audit artifact, not a gate, so the caller still waits
~490 ms. But "concurrent with the request" is the wrong mental picture. Receipts
land **minutes** after the answer does, and anything that waits on one has to be
built for an artifact that is not there yet.

---

## API

OpenRouter-shaped, so the interface is familiar.

```http
GET  /v1/models                          # counts of available capacity, never whose
GET  /v1/attestation                     # attestation bundle + client-side verification
GET  /v1/build-manifest                  # build id, PCRs, policy id, proof program
POST /v1/secure/chat/completions         # the canonical path: encrypted envelope
POST /v1/chat/completions                # compatibility: plain JSON, weaker, labelled
POST /v1/policy/test                     # evaluate a prompt without revealing it
GET  /v1/requests/:id                    # status, timings, route — never contents
GET  /v1/requests/:id/receipt            # signed receipt + proof + binding + verification
GET  /v1/requests/:id/proof              # proof state and public journal
GET  /v1/graph                           # provenance snapshot
GET  /v1/graph/events                    # live SSE: node.created / node.updated / link.created
GET  /v1/stats                           # p50/p95 per stage, parallelism measurement
```

The compatibility endpoint exists so unmodified OpenAI SDKs work. It is honest
about being weaker: TLS terminates at the coordinator, so the operator *could* see
the prompt. It never persists or logs plaintext, and every response from it carries
`privacy_mode: compatibility`. The demo defaults to the secure endpoint.

---

## Next

- Milestone 7: deploy the same service to a Nitro Enclave — vsock transport,
  real attestation, PCR-conditioned KMS unseal, parent-side TLS relay.
- Milestone 4 properly: ~~compile Safety Policy v1 into a RISC Zero guest~~ —
  done, standalone, on the Phase 2a branch (`prover/`, imageId `ddb7dc54…`); what
  remains is wiring it into the request path and replacing `simulated-reexec`
  (Phase 2b). The verifier already expects that shape.
- Streaming (§31) with encrypted response frames.
- Confidential GPU workers, which is what actually removes the upstream provider
  from the trust boundary.

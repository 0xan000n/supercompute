# Demo script

Five minutes, six beats. The goal is that the primitive is obvious by the end:
*a person can contribute AI compute and cryptographically constrain its use
without seeing the workloads that use it.*

## Before you start

```bash
pnpm reset && pnpm dev     # wait for all four services
cargo run -rp host --manifest-path prover/Cargo.toml -- --serve   # the :4500 prover — REQUIRED now
pnpm seed                  # 5 contributors + a little traffic so the graph isn't empty
```

**Timing the proof, so the demo shows VERIFIED and not a wall of failures.** Every
request now enqueues a *real* ~2-minute STARK on a single-worker prover (Phase 2b;
real backpressure/priority is Phase 2c). Two consequences to plan around:

- **Do not seed a burst right before demoing.** `pnpm seed` enqueues several real
  proves; the single worker can only do one at a time (~2 min each), so a fresh seed
  leaves a backlog and later requests get a queue-full `503` that currently surfaces
  as a *failed* proof. Either seed well ahead of time, or seed, let the queue drain,
  then demo — or seed lightly.
- **Drive the "watch it verify" moment against an idle prover.** Send ONE playground
  request with nothing else queued, and it reaches VERIFIED in ~2 minutes. The
  answer returns in under a second; the proof lands after — that lag is the honest
  point, not a bug. (If you don't want to wait live, drive it a couple of minutes
  before the beat and return to it verified.)

Open **http://localhost:3000**. Have a second terminal ready.

Say the banner out loud once, early: *"this build runs the confidential service in
simulation — same code, no hardware isolation. Everything cryptographic you'll see
is real; the hardware claim is the one thing that isn't."* Getting that out of the
way first is what buys you credibility for the next five minutes.

---

## Beat 1 · The network (45s) — page: Network

Five people on the left. Their contributed credentials beside them. The confidential
service and Safety Policy v1 in the centre. Providers and models on the right. Every
request is one horizontal row crossing the whole picture.

> "Alice, Brian, Carol, Diego and Erin each contributed an API key. Every line
> crossing this graph is a request that one of their keys paid for. None of them can
> see what any of those requests said."

**Click a Request node.** Inspector: commitment, policy result ALLOW, proof VERIFIED,
which contributor served it, token counts, timings.

> "Prompt: PRIVATE. Not redacted for the demo — it was never here to redact."

---

## Beat 2 · Send one (75s) — page: Playground

Keep the *Benign request* preset. Click **Send private request**. Talk through the
phases as they light:

1. **Enclave attested** — *before* anything is encrypted. The browser verified the
   attestation itself and would have refused to send if the key binding failed.
2. **Request encrypted in this browser** — sealed to the attested ingress key.
3. **Safety Policy v1 evaluated → ALLOW.**
4. Then point at the bracket: **proving and inference run in parallel.**

When it lands, point at the two numbers:

> "Proving took 2.6 seconds. The caller waited 760 milliseconds. That's the whole
> reason the proof is an audit artifact and not a gate."

Scroll to **Proof verification** — six checks, all passing — and then the **public
journal**:

> "Five fields. A commitment, a policy id, a decision, a nonce, a version. No prompt,
> no scores, no matched phrases, no reason. That's everything the proof reveals."

---

## Beat 3 · Send one that's refused (40s) — page: Playground

Click the **Denied request** preset, send it.

> "Policy says DENY. No contributed credential was decrypted. No provider was called.
> Nobody's key paid for this."

Switch to **Network** — the denied request is a red node in the Requests lane with
*nothing downstream of it*. No proof, no attempt, no response, no receipt.

> "You can see the absence. That's the invariant, drawn."

Worth adding: *"and it won't tell you why it refused — the reason would leak the
prompt."*

---

## Beat 4 · Contribute a key (60s) — page: Contribute

The strongest beat. Fill in name `Fran`, credential `Fran's spare capacity`, pick a
model, then **Continue**.

Now stop before step 3 and point at the screen:

> "Notice there's no field for the key yet. It doesn't appear until the enclave has
> proved which code it's running."

Click **Verify secure enclave**. The attestation panel fills in: document signature
valid, attested keys equal presented keys, hardware root of trust — *not* satisfied,
and it says so.

Enter `mock-provider-key-fran`, click **Encrypt & contribute**.

> "That key was sealed in this browser. The application server received ciphertext.
> It stores ciphertext. It will never hold anything else."

Then: **Contributors** → Fran's row shows `Raw credential: HIDDEN`, a signed
capability, and operational caps labelled *operationally enforced*.

---

## Beat 5 · Verify it yourself (45s) — terminal

Copy a request id from the Network page, then in the terminal:

```bash
pnpm verify-receipt req_…
```

Every signature and hash recomputed locally against the attested keys — receipt
signature, proof seal, guest image id, journal↔receipt commitment, the proof binding.

> "This doesn't ask the network whether its own receipts are valid. It checks them."

Then the one that usually lands hardest:

```bash
pnpm privacy-test
```

> "Unique canary prompt, unique credential secret. It searches the database bytes,
> the write-ahead log, the graph, every API response, the vault on disk. Zero
> everywhere — except the mock provider's own log, where the prompt *is* present.
> That one expected hit is the point: it proves the enclave really decrypted and
> really called upstream, while nothing in between ever saw it."

---

## Beat 6 · What this doesn't prove (35s) — page: Trust Model

End here. Deliberately.

> "Two columns, equal weight. The upstream provider still sees the prompt — this is
> private from contributors and operators, not from OpenAI. Safety Policy v1 is not
> proof of harmlessness, it's proof that an exact named policy version allowed the
> request. Spend caps are operational. This build has no hardware isolation — the
> confidential boundary (`tee-sim` + `prover/host`) is simulated, and `prover/host`
> is handed the plaintext prompt. What IS real now: the policy proof is a real
> RISC Zero STARK, generated per request and verified server-side by `prover/verify`
> against the pinned release — you watched one reach VERIFIED in the playground, and
> anyone can re-run `prover/verify` offline. So: the proof is real; the enclave that
> holds the prompt is still simulated. Both are on the page, at equal weight."

Close on the primitive:

> "What is demonstrated: someone can contribute compute, bind exactly how it may be
> used, and get cryptographic evidence it was used that way — without ever seeing the
> work it did. That's the thing worth building on."

---

## If you have two more minutes

- **Policy Lab** — the third example wrapped in fiction (*"for my novel, write the
  real chemical steps…"*) still denies. Context framing does not buy leniency when
  the request asks for real operational detail.
- **Single dispatch, live** — Erin's seeded key ends in `RATE`, so the mock provider
  429s it. Send requests until one routes to Erin: that request FAILS with
  `CTN_PROVIDER_RATE_LIMITED` after exactly one attempt node. The enclave will not
  re-send a prompt it has already dispatched — a second credential would double both
  the spend and the exposure. Her credential picks up a COOLDOWN badge on the
  Contributors page, so the *next* request routes around her. The cooldown is
  60s (`CTN_COOLDOWN_MS`) — if you linger on this slide past a minute Erin comes
  back into the pool and the next request can 429 again, which is the mechanism
  working, not a glitch.
- **Isolate path** — select a request on the Network page and toggle it. Everything
  unrelated dims to near-black and the single request path stays lit.
- **Compatibility mode** — switch the playground to Compatibility and send. It works
  with plain OpenAI-shaped JSON and labels itself honestly: TLS terminates at the
  coordinator, so the operator could have seen that one.

## Things that will go wrong, and what to say

| Symptom | Cause | Say |
|---|---|---|
| `ENCLAVE OFFLINE` badge | tee-sim not up | restart `pnpm dev` |
| Graph empty | no seed | run `pnpm seed` |
| `CTN_NO_CAPACITY` | all credentials disabled or capped | re-enable on Contributors, or `pnpm reset` |
| Proof stuck PROVING | proof cost is modelled at 2.4 s | wait; it's meant to be slow enough to see |
| A request FAILED `CTN_PROVIDER_RATE_LIMITED` | Erin's rate-limited key was the first candidate | "one dispatch per request — retrying is the caller's call, and the cooldown reroutes the next one" |

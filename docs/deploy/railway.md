# Deploying the whole demo to Railway

The full Compute Trust Network — web, coordinator, mock provider, and the
enclave (tee-sim **+** the real RISC Zero prover) — as four services in one
Railway project. When it's up you get a public URL where anyone can contribute a
credential, run a prompt, watch the gate + STARK, and verify the receipt — plus
the deck at `/deck.html`.

> **Who runs what.** The repo now carries everything deployable (Dockerfiles,
> per-service `railway.json`, bind-host fixes). The steps below need *your*
> Railway account — Claude can't authenticate for you. Run `railway login`
> yourself (or paste a project token) and drive the CLI/dashboard.

---

## Topology

```
                 ┌──────────── public ────────────┐
  browser ──▶ web (Next.js, /deck.html)            │
     │        └─ built with NEXT_PUBLIC_COORDINATOR_URL = coordinator's public URL
     │
     └──────▶ coordinator (Node + node:sqlite)  ◀── browser calls this directly (CORS origin:true)
                 │
                 │  TEE_URL
                 ▼
              enclave  (INTERNAL only)
                 ├─ tee-sim (Node)  :4400   ← coordinator reaches over railway.internal
                 └─ prover  (Rust)  127.0.0.1:4500  ← loopback ONLY, by design
                 │  MOCK_PROVIDER_URL + egress allowlist
                 ▼
              mock-provider (INTERNAL only)  :4300
```

Two services get a **public domain** (web, coordinator). Two are **internal
only** (enclave, mock-provider) — reached over Railway's private network at
`<service>.railway.internal`.

Why the enclave is one container: the prover daemon binds `127.0.0.1:4500` **by
design** (the plaintext witness must never leave over a non-loopback socket), and
tee-sim spawns the `prover-verify` binary as a local subprocess. So both the Rust
artifacts and the Node service live together and talk over loopback.

---

## One-time setup

```bash
railway login                       # your account
railway init                        # create a project (pick a name, e.g. supercompute)
```

Then create **four services** in that project, all from this GitHub repo
(`0xan000n/compute-trust-network`). For EACH service, in its Settings:

- **Source**: this repo, branch `main` (or your deploy branch).
- **Root Directory**: `/`  ← must be repo root, so the pnpm workspace lockfile is
  in the build context.
- **Config-as-code path**: the service's `railway.json` (see table). This selects
  the right Dockerfile; `dockerfilePath` inside it is repo-root-relative.

| Service name (exact) | Config path | Exposure |
|---|---|---|
| `web` | `apps/web/railway.json` | Public domain |
| `coordinator` | `services/coordinator/railway.json` | Public domain |
| `enclave` | `services/tee-sim/railway.json` | Internal only |
| `mock-provider` | `services/mock-provider/railway.json` | Internal only |

> Service **names matter** — internal DNS is `<name>.railway.internal`. If you
> name the enclave something other than `enclave`, update `TEE_URL` accordingly.

---

## Environment variables

Most wiring is baked into the Dockerfiles (`HOST=::`, fixed internal ports, prover
paths). Only these have to be set per service in Railway:

**coordinator**
| Var | Value |
|---|---|
| `TEE_URL` | `http://enclave.railway.internal:4400` |
| `CTN_DB_PATH` | *(optional)* `/data/coordinator.sqlite` — only if you attach a volume at `/data` |

`COORDINATOR_PORT` is mapped from Railway's injected `$PORT` automatically (see the
Dockerfile CMD). Enable a public domain on this service.

**enclave**
| Var | Value |
|---|---|
| `MOCK_PROVIDER_URL` | `http://mock-provider.railway.internal:4300` |
| `CTN_EGRESS_ALLOWLIST` | `mock-provider.railway.internal:4300` |

*(optional)* attach a volume at `/app/.data` to persist the enclave's KMS key +
wrapped DEK across redeploys — otherwise a redeploy regenerates them and
credentials contributed before the redeploy can no longer be decrypted.

**mock-provider** — nothing required (port + host are baked).

**web** — set as a **build variable** (it's inlined at build time):
| Var | Value |
|---|---|
| `NEXT_PUBLIC_COORDINATOR_URL` | `https://<coordinator's public domain>` |

Enable a public domain on this service too.

---

## Deploy order (matters once)

1. **mock-provider** and **enclave** first (internal). The enclave build is the
   long one (RISC Zero toolchain + a cold guest+host Rust compile — expect
   ~10–25 min the first time). Watch its logs for `=== built image identity ===`.
2. **coordinator** next. Set `TEE_URL`. Generate its public domain and copy it.
3. **web** last. Set `NEXT_PUBLIC_COORDINATOR_URL` to the coordinator domain from
   step 2, then deploy (this value is compiled into the bundle, so it must be set
   *before* the build). Generate its public domain — that's the URL you share.

After a first successful run, redeploys are independent per service; only web must
be rebuilt if the coordinator's domain ever changes.

---

## Seed the demo

The network starts empty. Seed it from your machine, pointed at the deployed
coordinator:

```bash
CTN_COORDINATOR_URL=https://<coordinator-domain> pnpm seed
```

> **Prover load caveat (known, deferred Phase 2c).** The prover is a *single
> worker*. Seeding sends a burst of requests; on a cloud box (slower than an M1)
> the STARK queue can fill and some proofs will show as **FAILED (queue full)** —
> that's backpressure, not a policy denial. For a clean demo: seed once, let the
> queue drain, and drive the live "prove" moment against an idle prover. Sharing
> a public link with many simultaneous clickers will surface this; a handful of
> people taking turns is fine. If you want it robust under real traffic, do the
> Phase 2c backpressure work before sharing widely.

---

## Troubleshooting

**Enclave build fails / times out.** It's the RISC Zero compile. Likely causes:
- *GitHub rate limit* pulling risc0 releases → set a `GITHUB_TOKEN` build arg/var
  on the enclave service.
- *Build timeout* on Railway's builder → build the image locally with
  `docker buildx build --platform linux/amd64 -f services/tee-sim/Dockerfile -t <registry>/enclave .`,
  push to a registry, and point the enclave service at the prebuilt image instead
  of the Dockerfile.
- *Missing runtime lib* (host binary won't start) → the runtime stage already
  installs `libssl3` + `libstdc++6`; if a log shows another missing `.so`, add it
  there.

**Every request returns `PROVER_UNAVAILABLE`.** The enclave/prover isn't
reachable. Check the enclave logs for `prover is healthy`; confirm the coordinator's
`TEE_URL` names the enclave service exactly and the enclave is deployed.

**A service starts but Railway marks it unhealthy / unreachable.** It's binding
loopback. Confirm `HOST=::` is set (it's baked in the Dockerfiles) — the code
defaults to `127.0.0.1` only when `HOST` is unset.

**Browser console: CORS / network error to the coordinator.** `NEXT_PUBLIC_COORDINATOR_URL`
was wrong or unset at web build time. It must be the coordinator's *public https*
domain, and web must be rebuilt after changing it.

**ImageID note.** The enclave regenerates `release.json` from its own build, so the
verifier and the daemon always agree and receipts verify. The RISC Zero guest is
compiled for RISC-V regardless of host arch and the toolchain is pinned, so the
ImageID *should* reproduce as the committed `ddb7dc54…`. If the deployed ImageID
differs, that's a cosmetic mismatch with the value baked into the static deck —
not a functional break; VERIFIED still works because the manifest matches the
running daemon.
```

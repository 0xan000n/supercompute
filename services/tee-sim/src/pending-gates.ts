/**
 * Phase 2b §3 — bounded, TTL-enforced parking for the ALLOW gate outcome that
 * lives between `/gate` and `/execute` in the two-call protocol.
 *
 * The parked value is DECRYPTED plaintext (the gate witness: prompt, canonical
 * request, authorized state), so its residency MUST be bounded in TIME, not just
 * in count. Three eviction forces, all of them real:
 *
 *   • consume()       — the happy path: `/execute` takes the entry, milliseconds
 *                       after `/gate` parked it, and it is gone the instant it is
 *                       used.
 *   • reap-on-insert  — every `remember()` first sweeps entries older than
 *                       `ttlMs`. This is what makes the TTL enforced under load
 *                       (an earlier version only reaped when the map was full,
 *                       so the TTL was effectively dead below the ceiling).
 *   • background sweep — a low-frequency timer (`startSweeper()`, unref'd) reaps
 *                       an IDLE map even when no new inserts arrive. Reap-on-
 *                       insert alone leaves plaintext parked once traffic stops;
 *                       the sweep closes that window (e.g. a no-capacity ALLOW,
 *                       whose `/execute` is never called).
 *   • max             — a hard count bound; the oldest are dropped if the map is
 *                       still full after reaping.
 *
 * consume() is BOUND TO THE REQUEST COMMITMENT. The map key is the client-
 * controlled `requestId`; the commitment is a hash of the secret prompt+nonce
 * that only the party which received the `/gate` response holds. An `/execute`
 * that names a parked `requestId` but cannot reproduce its commitment is
 * rejected without consuming or redirecting the victim's entry.
 */

/** The outcome of a consume attempt. MISMATCH leaves the parked entry intact. */
export type ConsumeResult<T> =
  | { status: "MISS" }
  | { status: "MISMATCH" }
  | { status: "HIT"; value: T };

export interface PendingGatesOptions {
  /** Max age of a parked entry before it is reaped. */
  ttlMs: number;
  /** Hard upper bound on the number of parked entries. */
  max: number;
  /** Background sweep cadence; defaults to 30s. */
  sweepIntervalMs?: number;
  /** Injectable clock (tests advance it past the TTL without waiting). */
  now?: () => number;
}

export class PendingGates<T> {
  private readonly entries = new Map<string, { value: T; commitment: string; at: number }>();
  private readonly ttlMs: number;
  private readonly max: number;
  private readonly sweepIntervalMs: number;
  private readonly now: () => number;

  constructor(opts: PendingGatesOptions) {
    this.ttlMs = opts.ttlMs;
    this.max = opts.max;
    this.sweepIntervalMs = opts.sweepIntervalMs ?? 30_000;
    this.now = opts.now ?? Date.now;
  }

  get size(): number {
    return this.entries.size;
  }

  /**
   * Park a gate outcome under `key`, bound to `commitment`. Reaps expired
   * entries first (TTL enforced on EVERY insert), then enforces the hard count
   * bound by dropping the oldest.
   */
  remember(key: string, commitment: string, value: T): void {
    const now = this.now();
    this.reap(now);
    // Map iteration is insertion-ordered, so this drops the oldest first.
    while (this.entries.size >= this.max) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
    this.entries.set(key, { value, commitment, at: now });
  }

  /**
   * Consume the entry parked under `key` iff it is unexpired AND its commitment
   * matches. An expired entry is dropped and reported as a MISS. A commitment
   * mismatch is reported without evicting the entry (so the legitimate holder can
   * still consume it) and without exposing anything about the parked request.
   */
  consume(key: string, commitment: string): ConsumeResult<T> {
    const entry = this.entries.get(key);
    if (!entry) return { status: "MISS" };
    if (this.now() - entry.at > this.ttlMs) {
      this.entries.delete(key);
      return { status: "MISS" };
    }
    if (entry.commitment !== commitment) return { status: "MISMATCH" };
    this.entries.delete(key);
    return { status: "HIT", value: entry.value };
  }

  /** Reap every entry older than the TTL. Returns the count removed. */
  sweep(): number {
    return this.reap(this.now());
  }

  private reap(now: number): number {
    let removed = 0;
    for (const [key, entry] of this.entries) {
      if (now - entry.at > this.ttlMs) {
        this.entries.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  /**
   * Start the low-frequency background sweep so an idle map with parked plaintext
   * still reaps on time. The timer is unref'd — it never keeps the process alive.
   * Returns a stop handle (used by tests; the server runs it for its lifetime).
   */
  startSweeper(): () => void {
    const timer = setInterval(() => this.sweep(), this.sweepIntervalMs);
    if (typeof (timer as { unref?: () => void }).unref === "function") {
      (timer as { unref: () => void }).unref();
    }
    return () => clearInterval(timer);
  }
}

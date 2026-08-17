import { test } from "node:test";
import assert from "node:assert/strict";
import { PendingGates } from "./pending-gates.js";

/**
 * These tests are the regression guard the Task-2 reviewer asked for: they FAIL
 * if the reap/TTL is removed (a parked entry then lives forever) or if the
 * commitment binding is dropped (any /execute could consume any parked gate).
 * A controllable clock lets the tests advance time past the TTL without waiting.
 */
function fakeClock(start = 1_000_000): { now: () => number; advance: (ms: number) => void } {
  let t = start;
  return { now: () => t, advance: (ms) => (t += ms) };
}

const TTL = 60_000;

test("reap-on-insert: a parked entry older than the TTL is gone after the next insert", () => {
  const clock = fakeClock();
  const gates = new PendingGates<string>({ ttlMs: TTL, max: 10_000, now: clock.now });

  gates.remember("req-A", "0xcommitA", "plaintext-A");
  assert.equal(gates.size, 1);

  // Time passes beyond the TTL, then a *second, unrelated* request is gated.
  clock.advance(TTL + 1);
  gates.remember("req-B", "0xcommitB", "plaintext-B");

  // A retained req-A would make this size 2 — that is exactly the bug the reap
  // closes. Inserting B must first sweep the expired A.
  assert.equal(gates.size, 1, "reap-on-insert must evict the expired entry when a new one is parked");
  assert.deepEqual(gates.consume("req-A", "0xcommitA"), { status: "MISS" }, "the reaped plaintext must not be consumable");
  assert.equal(gates.consume("req-B", "0xcommitB").status, "HIT");
});

test("background sweep: an IDLE map with parked plaintext reaps on time with no new inserts", () => {
  const clock = fakeClock();
  const gates = new PendingGates<string>({ ttlMs: TTL, max: 10_000, now: clock.now });

  gates.remember("req-A", "0xcommitA", "plaintext-A");
  assert.equal(gates.size, 1);

  // No further inserts arrive (traffic stops). Reap-on-insert alone would leave
  // the plaintext parked forever; the sweep is what closes that window.
  clock.advance(TTL + 1);
  const reaped = gates.sweep();

  assert.equal(reaped, 1, "sweep must report the entry it reaped");
  assert.equal(gates.size, 0, "the idle map must be empty after a sweep past the TTL");
  assert.deepEqual(gates.consume("req-A", "0xcommitA"), { status: "MISS" });
});

test("no-capacity ALLOW: a never-consumed entry does not stay parked past the TTL", () => {
  const clock = fakeClock();
  const gates = new PendingGates<string>({ ttlMs: TTL, max: 10_000, now: clock.now });

  // Models the no-capacity ALLOW: /gate parks the plaintext, /execute is NEVER
  // called (coordinator returns CTN_NO_CAPACITY). Its reaping IS the TTL.
  gates.remember("req-nocap", "0xcommit", "decrypted-prompt");
  clock.advance(TTL + 1);
  gates.sweep();

  assert.equal(gates.size, 0, "an abandoned no-capacity ALLOW must be reaped, not retained");
  assert.deepEqual(gates.consume("req-nocap", "0xcommit"), { status: "MISS" });
});

test("consume of an expired entry is a MISS even with the correct commitment", () => {
  const clock = fakeClock();
  const gates = new PendingGates<string>({ ttlMs: TTL, max: 10_000, now: clock.now });

  gates.remember("req-A", "0xcommitA", "plaintext-A");
  clock.advance(TTL + 1);

  // Even a caller that knows the right commitment cannot consume a stale gate.
  assert.deepEqual(gates.consume("req-A", "0xcommitA"), { status: "MISS" });
  assert.equal(gates.size, 0, "the expired entry is dropped on the consume attempt");
});

test("commitment binding: a mismatched /execute is rejected and does NOT consume the victim gate", () => {
  const clock = fakeClock();
  const gates = new PendingGates<string>({ ttlMs: TTL, max: 10_000, now: clock.now });

  // Victim's ALLOW is parked under its real commitment.
  gates.remember("req-victim", "0xVICTIMcommit", "victim-plaintext");

  // Attacker learns the pending requestId but not the commitment (a hash of the
  // secret prompt+nonce). Their /execute presents a different/absent commitment.
  assert.deepEqual(gates.consume("req-victim", "0xATTACKERcommit"), { status: "MISMATCH" });
  assert.deepEqual(gates.consume("req-victim", ""), { status: "MISMATCH" });

  // The victim's gate must still be intact and consumable by the real party.
  assert.equal(gates.size, 1, "a mismatched consume must not evict or redirect the victim gate");
  assert.deepEqual(gates.consume("req-victim", "0xVICTIMcommit"), { status: "HIT", value: "victim-plaintext" });
  assert.equal(gates.size, 0);
});

test("happy path: consume returns the parked value exactly once", () => {
  const gates = new PendingGates<string>({ ttlMs: TTL, max: 10_000 });
  gates.remember("req-A", "0xc", "payload");
  assert.deepEqual(gates.consume("req-A", "0xc"), { status: "HIT", value: "payload" });
  // A second consume finds nothing — the plaintext is gone the instant it is used.
  assert.deepEqual(gates.consume("req-A", "0xc"), { status: "MISS" });
});

test("hard bound: PENDING_MAX is never exceeded; the oldest is dropped", () => {
  const clock = fakeClock();
  const gates = new PendingGates<number>({ ttlMs: TTL, max: 3, now: clock.now });

  // All within the TTL, so the count bound (not the TTL) is what evicts.
  for (let i = 0; i < 5; i++) {
    clock.advance(1);
    gates.remember(`req-${i}`, `0xc${i}`, i);
  }

  assert.equal(gates.size, 3, "size must be clamped to max");
  // The two oldest were dropped to make room.
  assert.equal(gates.consume("req-0", "0xc0").status, "MISS");
  assert.equal(gates.consume("req-1", "0xc1").status, "MISS");
  assert.equal(gates.consume("req-4", "0xc4").status, "HIT");
});

test("startSweeper wires sweep() onto an unref'd timer that actually fires", async () => {
  const clock = fakeClock();
  const gates = new PendingGates<string>({ ttlMs: TTL, max: 10_000, sweepIntervalMs: 5, now: clock.now });

  gates.remember("req-A", "0xc", "plaintext");
  clock.advance(TTL + 1);

  const stop = gates.startSweeper();
  try {
    // Give the real interval a couple of ticks to fire the (clock-advanced) sweep.
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(gates.size, 0, "the background timer must have reaped the expired entry");
  } finally {
    stop();
  }
});

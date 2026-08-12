import { test } from "node:test";
import assert from "node:assert/strict";
import { enclaveSafe, enclaveLog } from "./enclave-log.js";

/**
 * §57 inside the trust boundary. This process holds the plaintext provider key,
 * and stdout is the one channel that leaves the enclave, so the refusal is
 * tested against the real key shapes rather than assumed.
 */

const REDACTED = "[redacted-by-enclaveSafe]";

test("real Anthropic and OpenAI key material never reaches stdout", () => {
  assert.equal(enclaveSafe("sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA"), REDACTED);
  assert.equal(enclaveSafe("sk-proj-BBBBBBBBBBBBBBBBBBBBBBBB"), REDACTED);
  assert.equal(enclaveSafe("Bearer sk-ant-real-key-123456789"), REDACTED);
  assert.equal(enclaveSafe("mock-provider-key-CCCCCCCC"), REDACTED);
});

test("a key embedded in an upstream error message is redacted, not truncated", () => {
  // The dangerous case: short enough to escape the length cap, so only the
  // value patterns stand between the key and the parent's stdout.
  const message = "upstream 401: header x-api-key=sk-ant-api03-DDDDDDDDDDDDDDDD rejected";
  assert.ok(message.length < 160, "must be under the truncation cap for this test to mean anything");
  assert.equal(enclaveSafe(message), REDACTED);
});

test("provider metadata survives, so enclave logs stay useful", () => {
  assert.equal(enclaveSafe("2023-06-01"), "2023-06-01");
  assert.equal(enclaveSafe("claude-sonnet-4-5"), "claude-sonnet-4-5");
  assert.equal(enclaveSafe("cred_1"), "cred_1");
});

test("enclaveLog scrubs field values on the way to the console", () => {
  const lines: string[] = [];
  const original = console.log;
  console.log = (line: string) => void lines.push(line);
  try {
    enclaveLog("dispatch", {
      credentialId: "cred_1",
      header: "x-api-key: sk-ant-api03-EEEEEEEEEEEEEEEE",
      httpStatus: 200,
    });
  } finally {
    console.log = original;
  }
  assert.equal(lines.length, 1);
  assert.ok(!lines[0].includes("sk-ant"), `key leaked: ${lines[0]}`);
  assert.ok(lines[0].includes("credentialId=cred_1"));
  assert.ok(lines[0].includes("httpStatus=200"));
});

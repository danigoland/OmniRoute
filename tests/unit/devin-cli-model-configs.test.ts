import { gzipSync } from "node:zlib";
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DEVIN_CLI_MODEL_CONFIGS_PATH,
  encodeDevinDesktopAuthRequest,
} from "../../open-sse/executors/devin-desktop.ts";
import {
  fetchDevinCliModelConfigs,
  parseDevinCliModelConfigs,
} from "../../open-sse/services/devinDesktopModels.ts";

function varint(value: number): Uint8Array {
  const bytes: number[] = [];
  let remaining = value;
  while (remaining >= 0x80) {
    bytes.push((remaining % 0x80) | 0x80);
    remaining = Math.floor(remaining / 0x80);
  }
  bytes.push(remaining);
  return Uint8Array.from(bytes);
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(arrays.reduce((total, bytes) => total + bytes.length, 0));
  let offset = 0;
  for (const bytes of arrays) {
    result.set(bytes, offset);
    offset += bytes.length;
  }
  return result;
}

function bytesField(fieldNumber: number, payload: Uint8Array): Uint8Array {
  return concat(varint((fieldNumber << 3) | 2), varint(payload.length), payload);
}

function stringField(fieldNumber: number, value: string): Uint8Array {
  return bytesField(fieldNumber, new TextEncoder().encode(value));
}

function varintField(fieldNumber: number, value: number): Uint8Array {
  return concat(varint(fieldNumber << 3), varint(value));
}

function catalogItem(input: { name: string; id: string; context?: number }): Uint8Array {
  const parts = [stringField(1, input.name), stringField(22, input.id)];
  if (input.context != null) parts.push(varintField(18, input.context));
  return bytesField(1, concat(...parts));
}

test("parseDevinCliModelConfigs reads name, wire id, and context", () => {
  const payload = concat(
    catalogItem({ name: "SWE-1.7 Max", id: "swe-1-7", context: 262000 }),
    catalogItem({ name: "Adaptive", id: "adaptive", context: 1000 }),
    catalogItem({ name: "Subagent Default", id: "subagent-default", context: 1000 }),
    catalogItem({
      name: "Memory Migration Default",
      id: "memory-migration-default",
      context: 1000,
    }),
    catalogItem({ name: "Claude Opus 5 Medium", id: "claude-opus-5-medium", context: 1000000 })
  );
  assert.deepEqual(parseDevinCliModelConfigs(payload), [
    { id: "swe-1-7", name: "SWE-1.7 Max", contextLength: 262000 },
    { id: "claude-opus-5-medium", name: "Claude Opus 5 Medium", contextLength: 1000000 },
  ]);
});

test("parseDevinCliModelConfigs unwraps gzip and connect frames", () => {
  const inner = catalogItem({ name: "Kimi K3 High", id: "kimi-k3-high", context: 1048576 });
  const gzipped = gzipSync(inner);
  assert.deepEqual(parseDevinCliModelConfigs(gzipped), [
    { id: "kimi-k3-high", name: "Kimi K3 High", contextLength: 1048576 },
  ]);

  const header = Buffer.alloc(5);
  header.writeUInt32BE(inner.length, 1);
  assert.deepEqual(parseDevinCliModelConfigs(concat(header, inner)), [
    { id: "kimi-k3-high", name: "Kimi K3 High", contextLength: 1048576 },
  ]);
});

test("fetchDevinCliModelConfigs posts metadata-only GetCliModelConfigs", async () => {
  const calls: Array<{ url: string; headers: Headers; body: Uint8Array }> = [];
  const payload = catalogItem({ name: "SWE-1.6", id: "swe-1-6", context: 200000 });
  const result = await fetchDevinCliModelConfigs({
    apiKey: "devin-session-token$test",
    fetchImpl: async (url, init) => {
      calls.push({
        url: String(url),
        headers: new Headers(init?.headers),
        body: new Uint8Array(await new Response(init?.body).arrayBuffer()),
      });
      return new Response(Buffer.from(payload), { status: 200 });
    },
  });

  assert.equal(result.source, "api");
  assert.deepEqual(result.models, [{ id: "swe-1-6", name: "SWE-1.6", contextLength: 200000 }]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url.endsWith(DEVIN_CLI_MODEL_CONFIGS_PATH), true);
  assert.equal(calls[0].headers.get("content-type"), "application/proto");
  const expected = encodeDevinDesktopAuthRequest({
    apiKey: "devin-session-token$test",
    sessionId: "",
  });
  assert.deepEqual(calls[0].body, expected);
});

test("fetchDevinCliModelConfigs prefixes a bare JWT as a Devin session token", async () => {
  let sent: Uint8Array | undefined;
  const payload = catalogItem({ name: "SWE-1.6", id: "swe-1-6", context: 200000 });
  await fetchDevinCliModelConfigs({
    apiKey: "eyJhbGciOiJub25lIn0.e30.x",
    fetchImpl: async (_url, init) => {
      sent = new Uint8Array(await new Response(init?.body).arrayBuffer());
      return new Response(Buffer.from(payload), { status: 200 });
    },
  });
  assert.ok(sent);
  const expected = encodeDevinDesktopAuthRequest({
    apiKey: "devin-session-token$eyJhbGciOiJub25lIn0.e30.x",
    sessionId: "",
  });
  assert.deepEqual(sent, expected);
});

test("fetchDevinCliModelConfigs returns error on empty or failed catalog", async () => {
  const empty = await fetchDevinCliModelConfigs({
    apiKey: "x",
    fetchImpl: async () => new Response(new Uint8Array(), { status: 200 }),
  });
  assert.equal(empty.source, "error");

  const failed = await fetchDevinCliModelConfigs({
    apiKey: "x",
    fetchImpl: async () => new Response("nope", { status: 401 }),
  });
  assert.equal(failed.source, "error");
  assert.equal(failed.error, "HTTP 401");
});

test("fetchDevinCliModelConfigs returns an error for oversized bodies without throwing", async () => {
  const oversized = new Uint8Array(2 * 1024 * 1024 + 1);
  const result = await fetchDevinCliModelConfigs({
    apiKey: "x",
    fetchImpl: async () => new Response(oversized, { status: 200 }),
  });

  assert.equal(result.source, "error");
  assert.match(result.error ?? "", /safety limit/);
});

test("fetchDevinCliModelConfigs returns an error for malformed protobuf without throwing", async () => {
  const result = await fetchDevinCliModelConfigs({
    apiKey: "x",
    fetchImpl: async () => new Response(Uint8Array.from([0x80]), { status: 200 }),
  });

  assert.equal(result.source, "error");
  assert.match(result.error ?? "", /protobuf/);
});

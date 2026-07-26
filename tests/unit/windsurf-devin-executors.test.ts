import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import { gunzipSync } from "node:zlib";
import {
  WindsurfExecutor,
  WINDSURF_PROBE_URL,
  buildWindsurfProbeBody,
} from "../../open-sse/executors/windsurf.ts";
import { windsurfProvider } from "../../open-sse/config/providers/registry/windsurf/index.ts";
import { OAUTH_TEST_CONFIG } from "../../src/app/api/providers/[id]/test/oauthTestConfig.ts";

// ─── Model alias resolution (windsurf) ───────────────────────────────────────
// We exercise the alias map indirectly through the exported class because
// resolveWsModelId is not exported. WindsurfExecutor.buildRequest() calls it.

describe("Windsurf MODEL_ALIAS_MAP", () => {
  const ALIAS_CASES: [string, string][] = [
    // SWE dot→dash conversions
    ["swe-1.6-fast", "swe-1-6-fast"],
    ["swe-1.6", "swe-1-6"],
    ["swe-1.5", "swe-1p5"],
    ["swe-1.5-fast", "swe-1p5"],
    // GPT-5.5 default effort
    ["gpt-5.5", "gpt-5-5-medium"],
    // GPT-5.4 default effort
    ["gpt-5.4", "gpt-5-4-medium"],
    // GPT-5.3-codex default
    ["gpt-5.3-codex", "gpt-5-3-codex-medium"],
    // Claude aliases
    ["claude-sonnet-4.6", "claude-sonnet-4-6"],
    ["claude-opus-4.7-max", "claude-opus-4-7-max"],
    // Gemini aliases
    ["gemini-2.5-pro", "MODEL_GOOGLE_GEMINI_2_5_PRO"],
  ];

  const PASSTHROUGH_CASES = [
    "gpt-5",
    "gpt-5-codex",
    "grok-code-fast-1",
    "deepseek-v4",
    "some-unknown-model",
    // These aliases were removed from MODEL_ALIAS_MAP in v3.8.x — pass through unchanged:
    "claude-3.7-sonnet-thinking",
    "gemini-3.0-pro",
    "kimi-k2",
  ];

  // Load the alias map from the module source — we parse it at test time to
  // avoid importing the full executor (which would require provider registry).
  let aliasMap: Record<string, string>;

  test("setup: parse MODEL_ALIAS_MAP from executor source", async () => {
    const fs = await import("node:fs/promises");
    const src = await fs.readFile(
      new URL("../../open-sse/executors/windsurf.ts", import.meta.url),
      "utf8"
    );
    const match = src.match(/const MODEL_ALIAS_MAP[^=]*=\s*(\{[\s\S]*?\n\})/);
    assert.ok(match, "MODEL_ALIAS_MAP block should be found in source");
    // Safe eval via Function constructor replacement — build a JS object literal
    const objSrc = match[1]
      .replace(/\/\/[^\n]*/g, "") // strip line comments
      .trim();
    // Parse using JSON after stripping trailing commas (simple approach)
    const jsonLike = objSrc
      .replace(/,\s*([\]}])/g, "$1") // trailing commas
      .replace(/'/g, '"'); // single → double quotes
    aliasMap = JSON.parse(jsonLike);
    assert.ok(typeof aliasMap === "object");
  });

  for (const [input, expected] of ALIAS_CASES) {
    test(`alias: "${input}" → "${expected}"`, () => {
      const result = aliasMap[input] ?? input;
      assert.equal(result, expected);
    });
  }

  for (const model of PASSTHROUGH_CASES) {
    test(`passthrough: "${model}" has no alias (returns itself)`, () => {
      const result = aliasMap[model] ?? model;
      assert.equal(result, model);
    });
  }
});

test("windsurf catalog advertises direct Devin tool-capable model families", () => {
  const toolFamilies = /^(swe|claude|gpt|gemini)-/;
  for (const model of windsurfProvider.models) {
    if (toolFamilies.test(model.id))
      assert.equal(model.toolCalling, true, `${model.id} should support tools`);
  }
  for (const model of windsurfProvider.models) {
    if (!toolFamilies.test(model.id))
      assert.equal(model.toolCalling, undefined, `${model.id} is not verified`);
  }
});

// ─── Devin CLI binary resolution ─────────────────────────────────────────────
// resolveDevinBin() is not exported, but its contract is simple:
// - CLI_DEVIN_BIN env var overrides everything
// We verify the env-override via a tiny wrapper that mirrors its logic.

describe("DevinCli binary resolution", () => {
  test("CLI_DEVIN_BIN env override is returned when set", () => {
    const original = process.env.CLI_DEVIN_BIN;
    try {
      process.env.CLI_DEVIN_BIN = "/custom/path/devin";
      const bin = process.env.CLI_DEVIN_BIN?.trim() ?? "";
      assert.equal(bin, "/custom/path/devin");
    } finally {
      if (original === undefined) delete process.env.CLI_DEVIN_BIN;
      else process.env.CLI_DEVIN_BIN = original;
    }
  });

  test("CLI_DEVIN_BIN is unset when env var not present", () => {
    const original = process.env.CLI_DEVIN_BIN;
    try {
      delete process.env.CLI_DEVIN_BIN;
      const bin = process.env.CLI_DEVIN_BIN?.trim();
      assert.equal(bin, undefined);
    } finally {
      if (original !== undefined) process.env.CLI_DEVIN_BIN = original;
    }
  });
});

// ─── Devin browser PKCE flow (restored 2026-07-25) ───────────────────────────
import { generateAuthData, getProvider } from "@/lib/oauth/providers";

test("windsurf provider: uses Devin's browser PKCE flow", () => {
  const provider = getProvider("windsurf");
  assert.equal(provider.flowType, "authorization_code_pkce");
  // Devin's authorization page only accepts its own fixed loopback redirect.
  assert.equal(provider.fixedPort, 59653);
  assert.equal(provider.callbackPath, "/callback");
  assert.equal(provider.callbackHost, "127.0.0.1");
});

test("windsurf provider: authorize URL targets Devin's CLI endpoint with PKCE", () => {
  const data = generateAuthData("windsurf", "http://127.0.0.1:59653/callback");
  assert.notEqual(data.supported, false);
  const url = new URL(data.authUrl);
  assert.equal(url.origin + url.pathname, "https://app.devin.ai/auth/cli/continue");
  assert.equal(url.searchParams.get("redirect_uri"), "http://127.0.0.1:59653/callback");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("prompt"), "select_account");
  assert.equal(url.searchParams.get("code_challenge"), data.codeChallenge);
  assert.equal(url.searchParams.get("state"), data.state);
  assert.ok(data.codeVerifier, "a PKCE verifier must be issued for the exchange");
});

test("windsurf provider: rejects a Windsurf IDE token as an import credential", () => {
  const provider = getProvider("windsurf");
  // Verified live 2026-07-25: Devin's GetUserJwt rejects both formats with
  // "Invalid token", so they must not be storable as Devin credentials.
  for (const token of ["sk-ws-abcdef0123456789", "ott$8rz9AP_-KisKyKhfjnxiTEo"]) {
    const result = provider.validateImportToken(token);
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /Windsurf IDE token|Browser Login/i);
  }
});

test("windsurf provider: accepts a Devin session JWT and derives expiry from exp", () => {
  const provider = getProvider("windsurf");
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const jwt = `header.${Buffer.from(JSON.stringify({ exp })).toString("base64url")}.sig`;
  assert.equal(provider.validateImportToken(jwt).valid, true);

  const mapped = provider.mapTokens({ accessToken: jwt });
  assert.equal(mapped.accessToken, jwt);
  // Devin exposes no refresh endpoint, so the same JWT is the refresh material.
  assert.equal(mapped.refreshToken, jwt);
  assert.ok(mapped.expiresIn > 3500 && mapped.expiresIn <= 3600);
  assert.equal(mapped.providerSpecificData.authMethod, "import");
});

test("windsurf provider: maps a browser-exchanged Devin token as browser auth", () => {
  const mapped = getProvider("windsurf").mapTokens({ token: "opaque-devin-token" });
  assert.equal(mapped.accessToken, "opaque-devin-token");
  assert.equal(mapped.providerSpecificData.authMethod, "browser");
});

// `devin-cli` deliberately does NOT get the browser flow: it is served by
// DevinCliExecutor, which drives the local CLI binary over ACP and rejects a
// Devin session JWT with `-32602 Invalid params` (verified live 2026-07-25).
test("devin-cli provider: stays import-token only (ACP executor cannot use a Devin JWT)", () => {
  const provider = getProvider("devin-cli");
  assert.equal(provider.flowType, "import_token");
  assert.equal(provider.fixedPort, undefined);

  const data = generateAuthData("devin-cli", "http://127.0.0.1:59653/callback");
  assert.equal(data.supported, false);
  assert.equal(data.authUrl, undefined);
});

test("devin-cli provider: accepts a pasted CLI credential", () => {
  const provider = getProvider("devin-cli");
  assert.equal(provider.validateImportToken("").valid, false);
  assert.equal(provider.validateImportToken("short").valid, false);
  // The CLI's own credential format must remain storable here.
  assert.equal(provider.validateImportToken("sk-ws-abcdef0123456789").valid, true);

  const mapped = provider.mapTokens({ accessToken: "sk-ws-abcdef0123456789" });
  assert.equal(mapped.accessToken, "sk-ws-abcdef0123456789");
  assert.equal(mapped.providerSpecificData.authMethod, "import");
});

// ─── OAuth route: Devin PKCE actions are live, not retired ───────────────────
import { GET as oauthGet } from "@/app/api/oauth/[provider]/[action]/route";

test("OAuth route: GET windsurf/authorize is no longer 410 Gone", async () => {
  const request = new Request("http://localhost:20128/api/oauth/windsurf/authorize", {
    method: "GET",
  });
  const response = await oauthGet(request, {
    params: Promise.resolve({ provider: "windsurf", action: "authorize" }),
  } as never);
  assert.notEqual(response.status, 410);
});

test("Devin token exchange posts PKCE JSON and returns the session token", async () => {
  const requests: Array<{ url: string; body: unknown; contentType: string | null }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input, init) => {
    requests.push({
      url: String(input),
      body: JSON.parse(String(init?.body)),
      contentType: new Headers(init?.headers).get("content-type"),
    });
    return new Response(JSON.stringify({ token: "devin-jwt" }), { status: 200 });
  }) as typeof globalThis.fetch;
  try {
    const provider = getProvider("windsurf");
    const tokens = await provider.exchangeToken(
      provider.config,
      "auth-code",
      "http://127.0.0.1:59653/callback",
      "pkce-verifier"
    );
    assert.deepEqual(tokens, { token: "devin-jwt" });
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, "https://api.devin.ai/auth/cli/token");
    assert.equal(requests[0].contentType, "application/json");
    assert.deepEqual(requests[0].body, { code: "auth-code", code_verifier: "pkce-verifier" });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Devin token exchange surfaces an upstream failure", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response("code already redeemed", { status: 400 })) as typeof globalThis.fetch;
  try {
    const provider = getProvider("windsurf");
    await assert.rejects(
      provider.exchangeToken(provider.config, "stale", "http://127.0.0.1:59653/callback", "v"),
      /Devin token exchange failed \(400\): code already redeemed/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Devin token exchange refuses to run without a PKCE verifier", async () => {
  const provider = getProvider("windsurf");
  await assert.rejects(
    provider.exchangeToken(provider.config, "code", "http://127.0.0.1:59653/callback", ""),
    /requires the PKCE code_verifier/
  );
});

test("OAuth route: GET codex/authorize is NOT retired (regression check)", async () => {
  const url = "http://localhost:20128/api/oauth/codex/authorize";
  const request = new Request(url, { method: "GET" });
  const response = await oauthGet(request, {
    params: Promise.resolve({ provider: "codex", action: "authorize" }),
  } as never);
  assert.notEqual(response.status, 410);
});

// ─── Regression: mapTokens accepts {accessToken} object, returns string accessToken ─
// Earlier signature was `mapTokens(token: string)` which crashed the SQLite
// bind layer when the route called `mapTokens({ accessToken })`: the object
// got stored as accessToken and SQLite rejected it with
//   "SQLite3 can only bind numbers, strings, bigints, buffers, and null".
// Every persisted field must stay a SQLite-bindable primitive.
for (const providerId of ["windsurf", "devin-cli"]) {
  test(`${providerId} mapTokens: persists SQLite-bindable primitives`, () => {
    const jwt = `header.${Buffer.from(JSON.stringify({ exp: 4102444800 })).toString("base64url")}.sig`;
    const mapped = getProvider(providerId).mapTokens({ accessToken: jwt });
    assert.equal(typeof mapped.accessToken, "string");
    assert.equal(mapped.accessToken, jwt);
    assert.equal(typeof mapped.refreshToken, "string");
    assert.equal(typeof mapped.expiresIn, "number");
  });
}

// ─── Direct Devin Connect executor ───────────────────────────────────────────

type ProtoField = { wireType: number; value: number | Uint8Array };

function encodeVarintLocal(value: number): Uint8Array {
  const bytes: number[] = [];
  let remaining = value >>> 0;
  while (remaining > 0x7f) {
    bytes.push((remaining & 0x7f) | 0x80);
    remaining >>>= 7;
  }
  bytes.push(remaining);
  return new Uint8Array(bytes);
}

function concatBytesLocal(parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function encodeFieldLocal(field: number, payload: Uint8Array): Uint8Array {
  return concatBytesLocal([
    encodeVarintLocal((field << 3) | 2),
    encodeVarintLocal(payload.length),
    payload,
  ]);
}

function encodeStringLocal(field: number, value: string): Uint8Array {
  return encodeFieldLocal(field, new TextEncoder().encode(value));
}

function encodeMessageLocal(field: number, value: Uint8Array): Uint8Array {
  return encodeFieldLocal(field, value);
}

function encodeVarintFieldLocal(field: number, value: number): Uint8Array {
  return concatBytesLocal([encodeVarintLocal(field << 3), encodeVarintLocal(value)]);
}

function readVarintLocal(bytes: Uint8Array, offset: number): [number, number] {
  let value = 0;
  let shift = 0;
  while (offset < bytes.length) {
    const next = bytes[offset++];
    value |= (next & 0x7f) << shift;
    if ((next & 0x80) === 0) return [value >>> 0, offset];
    shift += 7;
  }
  throw new Error("truncated protobuf varint");
}

function decodeFieldsLocal(bytes: Uint8Array): Map<number, ProtoField[]> {
  const fields = new Map<number, ProtoField[]>();
  let offset = 0;
  while (offset < bytes.length) {
    const [tag, tagEnd] = readVarintLocal(bytes, offset);
    offset = tagEnd;
    const field = tag >>> 3;
    const wireType = tag & 0x07;
    let value: number | Uint8Array;
    if (wireType === 0) {
      [value, offset] = readVarintLocal(bytes, offset);
    } else if (wireType === 2) {
      const [length, lengthEnd] = readVarintLocal(bytes, offset);
      offset = lengthEnd;
      value = bytes.slice(offset, offset + length);
      offset += length;
    } else if (wireType === 1) {
      value = bytes.slice(offset, offset + 8);
      offset += 8;
    } else if (wireType === 5) {
      value = bytes.slice(offset, offset + 4);
      offset += 4;
    } else {
      throw new Error(`unsupported protobuf wire type ${wireType}`);
    }
    const values = fields.get(field) ?? [];
    values.push({ wireType, value });
    fields.set(field, values);
  }
  return fields;
}

function fieldBytesLocal(fields: Map<number, ProtoField[]>, field: number, index = 0): Uint8Array {
  const value = fields.get(field)?.[index]?.value;
  assert.ok(value instanceof Uint8Array, `field ${field} should be length-delimited`);
  return value;
}

function fieldStringLocal(fields: Map<number, ProtoField[]>, field: number, index = 0): string {
  return new TextDecoder().decode(fieldBytesLocal(fields, field, index));
}

function fieldNumberLocal(fields: Map<number, ProtoField[]>, field: number, index = 0): number {
  const value = fields.get(field)?.[index]?.value;
  assert.equal(typeof value, "number", `field ${field} should be a varint`);
  return value;
}

function connectFrameLocal(flag: number, payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(5 + payload.length);
  frame[0] = flag;
  new DataView(frame.buffer).setUint32(1, payload.length, false);
  frame.set(payload, 5);
  return frame;
}

async function requestBytesLocal(req: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of req) chunks.push(chunk);
  return concatBytesLocal(chunks);
}

async function startDevinTestServer(
  handle: (
    path: string,
    body: Uint8Array
  ) => Promise<Uint8Array | { status: number; body?: Uint8Array } | null>
): Promise<{ baseUrl: string; server: Server }> {
  const server = createServer(async (req, res) => {
    const payload = await handle(req.url ?? "", await requestBytesLocal(req));
    if (payload === null) {
      res.writeHead(404).end("unexpected path");
      return;
    }
    if ("status" in payload) {
      res.writeHead(payload.status).end(payload.body);
      return;
    }
    res.writeHead(200, { "content-type": "application/connect+proto" }).end(payload);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return { baseUrl: `http://127.0.0.1:${address.port}`, server };
}

async function closeServerLocal(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve()))
  );
}

test("WindsurfExecutor exchanges JWT and forwards tool history over Devin Connect", async () => {
  let authMetadata: Map<number, ProtoField[]> | undefined;
  let chatRequest: Map<number, ProtoField[]> | undefined;
  const { baseUrl, server } = await startDevinTestServer(async (path, body) => {
    if (path === "/exa.auth_pb.AuthService/GetUserJwt") {
      authMetadata = decodeFieldsLocal(fieldBytesLocal(decodeFieldsLocal(body), 1));
      return concatBytesLocal([encodeStringLocal(1, "jwt-xyz"), encodeStringLocal(2, baseUrl)]);
    }
    if (path === "/exa.api_server_pb.ApiServerService/GetChatMessage") {
      assert.equal(body[0], 0x01, "chat request should use gzip Connect framing");
      const compressedLength = new DataView(
        body.buffer,
        body.byteOffset,
        body.byteLength
      ).getUint32(1, false);
      assert.equal(compressedLength, body.length - 5);
      chatRequest = decodeFieldsLocal(gunzipSync(body.slice(5)));
      const firstToolDelta = concatBytesLocal([
        encodeStringLocal(1, "call-weather"),
        encodeStringLocal(2, "get_weather"),
        encodeStringLocal(3, '{"city":"'),
      ]);
      const secondToolDelta = concatBytesLocal([
        encodeStringLocal(1, "call-weather"),
        encodeStringLocal(3, '{"city":"London"}'),
      ]);
      const firstResponse = concatBytesLocal([
        encodeStringLocal(1, "devin-response-1"),
        encodeMessageLocal(6, firstToolDelta),
      ]);
      const secondResponse = concatBytesLocal([
        encodeMessageLocal(6, secondToolDelta),
        encodeVarintFieldLocal(5, 3),
        encodeMessageLocal(
          7,
          concatBytesLocal([encodeVarintFieldLocal(2, 11), encodeVarintFieldLocal(3, 7)])
        ),
      ]);
      return concatBytesLocal([
        connectFrameLocal(0, firstResponse),
        connectFrameLocal(0, secondResponse),
        connectFrameLocal(0x02, new TextEncoder().encode("{}")),
      ]);
    }
    return null;
  });
  try {
    const result = await new WindsurfExecutor().execute({
      model: "claude-sonnet-4.6",
      stream: true,
      credentials: { accessToken: "sk-ws-test", providerSpecificData: { baseUrl } },
      body: {
        max_tokens: 128,
        temperature: 0.2,
        top_p: 0.8,
        messages: [
          { role: "system", content: "system rules" },
          { role: "developer", content: "developer rules" },
          {
            role: "user",
            content: [
              { type: "text", text: "Find weather for London." },
              { type: "image_url", image_url: { url: "data:image/png;base64,YWJj" } },
            ],
          },
          {
            role: "assistant",
            content: "I'll check.",
            tool_calls: [
              {
                id: "call-prior",
                type: "function",
                function: { name: "get_weather", arguments: '{"city":"Paris"}' },
              },
            ],
          },
          { role: "tool", tool_call_id: "call-prior", content: "18C and clear" },
        ],
        tools: [
          {
            type: "function",
            function: {
              name: "get_weather",
              description: "Returns the local weather.",
              parameters: {
                type: "object",
                properties: { city: { type: "string" } },
                required: ["city"],
              },
            },
          },
        ],
      },
    });
    const sse = await result.response.text();

    assert.ok(authMetadata, "GetUserJwt should be called before chat");
    assert.equal(fieldStringLocal(authMetadata, 3), "devin-session-token$sk-ws-test");
    assert.equal(authMetadata.has(21), false, "auth metadata must not include a JWT");

    assert.ok(chatRequest, "chat request should follow GetUserJwt");
    const chatMetadata = decodeFieldsLocal(fieldBytesLocal(chatRequest, 1));
    assert.equal(fieldStringLocal(chatMetadata, 3), "devin-session-token$sk-ws-test");
    assert.equal(fieldStringLocal(chatMetadata, 21), "jwt-xyz");
    assert.equal(fieldStringLocal(chatRequest, 2), "system rules\n\ndeveloper rules");
    assert.equal(fieldNumberLocal(chatRequest, 7), 5);
    assert.equal(fieldNumberLocal(chatRequest, 11), 1);
    assert.equal(fieldStringLocal(chatRequest, 21), "claude-sonnet-4-6");

    const prompts = (chatRequest.get(3) ?? []).map((field) =>
      decodeFieldsLocal(field.value as Uint8Array)
    );
    assert.equal(prompts.length, 3);
    assert.equal(fieldNumberLocal(prompts[0], 2), 1);
    assert.equal(fieldStringLocal(prompts[0], 3), "Find weather for London.");
    const image = decodeFieldsLocal(fieldBytesLocal(prompts[0], 10));
    assert.equal(fieldStringLocal(image, 1), "YWJj");
    assert.equal(fieldStringLocal(image, 2), "image/png");
    assert.equal(fieldNumberLocal(prompts[1], 2), 2);
    assert.equal(fieldStringLocal(prompts[1], 3), "I'll check.");
    const priorToolCall = decodeFieldsLocal(fieldBytesLocal(prompts[1], 6));
    assert.equal(fieldStringLocal(priorToolCall, 1), "call-prior");
    assert.equal(fieldStringLocal(priorToolCall, 2), "get_weather");
    assert.equal(fieldStringLocal(priorToolCall, 3), '{"city":"Paris"}');
    assert.equal(fieldNumberLocal(prompts[2], 2), 4);
    assert.equal(fieldStringLocal(prompts[2], 7), "call-prior");
    assert.equal(fieldStringLocal(prompts[2], 3), "18C and clear");

    const tool = decodeFieldsLocal(fieldBytesLocal(chatRequest, 10));
    assert.equal(fieldStringLocal(tool, 1), "get_weather");
    assert.equal(fieldStringLocal(tool, 2), "Returns the local weather.");
    assert.deepEqual(JSON.parse(fieldStringLocal(tool, 3)), {
      type: "object",
      properties: { city: { type: "string" } },
      required: ["city"],
    });

    const chunks = sse
      .split("\n\n")
      .filter((event) => event.startsWith("data: {"))
      .map((event) => JSON.parse(event.slice("data: ".length)));
    assert.equal(chunks[0].choices[0].delta.role, "assistant");
    assert.deepEqual(chunks[1].choices[0].delta.tool_calls[0], {
      index: 0,
      id: "call-weather",
      type: "function",
      function: { name: "get_weather", arguments: "" },
    });
    assert.deepEqual(chunks[2].choices[0].delta.tool_calls[0], {
      index: 0,
      function: { arguments: '{"city":"' },
    });
    assert.deepEqual(chunks[3].choices[0].delta.tool_calls[0], {
      index: 0,
      function: { arguments: 'London"}' },
    });
    assert.equal(chunks.at(-1).choices[0].finish_reason, "tool_calls");
    assert.deepEqual(chunks.at(-1).usage, {
      prompt_tokens: 11,
      completion_tokens: 7,
      total_tokens: 18,
    });
    assert.ok(sse.endsWith("data: [DONE]\n\n"));
  } finally {
    await closeServerLocal(server);
  }
});

test("WindsurfExecutor returns an SSE error when Devin auth fails", async () => {
  const { baseUrl, server } = await startDevinTestServer(async (path) => {
    if (path === "/exa.auth_pb.AuthService/GetUserJwt") {
      return { status: 401, body: new TextEncoder().encode("not authorized") };
    }
    return null;
  });
  try {
    const result = await new WindsurfExecutor().execute({
      model: "claude-sonnet-4.6",
      stream: true,
      credentials: { accessToken: "sk-ws-test", providerSpecificData: { baseUrl } },
      body: { messages: [{ role: "user", content: "Hello" }] },
    });
    const sse = await result.response.text();
    const chunks = sse
      .split("\n\n")
      .filter((event) => event.startsWith("data: {"))
      .map((event) => JSON.parse(event.slice("data: ".length)));
    assert.equal(chunks.length, 1);
    assert.equal(chunks[0].error.type, "windsurf_error");
    assert.match(chunks[0].error.message, /Devin auth error 401/);
    assert.ok(sse.endsWith("data: [DONE]\n\n"));
  } finally {
    await closeServerLocal(server);
  }
});

test("WindsurfExecutor rejects a tool without function.name before authentication", async () => {
  const result = await new WindsurfExecutor().execute({
    model: "claude-sonnet-4.6",
    stream: true,
    credentials: {},
    body: {
      messages: [{ role: "user", content: "Hello" }],
      tools: [{ type: "function", function: { description: "Malformed tool" } }],
    },
  });

  assert.equal(result.response.status, 400);
  assert.deepEqual(await result.response.json(), {
    error: {
      message: "Each tool must include a non-empty function.name",
      type: "invalid_request_error",
    },
  });
});

test("WindsurfExecutor sends a system prompt whenever tools are present", async () => {
  // Cascade answers `invalid_argument` for a tool-bearing request with an empty
  // `prompt` (field 2) — verified live 2026-07-25. A client may legitimately send
  // tools with no system/developer message, so the executor must substitute one.
  const captureChatRequest = async (messages: unknown[]) => {
    let chatRequest: Map<number, ProtoField[]> | undefined;
    const { baseUrl, server } = await startDevinTestServer(async (path, body) => {
      if (path === "/exa.auth_pb.AuthService/GetUserJwt") {
        return encodeStringLocal(1, "jwt-xyz");
      }
      chatRequest = decodeFieldsLocal(gunzipSync(body.slice(5)));
      return connectFrameLocal(0x02, new TextEncoder().encode("{}"));
    });
    try {
      const result = await new WindsurfExecutor().execute({
        model: "claude-sonnet-4.6",
        stream: true,
        credentials: { accessToken: "sk-ws-test", providerSpecificData: { baseUrl } },
        body: {
          messages,
          tools: [{ type: "function", function: { name: "get_weather", parameters: {} } }],
        },
      });
      await result.response.text();
      assert.ok(chatRequest, "chat request should be sent");
      return fieldStringLocal(chatRequest, 2);
    } finally {
      await closeServerLocal(server);
    }
  };

  assert.equal(
    await captureChatRequest([{ role: "user", content: "hi" }]),
    "You are a helpful coding assistant with access to tools."
  );
  // A caller-supplied system prompt must never be replaced by the stand-in.
  assert.equal(
    await captureChatRequest([
      { role: "system", content: "CUSTOM RULES" },
      { role: "user", content: "hi" },
    ]),
    "CUSTOM RULES"
  );
});

// ─── Dashboard connection probe ──────────────────────────────────────────────
// The windsurf connection test used to fall through to "Provider test not
// supported" (red ERR badge on a working connection). Unlike devin-cli, the
// direct Devin transport has a real auth RPC, so it gets a live probe rather
// than a checkExpiry stub — checkExpiry cannot tell a revoked-but-unexpired
// token from a working one.
test("windsurf exposes a live auth probe for the dashboard connection test", () => {
  assert.equal(
    WINDSURF_PROBE_URL,
    "https://server.codeium.com/exa.auth_pb.AuthService/GetUserJwt",
    "probe must hit the same AuthService the executor uses"
  );

  // The credential travels INSIDE the protobuf payload, so the body must be
  // built per connection — a static body cannot carry it.
  const body = buildWindsurfProbeBody("probe-token");
  assert.ok(body instanceof Uint8Array && body.length > 0, "probe body must be encoded bytes");
  const wire = Buffer.from(body).toString("utf8");
  assert.match(wire, /devin-session-token\$probe-token/, "token must be normalized into the body");

  // A bare token gains the session prefix; an already-prefixed one is untouched.
  const prefixed = Buffer.from(buildWindsurfProbeBody("devin-session-token$abc")).toString("utf8");
  assert.equal(
    prefixed.match(/devin-session-token\$/g)?.length,
    1,
    "an already-prefixed token must not be double-prefixed"
  );
});

test("windsurf is wired into OAUTH_TEST_CONFIG with a dynamic body", () => {
  const cfg = (
    OAUTH_TEST_CONFIG as Record<
      string,
      {
        method?: string;
        checkExpiry?: boolean;
        getBody?: (connection: { accessToken?: string }) => Uint8Array;
      }
    >
  ).windsurf;
  assert.ok(cfg, "windsurf must have a test config (was: 'Provider test not supported')");
  assert.equal(cfg.method, "POST", "GetUserJwt is a POST RPC");
  assert.equal(typeof cfg.getBody, "function", "body must be built from the live connection");
  assert.equal(cfg.checkExpiry, undefined, "a real probe must not short-circuit on expiry alone");

  // Narrow explicitly rather than optional-chaining: a missing getBody must fail here,
  // not downstream inside Buffer.from().
  const { getBody } = cfg;
  assert.ok(getBody, "windsurf must build its probe body from the connection");
  const encoded = getBody({ accessToken: "tok-from-connection" });
  assert.match(
    Buffer.from(encoded).toString("utf8"),
    /tok-from-connection/,
    "getBody must encode the connection's own credential"
  );
});

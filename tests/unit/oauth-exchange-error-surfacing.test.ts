// Devin Desktop token exchange failures used to be indistinguishable from a
// server bug: a stale/reused callback code returns Devin's 401
// `{"detail":"Invalid or expired code."}`, but the route swallowed it into a
// generic `{"error":"Internal server error"}` (500). This verifies the typed
// `OAuthExchangeError` surfaces a safe, actionable message and status while
// never leaking the raw upstream body (Hard Rule #12).

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-oauth-exchange-err-"));
process.env.DATA_DIR = TEST_DATA_DIR;

// Dynamic imports are required here (not a static-import violation): DATA_DIR
// must be set before these modules load their DB singletons, matching the
// established pattern in oauth-grok-cli-browser.test.ts:14-24.
const core = await import("../../src/lib/db/core.ts");
const settingsDb = await import("../../src/lib/db/settings.ts");
const route = await import("../../src/app/api/oauth/[provider]/[action]/route.ts");
const { OAuthExchangeError, isOAuthExchangeError } = await import("../../src/lib/oauth/errors.ts");

const originalFetch = globalThis.fetch;

test.before(async () => {
  await settingsDb.updateSettings({ requireLogin: false });
});

test.after(async () => {
  globalThis.fetch = originalFetch;
  core.resetDbInstance();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
});

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

function postRoute(provider: string, action: string, body: unknown) {
  const request = new Request(`http://localhost:20128/api/oauth/${provider}/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return route.POST(request, { params: Promise.resolve({ provider, action }) });
}

// ── OAuthExchangeError / isOAuthExchangeError (unit-level) ────────────────

test("OAuthExchangeError carries a friendly message and defaults httpStatus to 400", () => {
  const err = new OAuthExchangeError("technical detail", "friendly text");
  assert.equal(err.friendly, "friendly text");
  assert.equal(err.httpStatus, 400);
  assert.equal(err.message, "technical detail");
});

test("isOAuthExchangeError recognizes real instances, rejects plain Errors, and accepts a structurally-identical cross-realm duplicate", () => {
  assert.equal(isOAuthExchangeError(new OAuthExchangeError("t", "f")), true);
  assert.equal(isOAuthExchangeError(new Error("plain")), false);
  assert.equal(
    isOAuthExchangeError({ name: "OAuthExchangeError", friendly: "f", httpStatus: 400 }),
    true
  );
});

// ── POST /api/oauth/devin-desktop/exchange — route-level ────────────────────

test("POST /api/oauth/devin-desktop/exchange with a stale code returns 400 with an actionable message", async () => {
  globalThis.fetch = async () =>
    new Response('{"detail":"Invalid or expired code."}', { status: 401 });

  const res = await postRoute("devin-desktop", "exchange", {
    code: "stale",
    redirectUri: "http://127.0.0.1:59653/callback",
    codeVerifier: "v",
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.match(String(body.error), /expired or was already used/);
});

test("POST /api/oauth/devin-desktop/exchange never leaks the raw upstream body (Hard Rule #12)", async () => {
  globalThis.fetch = async () => new Response("leak: token=abc123", { status: 401 });

  const res = await postRoute("devin-desktop", "exchange", {
    code: "stale",
    redirectUri: "http://127.0.0.1:59653/callback",
    codeVerifier: "v",
  });
  const body = await res.json();
  assert.doesNotMatch(String(body.error), /token=abc123/, "must not leak the upstream error body");
});

test("POST /api/oauth/devin-desktop/exchange with an upstream outage returns 502", async () => {
  globalThis.fetch = async () => new Response("service unavailable", { status: 503 });

  const res = await postRoute("devin-desktop", "exchange", {
    code: "any",
    redirectUri: "http://127.0.0.1:59653/callback",
    codeVerifier: "v",
  });
  assert.equal(res.status, 502);
  const body = await res.json();
  assert.match(String(body.error), /unavailable \(HTTP 503\)/);
});

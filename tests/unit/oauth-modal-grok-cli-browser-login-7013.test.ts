import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// #7013: grok-cli now ships its own browser PKCE login alongside the
// pre-existing paste-token import. Regression guard for the two
// set-membership flips in OAuthModal.tsx that gate the "Browser Login" tab.
// Source-level guard (like oauth-device-code-error-transparency.test.ts):
// OAuthModal is a "use client" component with heavy runtime deps (next-intl,
// popup/fetch orchestration); pinning the exact provider-set membership by
// source inspection is the lightweight, reliable check for this regression.
const here = dirname(fileURLToPath(import.meta.url));
const modal = readFileSync(resolve(here, "../../src/shared/components/OAuthModal.tsx"), "utf8");

function extractSet(constName: string): string[] {
  const match = modal.match(new RegExp(`const ${constName} = new Set\\(\\[([^\\]]*)\\]\\)`));
  assert.ok(match, `expected to find ${constName} in OAuthModal.tsx`);
  return match![1]
    .replace(/\/\/[^\n]*/g, "")
    .split(",")
    .map((s) => s.trim().replace(/^"|"$/g, ""))
    .filter(Boolean);
}

test("grok-cli is NOT import-token-only — the Browser Login tab renders", () => {
  assert.ok(!extractSet("IMPORT_TOKEN_ONLY_PROVIDERS").includes("grok-cli"));
});

// devin-desktop gained a browser PKCE login alongside its API-key paste, so it
// must NOT be import-token-only: that set suppresses the tab bar the user needs
// to reach Browser Login. devin-cli remains paste-only (it drives the local CLI
// binary over ACP and cannot consume a browser-minted session JWT).
test("devin-cli stays import-token-only, devin-desktop does not", () => {
  const set = extractSet("IMPORT_TOKEN_ONLY_PROVIDERS");
  assert.ok(set.includes("devin-cli"));
  assert.ok(!set.includes("devin-desktop"));
});

test("grok-cli uses the local PKCE callback server, alongside codex/xai-oauth", () => {
  const set = extractSet("PKCE_CALLBACK_SERVER_PROVIDERS");
  assert.ok(set.includes("grok-cli"));
  assert.ok(set.includes("codex"));
  assert.ok(set.includes("xai-oauth"));
});

test("devin-desktop uses the local PKCE callback server", () => {
  const set = extractSet("PKCE_CALLBACK_SERVER_PROVIDERS");
  assert.ok(set.includes("devin-desktop"));
});

// Remote deployments: Devin only accepts the fixed loopback redirect
// 127.0.0.1:59653/callback, so the modal's non-localhost branch must send that
// exact URI. It previously built `localhost:<omniroute-port>/auth/callback`,
// a leftover from the retired Windsurf PKCE flow, which Devin rejects.
test("devin-desktop remote fallback uses Devin's fixed loopback redirect, not OmniRoute's port", () => {
  // Strip only full-line comments: a naive /\/\/.*/ also eats the `//` inside
  // the `http://…` template literal this test is asserting on.
  const source = modal.replace(/^\s*\/\/[^\n]*$/gm, "");
  const branch = source.match(/provider === "devin-desktop"\)\s*\{([\s\S]*?)\}\s*else if/);
  assert.ok(branch, "expected a devin-desktop branch in the redirect-URI selection");

  assert.match(branch[1], /DEVIN_CALLBACK_HOST/);
  assert.match(branch[1], /DEVIN_CALLBACK_PORT/);
  assert.match(branch[1], /DEVIN_CALLBACK_PATH/);
  // The retired path must not come back.
  assert.doesNotMatch(branch[1], /auth\/callback/);
  assert.doesNotMatch(branch[1], /window\.location\.port/);

  assert.match(modal, /const DEVIN_CALLBACK_HOST = "127\.0\.0\.1"/);
  assert.match(modal, /const DEVIN_CALLBACK_PORT = 59653/);
  assert.match(modal, /const DEVIN_CALLBACK_PATH = "\/callback"/);
});

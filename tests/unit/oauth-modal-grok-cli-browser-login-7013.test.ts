import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// #7013: grok-cli ships its own browser PKCE login alongside the pre-existing
// paste-token import. Regression guard for the provider-set membership in
// OAuthModal.tsx that gates the "Browser Login" tab.
//
// 2026-07-25: `IMPORT_TOKEN_ONLY_PROVIDERS` was removed once windsurf regained a
// browser flow (Devin CLI PKCE). No provider is paste-ONLY in the modal anymore,
// so the guard pins that the set is gone and that windsurf uses the loopback
// callback server. `devin-cli` stays paste-driven (ACP executor) but is not
// modal-gated by a dedicated set.
// Source-level guard (like oauth-device-code-error-transparency.test.ts):
// OAuthModal is a "use client" component with heavy runtime deps (next-intl,
// popup/fetch orchestration); pinning the exact provider-set membership by
// source inspection is the lightweight, reliable check for this regression.
const here = dirname(fileURLToPath(import.meta.url));
const modal = readFileSync(resolve(here, "../../src/shared/components/OAuthModal.tsx"), "utf8");

function extractSet(constName: string): string[] {
  // The declaration may span multiple lines and carry `// …` comments, so strip
  // comments first and match lazily up to the closing `])`.
  const source = modal.replace(/\/\/[^\n]*/g, "");
  const match = source.match(new RegExp(`const ${constName} = new Set\\(\\[([\\s\\S]*?)\\]\\)`));
  assert.ok(match, `expected to find ${constName} in OAuthModal.tsx`);
  return match[1]
    .split(",")
    .map((entry) => entry.trim().replace(/^"|"$/g, ""))
    .filter(Boolean);
}

test("no provider is import-token-only — the Browser Login tab always renders", () => {
  assert.doesNotMatch(
    modal,
    /IMPORT_TOKEN_ONLY_PROVIDERS/,
    "IMPORT_TOKEN_ONLY_PROVIDERS should stay removed: every paste-capable provider now has a browser flow"
  );
});

test("loopback PKCE callback server covers grok-cli, codex/xai-oauth and windsurf", () => {
  const set = extractSet("PKCE_CALLBACK_SERVER_PROVIDERS");
  for (const provider of ["grok-cli", "codex", "xai-oauth", "windsurf"]) {
    assert.ok(set.includes(provider), `${provider} must use the local PKCE callback server`);
  }
});

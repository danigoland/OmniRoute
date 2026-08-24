// Tests for `omniroute login devin-desktop`, the local Devin PKCE helper.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  buildDevinDesktopAuthRequest,
  runDevinDesktopLogin,
} from "../../bin/cli/commands/login.mjs";
import { decodeCredentialBlob } from "../../src/lib/oauth/credentialBlob.ts";

const verifier = "test-code-verifier";
const expectedChallenge = createHash("sha256").update(verifier).digest("base64url");

test("buildDevinDesktopAuthRequest: fixed loopback redirect and S256 PKCE", () => {
  const { authUrl, redirectUri, state, codeVerifier } = buildDevinDesktopAuthRequest(
    () => "fixed-state",
    () => verifier
  );
  assert.equal(redirectUri, "http://127.0.0.1:59653/callback");
  assert.equal(state, "fixed-state");
  assert.equal(codeVerifier, verifier);

  const url = new URL(authUrl);
  assert.equal(url.origin, "https://app.devin.ai");
  assert.equal(url.pathname, "/auth/cli/continue");
  assert.equal(url.searchParams.get("redirect_uri"), redirectUri);
  assert.equal(url.searchParams.get("prompt"), "select_account");
  assert.equal(url.searchParams.get("code_challenge"), expectedChallenge);
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
});

test("runDevinDesktopLogin: fixed port, exchanges PKCE, and emits a devin-desktop blob", async () => {
  let startedOn: number | null = null;
  let exchanged: { code: string; redirectUri: string; codeVerifier: string } | null = null;
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const token = `header.${Buffer.from(JSON.stringify({ exp })).toString("base64url")}.signature`;

  const blob = await runDevinDesktopLogin(
    { browser: false, push: false },
    {
      makeState: () => "S",
      makeVerifier: () => verifier,
      startServer: async (port: number) => {
        startedOn = port;
        return {
          port,
          waitForCallback: async () => ({ code: "the-code", state: "S" }),
          close: async () => {},
        };
      },
      exchange: async (code: string, redirectUri: string, codeVerifier: string) => {
        exchanged = { code, redirectUri, codeVerifier };
        return { token };
      },
      resolveContext: async () => null,
      print: () => {},
      log: () => {},
    }
  );

  assert.equal(startedOn, 59653);
  assert.deepEqual(exchanged, {
    code: "the-code",
    redirectUri: "http://127.0.0.1:59653/callback",
    codeVerifier: verifier,
  });

  const decoded = decodeCredentialBlob(blob);
  assert.equal(decoded.provider, "devin-desktop");
  assert.equal(decoded.tokens.access_token, token);
  assert.ok(Number(decoded.tokens.expires_in) > 0);
});

test("runDevinDesktopLogin: rejects a state mismatch before exchanging", async () => {
  let exchanged = false;
  await assert.rejects(
    () =>
      runDevinDesktopLogin(
        { browser: false },
        {
          makeState: () => "expected",
          makeVerifier: () => verifier,
          startServer: async (port: number) => ({
            port,
            waitForCallback: async () => ({ code: "c", state: "ATTACKER" }),
            close: async () => {},
          }),
          exchange: async () => {
            exchanged = true;
            return { token: "x" };
          },
          print: () => {},
          log: () => {},
        }
      ),
    /state mismatch|csrf/i
  );
  assert.equal(exchanged, false);
});

test("runDevinDesktopLogin: failed push still prints the credential blob", async () => {
  const printed: string[] = [];
  const blob = await runDevinDesktopLogin(
    { browser: false, push: true },
    {
      makeState: () => "S",
      makeVerifier: () => verifier,
      startServer: async (port: number) => ({
        port,
        waitForCallback: async () => ({ code: "c", state: "S" }),
        close: async () => {},
      }),
      exchange: async () => ({ token: "opaque-session-token" }),
      resolveContext: async () => ({ baseUrl: "https://devin.example.test" }),
      push: async () => ({ ok: false, error: "ECONNREFUSED" }),
      print: (text: string) => printed.push(text),
      log: () => {},
    }
  );
  assert.ok(printed.join("").includes(blob));
});

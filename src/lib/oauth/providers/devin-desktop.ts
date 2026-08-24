import { DEVIN_DESKTOP_CONFIG } from "../constants/oauth";
import {
  buildDevinAuthUrl,
  exchangeDevinToken,
  isDevinCliTokens,
  mapDevinSessionToken,
} from "./devin-session";

/**
 * Devin Desktop OAuth Provider — browser PKCE plus import-token hybrid.
 *
 * The Devin Desktop executor talks to Devin's Cascade API, which authenticates
 * a `devin-session-token$<jwt>` credential through `AuthService/GetUserJwt`.
 * Only Devin's own CLI authorization flow issues that JWT:
 *
 *   1. OmniRoute opens `https://app.devin.ai/auth/cli/continue` with PKCE S256
 *      and a loopback `redirect_uri` (127.0.0.1:59653/callback).
 *   2. The user signs in to Devin; Devin redirects back with `code`.
 *   3. OmniRoute exchanges it at `https://api.devin.ai/auth/cli/token`.
 *   4. The returned JWT is stored as `accessToken`.
 *
 * Windsurf IDE tokens (`sk-ws-…`, `ott$…`) are a DIFFERENT identity provider and
 * are rejected by `GetUserJwt` with "Invalid token" — `import-token` therefore
 * only accepts a genuine Devin session JWT.
 */
export const devinDesktop = {
  config: DEVIN_DESKTOP_CONFIG,
  flowType: "authorization_code_pkce" as const,
  // Devin's CLI flow pins the loopback port; the authorization page rejects a
  // redirect_uri on any other port.
  fixedPort: DEVIN_DESKTOP_CONFIG.callbackPort,
  callbackPath: DEVIN_DESKTOP_CONFIG.callbackPath,
  callbackHost: DEVIN_DESKTOP_CONFIG.callbackHost,

  buildAuthUrl: buildDevinAuthUrl,
  exchangeToken: exchangeDevinToken,

  /**
   * Validate a pasted credential. Devin session tokens are JWTs, so a token
   * lacking JWT structure is rejected up front rather than failing later at
   * `GetUserJwt` with an opaque "Invalid token".
   */
  validateImportToken(token: string): { valid: boolean; reason?: string } {
    const trimmed = (token ?? "").trim();
    if (!trimmed) {
      return { valid: false, reason: "Token is empty" };
    }
    if (trimmed.startsWith("sk-ws-") || trimmed.startsWith("ott$")) {
      return {
        valid: false,
        reason:
          "That is a Windsurf IDE token, which Devin rejects. Use Browser Login to sign in at app.devin.ai instead.",
      };
    }
    if (trimmed.split(".").length !== 3) {
      return {
        valid: false,
        reason: "Expected a Devin session JWT (three dot-separated segments)",
      };
    }
    return { valid: true };
  },

  mapTokens(tokens: { accessToken: string } | { token: string }) {
    return isDevinCliTokens(tokens)
      ? mapDevinSessionToken(tokens.token, "browser")
      : mapDevinSessionToken(tokens.accessToken, "import");
  },
};

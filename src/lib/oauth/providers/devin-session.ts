/**
 * Devin CLI browser PKCE flow — used by the `devin-desktop` / `devin-cli` providers.
 *
 * Devin authorizes CLI clients at `app.devin.ai/auth/cli/continue` and exchanges
 * the returned code for a session JWT at `api.devin.ai/auth/cli/token`. That JWT
 * is the credential the Devin Desktop executor prefixes with `devin-session-token$`
 * when calling `AuthService/GetUserJwt`.
 *
 * The exchange is plain JSON, so it does not reuse the shared form-encoded OAuth
 * helper. Devin also ignores `client_id`/`grant_type`: the request body carries
 * only `code` and `code_verifier`.
 */

import { DEVIN_DESKTOP_CONFIG } from "../constants/oauth";
import { OAuthExchangeError } from "../errors";

/** Long-lived fallback when a returned token carries no parseable `exp` claim. */
const FALLBACK_EXPIRES_IN = 365 * 24 * 60 * 60;

/** Devin's token endpoint response. */
export type DevinCliTokens = { token: string };

export function isDevinCliTokens(value: unknown): value is DevinCliTokens {
  if (!value || typeof value !== "object" || !("token" in value)) return false;
  return typeof value.token === "string" && value.token.length > 0;
}

/**
 * Build the Devin CLI authorization URL. `prompt=select_account` matches the
 * Devin CLI so a user with several accounts can choose which one to link.
 */
export function buildDevinAuthUrl(
  config: typeof DEVIN_DESKTOP_CONFIG,
  redirectUri: string,
  state: string,
  codeChallenge: string
): string {
  const params = new URLSearchParams({
    redirect_uri: redirectUri,
    state,
    prompt: "select_account",
    code_challenge: codeChallenge,
    code_challenge_method: config.codeChallengeMethod,
  });
  return `${config.authorizeUrl}?${params.toString()}`;
}

/** Exchange a Devin authorization code for its session JWT. */
export async function exchangeDevinToken(
  config: typeof DEVIN_DESKTOP_CONFIG,
  code: string,
  _redirectUri: string,
  codeVerifier: string
): Promise<DevinCliTokens> {
  if (!codeVerifier) {
    throw new Error("Devin token exchange requires the PKCE code_verifier");
  }

  const response = await fetch(`${config.authServerUrl}${config.exchangePath}`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ code, code_verifier: codeVerifier }),
  });

  if (!response.ok) {
    const detail = (await response.text()).slice(0, 200);
    const rejected = response.status === 400 || response.status === 401 || response.status === 403;
    throw new OAuthExchangeError(
      `Devin token exchange failed (${response.status}): ${detail}`.trim(),
      rejected
        ? "Devin rejected this authorization code — it has expired or was already used. Start the login again and paste the new callback URL."
        : `Devin's token endpoint is unavailable (HTTP ${response.status}). Try again in a moment.`,
      rejected ? 400 : 502
    );
  }

  const data: unknown = await response.json();
  if (!isDevinCliTokens(data)) {
    throw new Error("Devin token exchange returned an empty token");
  }
  return { token: data.token };
}

/**
 * Map a Devin session JWT onto the stored connection. Devin has no refresh
 * endpoint, so the same token is persisted as the refresh material; expiry comes
 * from the JWT's own `exp` claim. `authMethod` records which flow supplied the
 * token so diagnostics can tell a browser login from a pasted credential.
 */
export function mapDevinSessionToken(token: string | undefined, authMethod: "browser" | "import") {
  return {
    accessToken: token ?? "",
    refreshToken: token ?? "",
    expiresIn: token ? readJwtExpiresIn(token) : null,
    providerSpecificData: { authMethod },
  };
}

/** Seconds until a JWT's `exp`, or a long-lived fallback for opaque tokens. */
function readJwtExpiresIn(token: string): number {
  const payload = token.split(".")[1];
  if (payload) {
    try {
      const decoded: unknown = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      if (!decoded || typeof decoded !== "object" || !("exp" in decoded))
        return FALLBACK_EXPIRES_IN;
      const exp = decoded.exp;
      if (typeof exp === "number" && Number.isFinite(exp)) {
        return Math.max(0, Math.floor(exp - Date.now() / 1000));
      }
    } catch {
      // Opaque (non-JWT) token — fall through to the long-lived default.
    }
  }
  return FALLBACK_EXPIRES_IN;
}

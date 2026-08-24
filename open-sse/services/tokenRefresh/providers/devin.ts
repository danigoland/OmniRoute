// Extracted from open-sse/services/tokenRefresh.ts — see ../shared.ts for
// provenance notes (ported idea from KooshaPari's PR #7338, redone on tip).
import type { RefreshLogger } from "../shared.ts";

/** Skew applied to a JWT `exp` claim so a token is renewed before it lapses. */
const EXPIRY_SKEW_MS = 5 * 60 * 1000;

/**
 * Refresh Devin credentials.
 *
 * Devin's CLI authorization flow issues a single long-lived JWT and exposes no
 * refresh endpoint: the same token serves as both access and refresh material
 * until its `exp` claim lapses, after which the user must sign in again. So the
 * only useful work here is deciding between "still valid, nothing to do" and
 * "expired, re-authentication required".
 */
export async function refreshDevinToken(
  refreshToken: string,
  _providerSpecificData: Record<string, unknown> | null | undefined,
  log: RefreshLogger
): Promise<{ error: string; code: string } | null> {
  if (!refreshToken) {
    log?.warn?.("TOKEN_REFRESH", "No Devin token stored — re-authentication required");
    return { error: "unrecoverable_refresh_error", code: "MISSING_TOKEN" };
  }

  const expiresAt = readJwtExpiry(refreshToken);
  if (expiresAt !== null && expiresAt - EXPIRY_SKEW_MS <= Date.now()) {
    log?.error?.(
      "TOKEN_REFRESH",
      "Devin token has expired and cannot be refreshed. Re-authentication required."
    );
    return { error: "unrecoverable_refresh_error", code: "TOKEN_EXPIRED" };
  }

  log?.debug?.("TOKEN_REFRESH", "Devin token is still valid — no refresh available or needed");
  return null;
}

/** Expiry of a JWT in epoch milliseconds, or `null` when absent/unparseable. */
function readJwtExpiry(token: string): number | null {
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const decoded: unknown = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!decoded || typeof decoded !== "object") return null;
    const exp = (decoded as { exp?: unknown }).exp;
    return typeof exp === "number" && Number.isFinite(exp) ? exp * 1000 : null;
  } catch {
    return null;
  }
}

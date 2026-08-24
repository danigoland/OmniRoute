import { DEVIN_DESKTOP_CONFIG } from "../constants/oauth";
import { mapDevinSessionToken } from "./devin-session";

/**
 * Devin CLI OAuth Provider — import-token only.
 *
 * Distinct from the `devin-desktop` provider despite sharing this config.
 * `devin-cli` is served by `DevinCliExecutor`, which drives the locally
 * installed Devin CLI binary over ACP; it never speaks the Cascade Connect
 * protocol. A Devin session JWT minted by the browser PKCE flow is therefore
 * useless here — the ACP transport rejects it with `-32602 Invalid params` —
 * so browser login stays off for this entry and only `devin-desktop` exposes it.
 *
 * Credentials come from `devin auth login` (or a pasted `WINDSURF_API_KEY`),
 * which is what the CLI binary itself consumes.
 */
export const devinCli = {
  config: DEVIN_DESKTOP_CONFIG,
  flowType: "import_token" as const,

  validateImportToken(token: string): { valid: boolean; reason?: string } {
    const trimmed = (token ?? "").trim();
    if (!trimmed) {
      return { valid: false, reason: "Token is empty" };
    }
    if (trimmed.length < 16) {
      return { valid: false, reason: "Token is too short" };
    }
    return { valid: true };
  },

  /**
   * The pasted value IS the CLI credential; there is no exchange step. Shares
   * the Devin token mapper so the persisted shape (and JWT-derived expiry, when
   * the token happens to be a JWT) matches the `devin-desktop` entry.
   */
  mapTokens(tokens: { accessToken: string }) {
    return mapDevinSessionToken(tokens.accessToken, "import");
  },
};

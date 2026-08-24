/**
 * Devin Desktop (Windsurf-lineage) Connect API + CLI OAuth constants.
 *
 * Pure literals with zero imports — deliberately dependency-free so client
 * components (OAuthModal/OAuthModalPanels) can import this leaf without
 * dragging `constants/oauth.ts`'s open-sse/server modules (node:fs) into the
 * browser bundle. `constants/oauth.ts` re-exports this for server consumers.
 */
export const DEVIN_DESKTOP_CONFIG = {
  apiServerUrl: "https://server.codeium.com",
  inferenceUrl: "https://inference.codeium.com",
  ideName: "windsurf",
  defaultVersion: "3.6.27",
  // Devin CLI authorization page. Requires PKCE S256 plus a loopback redirect_uri.
  authorizeUrl: "https://app.devin.ai/auth/cli/continue",
  codeChallengeMethod: "S256" as const,
  // Devin's CLI callback listens on a fixed loopback port.
  callbackPort: 59653,
  callbackPath: "/callback",
  callbackHost: "127.0.0.1",
  authServerUrl: "https://api.devin.ai",
  exchangePath: "/auth/cli/token",
  // Legacy paste-token page, retained because import-token remains available for
  // accounts that already hold a genuine Devin session token.
  showAuthTokenUrl: "https://windsurf.com/show-auth-token",
  // IDE identity sent with every Connect request.
  ideVersion: "3.2.23",
  extensionVersion: "1.48.2",
};

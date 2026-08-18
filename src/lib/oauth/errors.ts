/**
 * An OAuth failure whose cause is safe and useful to show the user.
 *
 * `message` keeps the full technical detail (including the upstream body) for
 * the server log. `friendly` is authored HERE, never taken from an upstream
 * response, so surfacing it cannot leak an upstream body — the Rule #12 hazard
 * that keeps the generic catch in place for every other error.
 */
export class OAuthExchangeError extends Error {
  constructor(
    message: string,
    public readonly friendly: string,
    public readonly httpStatus: number = 400
  ) {
    super(message);
    this.name = "OAuthExchangeError";
  }
}

/**
 * Structural guard, not a bare `instanceof`. Under Next's bundler this module is
 * reached through two specifiers — `@/lib/oauth/errors` from the route and
 * `../errors` from the provider — and if those ever resolve to two module
 * instances, `instanceof` silently returns false and every user would be back to
 * a generic 500. Matching on the shape cannot fail that way.
 */
export function isOAuthExchangeError(value: unknown): value is OAuthExchangeError {
  if (value instanceof OAuthExchangeError) return true;
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as { name?: unknown; friendly?: unknown; httpStatus?: unknown };
  return (
    candidate.name === "OAuthExchangeError" &&
    typeof candidate.friendly === "string" &&
    typeof candidate.httpStatus === "number"
  );
}

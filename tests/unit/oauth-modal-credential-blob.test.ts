import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync("src/shared/components/OAuthModal.tsx", "utf8");

test("OAuthModal routes credential blobs through paste-credentials", () => {
  assert.match(source, /isCredentialBlob\(raw\)/);
  assert.match(
    source,
    /if \(isCredentialBlob\(raw\)\) \{\s*await submitCredentialBlob\(provider, raw, reauthConnection, setStep, onSuccess\);/
  );

  const blobBranch = source.indexOf("if (isCredentialBlob(raw))");
  const importBranch = source.indexOf("/import-token", blobBranch);
  assert.ok(blobBranch >= 0 && importBranch > blobBranch, "raw-token import remains the fallback");
});

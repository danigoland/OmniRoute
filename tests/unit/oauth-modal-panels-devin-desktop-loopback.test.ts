// Devin always redirects to its fixed loopback callback address regardless of
// how OmniRoute is accessed. A remote/LAN user landing on that error page
// cannot tell it apart from a misconfiguration unless the modal names the
// exact address — and only for `devin-desktop`, since every other provider's
// callback port varies (or doesn't apply).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const panelsSource = readFileSync("src/shared/components/OAuthModalPanels.tsx", "utf8");
const en = JSON.parse(readFileSync("src/i18n/messages/en.json", "utf8")) as {
  oauthModal: Record<string, string>;
};

test("OAuthModalPanels renders windsurfLoopbackNotice only when provider === devin-desktop", () => {
  const match = panelsSource.match(/\{provider === "devin-desktop" && \(([\s\S]*?)\n {6}\)\}/);
  assert.ok(match, 'expected a `provider === "devin-desktop"` guarded block');
  assert.match(match![1], /t\.rich\("windsurfLoopbackNotice"/);
});

test("windsurfLoopbackNotice sources its address from DEVIN_DESKTOP_CONFIG, not a hardcoded port", () => {
  assert.match(
    panelsSource,
    /import \{ DEVIN_DESKTOP_CONFIG \} from "@\/lib\/oauth\/constants\/devinDesktop";/
  );
  assert.match(
    panelsSource,
    /address:\s*`\$\{DEVIN_DESKTOP_CONFIG\.callbackHost\}:\$\{DEVIN_DESKTOP_CONFIG\.callbackPort\}`/
  );
});

test("en.json defines windsurfLoopbackNotice with an {address} placeholder inside oauthModal", () => {
  const notice = en.oauthModal.windsurfLoopbackNotice;
  assert.ok(notice, "oauthModal.windsurfLoopbackNotice must exist in en.json");
  assert.match(notice, /\{address\}/);
});

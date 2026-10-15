// Builds the extension for Chromium browsers (dist/chrome) and Firefox
// (dist/firefox).
import { build } from "esbuild";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync("package.json", "utf8"));

// Public key that fixes the Chrome extension id (mdafhkgmgciicpdegfgkblolngnhebca).
// It is public by design; the native host only accepts this id.
const CHROME_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvViyptf6rj6eD1acIaYeYXVVxx3RAYOD0fWyjexz78c0TVrvyJAid8ajv9zI1FOtGkJOQnZZnWU9hdTFoNUDEJFghEBe6qHSOk4HwWjagx9A03ETKZqRMicNOUfdNj1HgY1OyWiuAV+jEcDlQT68YxblU4KR+/WxKMXxswb3/MKUkaLaTm/XuiFCvI0Cg61me1NrMDXgw1o/pch/G+makEH5DEr+eXbWOoAXdhXs9ee2BgpB6+bbeZxbjdysBrFvd85Wr2UEjxKimSpIE3vtD4ngaQNscXvxBvvs6tL+07ZQ1JovDUM3hdS42dru9pYBx8xtTzp6gT5OYg1/ZZFyAQIDAQAB";
const FIREFOX_ID = "keyless@diegocastroalves.github.io";

const base = {
  manifest_version: 3,
  name: "__MSG_name__",
  description: "__MSG_description__",
  version: pkg.version,
  default_locale: "en",
  icons: { 16: "icons/icon-16.png", 32: "icons/icon-32.png", 48: "icons/icon-48.png", 128: "icons/icon-128.png" },
  action: { default_popup: "popup.html", default_icon: { 16: "icons/icon-16.png", 32: "icons/icon-32.png" } },
  permissions: ["nativeMessaging", "tabs", "storage", "contextMenus"],
  // Asked only if the user turns off the browser's own password manager.
  optional_permissions: ["privacy"],
  // Every web page (the content scripts run in http and https pages only);
  // "<all_urls>" also lets the extension take a picture of the visible page,
  // to read a two-factor setup QR code (see background.ts, scanTabQr).
  host_permissions: ["<all_urls>"],
  content_scripts: [
    // Also in frames inside pages, for login forms there (see src/content.ts).
    { matches: ["http://*/*", "https://*/*"], js: ["content.js"], run_at: "document_idle", all_frames: true },
    // Passkeys: the page's WebAuthn calls (webauthn-page.ts, in the page's
    // world) relayed to Keyless (webauthn.ts). Secure pages only, and the
    // frames in them (webauthn.ts checks what the page allows them).
    { matches: ["https://*/*", "http://localhost/*"], js: ["webauthn-page.js"], run_at: "document_start", world: "MAIN", all_frames: true },
    { matches: ["https://*/*", "http://localhost/*"], js: ["webauthn.js"], run_at: "document_start", all_frames: true },
  ],
  // The Keyless menus shown inside pages (see src/inline.ts).
  web_accessible_resources: [{ resources: ["inline.html"], matches: ["http://*/*", "https://*/*"] }],
  commands: {
    // Opens the popup.
    _execute_action: { suggested_key: { default: "Ctrl+Shift+Period", mac: "Command+Shift+Period" } },
    "fill-login": { suggested_key: { default: "Ctrl+Shift+L", mac: "Command+Shift+L" }, description: "__MSG_commandFill__" },
    // No key of its own by default (set one in the browser's shortcuts page).
    "fill-code": { description: "__MSG_commandFillCode__" },
  },
  content_security_policy: { extension_pages: "script-src 'self'; object-src 'none'; base-uri 'none'" },
};

const targets = {
  chrome: {
    ...base,
    key: CHROME_KEY,
    minimum_chrome_version: "133",
    // Site icons from the browser's own cache, for the login lists; the
    // websites' own sign-in dialogs (see background.ts).
    permissions: [...base.permissions, "favicon", "webRequest", "webRequestAuthProvider"],
    background: { service_worker: "background.js" },
  },
  firefox: {
    ...base,
    background: { scripts: ["background.js"] },
    // The websites' own sign-in dialogs (see background.ts).
    permissions: [...base.permissions, "webRequest", "webRequestBlocking"],
    // Mozilla asks every new extension what data it collects: none leaves the
    // computer (it goes to the Keyless app only; see docs/PRIVACY.md). That
    // key needs Firefox 140 (142 on Android, where the extension cannot reach
    // the app, but whose version addons.mozilla.org checks too).
    browser_specific_settings: { gecko: { id: FIREFOX_ID, strict_min_version: "140.0", data_collection_permissions: { required: ["none"] } }, gecko_android: { strict_min_version: "142.0" } },
  },
};

for (const [name, manifest] of Object.entries(targets)) {
  const outdir = `dist/${name}`;
  rmSync(outdir, { recursive: true, force: true });
  mkdirSync(outdir, { recursive: true });
  await build({
    entryPoints: {
      background: "src/background.ts",
      content: "src/content.ts",
      popup: "src/popup.ts",
      inline: "src/inline.ts",
      passkey: "src/passkey.ts",
      auth: "src/auth.ts",
      webauthn: "src/webauthn.ts",
      "webauthn-page": "src/webauthn-page.ts",
    },
    define: { __FAVICONS__: String(name === "chrome"), __FIREFOX__: String(name === "firefox") },
    bundle: true,
    format: "iife",
    target: name === "chrome" ? "chrome133" : "firefox130",
    outdir,
    minify: false,
    sourcemap: false,
    legalComments: "none",
  });
  cpSync("static", outdir, { recursive: true });
  // The app's font for the popup, with its license (SIL OFL).
  const fonts = "node_modules/@fontsource-variable/inter";
  mkdirSync(`${outdir}/fonts`, { recursive: true });
  for (const file of ["inter-latin-wght-normal.woff2", "inter-latin-ext-wght-normal.woff2"]) cpSync(`${fonts}/files/${file}`, `${outdir}/fonts/${file}`);
  cpSync(`${fonts}/LICENSE`, `${outdir}/fonts/LICENSE-Inter.txt`);
  writeFileSync(`${outdir}/manifest.json`, JSON.stringify(manifest, null, 2));
  console.log(`built ${outdir}`);
}

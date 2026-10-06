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
  permissions: ["nativeMessaging", "tabs"],
  host_permissions: ["http://*/*", "https://*/*"],
  content_scripts: [{ matches: ["http://*/*", "https://*/*"], js: ["content.js"], run_at: "document_idle", all_frames: false }],
  commands: {
    "fill-login": { suggested_key: { default: "Ctrl+Shift+L", mac: "Command+Shift+L" }, description: "__MSG_commandFill__" },
  },
  content_security_policy: { extension_pages: "script-src 'self'; object-src 'none'; base-uri 'none'" },
};

const targets = {
  chrome: { ...base, key: CHROME_KEY, minimum_chrome_version: "133", background: { service_worker: "background.js" } },
  firefox: {
    ...base,
    background: { scripts: ["background.js"] },
    browser_specific_settings: { gecko: { id: FIREFOX_ID, strict_min_version: "130.0" } },
  },
};

for (const [name, manifest] of Object.entries(targets)) {
  const outdir = `dist/${name}`;
  rmSync(outdir, { recursive: true, force: true });
  mkdirSync(outdir, { recursive: true });
  await build({
    entryPoints: { background: "src/background.ts", content: "src/content.ts", popup: "src/popup.ts" },
    bundle: true,
    format: "iife",
    target: name === "chrome" ? "chrome133" : "firefox130",
    outdir,
    minify: false,
    sourcemap: false,
    legalComments: "none",
  });
  cpSync("static", outdir, { recursive: true });
  writeFileSync(`${outdir}/manifest.json`, JSON.stringify(manifest, null, 2));
  console.log(`built ${outdir}`);
}

// Builds the public site (keyless.diegoalves.dev) into dist/: the home
// page, the page that opens share links (/share/), the browser extension's
// tutorial (/tutorial/), the privacy policy (/privacy/), where the links
// confirming an email change lead (/email-changed/) and, when it is on, the
// web vault (/vault/, with the WebAssembly client in vendor/). Static files
// only, served by Cloudflare Pages with the headers in dist/_headers.
import { build } from "esbuild";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

// The same public project values as the app (see apps/desktop config.rs).
const SUPABASE_URL = process.env.KEYLESS_SUPABASE_URL ?? "https://ednfhgbjtgkrmtnudcjr.supabase.co";
const SUPABASE_KEY = process.env.KEYLESS_SUPABASE_KEY ?? "sb_publishable_3SSYrJqgt-zB30WaRHnuSw_YN7WaHqD";

// The web vault is off: none of its files are published (/vault/ is a 404)
// and the home page does not link to it. KEYLESS_WEB_VAULT=on turns it back
// on (see README.md), together with the server's passkey sign-in switch.
const WEB_VAULT = process.env.KEYLESS_WEB_VAULT === "on";

// Field and category names, from the app's own translations.
async function labels() {
  const out = {};
  for (const lang of ["pt-BR", "en", "es"]) {
    const result = await build({ entryPoints: [`../desktop/src/i18n/${lang}.ts`], bundle: true, format: "esm", write: false, platform: "neutral" });
    const module = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString("base64")}`);
    out[lang] = { fieldLabels: module.default.fieldLabels, categories: module.default.categories, categoriesPlural: module.default.categoriesPlural };
  }
  return out;
}
const names = await labels();
const virtualLabels = {
  name: "labels",
  setup(b) {
    b.onResolve({ filter: /^virtual:labels$/ }, () => ({ path: "labels", namespace: "virtual" }));
    b.onLoad({ filter: /.*/, namespace: "virtual" }, () => ({ contents: JSON.stringify(names), loader: "json" }));
  },
};

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist/share", { recursive: true });
cpSync("static", "dist", { recursive: true });
cpSync("../extension/static/icons/icon-32.png", "dist/icon-32.png");
cpSync("../extension/static/icons/icon-128.png", "dist/icon-128.png");
if (WEB_VAULT) {
  cpSync("vendor/keyless-wasm/keyless_wasm_bg.wasm", "dist/vault/keyless_wasm_bg.wasm");
} else {
  rmSync("dist/vault", { recursive: true, force: true });
  // Links to it are marked data-web-vault.
  const home = readFileSync("dist/index.html", "utf8");
  writeFileSync("dist/index.html", home.replace(/\s*<a [^>]*data-web-vault[^>]*>[^<]*<\/a>/g, ""));
}

// Fonts (SIL Open Font License), served from this site.
mkdirSync("dist/fonts", { recursive: true });
const fonts = {
  "instrument-serif-400.woff2": "@fontsource/instrument-serif/files/instrument-serif-latin-400-normal.woff2",
  "instrument-serif-400-italic.woff2": "@fontsource/instrument-serif/files/instrument-serif-latin-400-italic.woff2",
  "ibm-plex-sans-400.woff2": "@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-400-normal.woff2",
  "ibm-plex-sans-500.woff2": "@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-500-normal.woff2",
  "ibm-plex-sans-600.woff2": "@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-600-normal.woff2",
  "ibm-plex-mono-400.woff2": "@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2",
  "ibm-plex-mono-500.woff2": "@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-500-normal.woff2",
};
for (const [name, from] of Object.entries(fonts)) cpSync(`node_modules/${from}`, `dist/fonts/${name}`);

await build({
  entryPoints: { "share/app": "src/share.ts", home: "src/home.ts", "tutorial/app": "src/tutorial.ts", "privacy/app": "src/privacy.ts", "email-changed/app": "src/email-changed.ts", 404: "src/not-found.ts", ...(WEB_VAULT ? { "vault/app": "src/vault/app.ts" } : {}) },
  bundle: true,
  minify: true,
  format: "esm",
  target: ["chrome120", "firefox120", "safari16"],
  outdir: "dist",
  define: { __SUPABASE_URL__: JSON.stringify(SUPABASE_URL), __SUPABASE_KEY__: JSON.stringify(SUPABASE_KEY) },
  legalComments: "none",
  plugins: [virtualLabels],
});

// The theme chosen on this browser, set by every page in its <head> before
// the first paint: a classic script, since a module runs only after the
// page is parsed.
await build({
  entryPoints: { theme: "src/theme-head.ts" },
  bundle: true,
  minify: true,
  format: "iife",
  target: ["chrome120", "firefox120", "safari16"],
  outdir: "dist",
  legalComments: "none",
});

// Only this site's own files run, nothing can frame it, and links never
// tell the next site where they came from. Each page may connect only where
// it needs: the share page to the Keyless server, the home page to GitHub
// (for the newest release). The rules for pages do not overlap, since
// Cloudflare would join two policies for one page. The fonts may also load
// from elsewhere: the account emails use them (supabase/templates).
const csp = (connect, script = "'self'") =>
  [
    "default-src 'none'",
    `script-src ${script}`,
    "style-src 'self'",
    "img-src 'self'",
    "font-src 'self'",
    `connect-src ${connect}`,
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
writeFileSync(
  "dist/_headers",
  `/*
  Referrer-Policy: no-referrer
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Cross-Origin-Opener-Policy: same-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Strict-Transport-Security: max-age=31536000; includeSubDomains
/
  Content-Security-Policy: ${csp("https://api.github.com")}
/index.html
  Content-Security-Policy: ${csp("https://api.github.com")}
/404.html
  Content-Security-Policy: ${csp("'none'")}
/tutorial/*
  Content-Security-Policy: ${csp("'none'")}
/privacy/*
  Content-Security-Policy: ${csp("'none'")}
/email-changed/*
  Content-Security-Policy: ${csp("'none'")}
${
  WEB_VAULT
    ? `/vault/*
  Content-Security-Policy: ${csp(`'self' ${SUPABASE_URL}`, "'self' 'wasm-unsafe-eval'")}
  Cache-Control: no-store
  X-Robots-Tag: noindex
`
    : ""
}/share/*
  Content-Security-Policy: ${csp(SUPABASE_URL)}
  Cache-Control: no-store
  X-Robots-Tag: noindex
/fonts/*
  Access-Control-Allow-Origin: *
`,
);
console.log("built dist");

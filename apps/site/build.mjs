// Builds the public site (keyless.diegoalves.dev) into dist/: for now, the
// page that opens share links (/share/). Static files only, served by
// Cloudflare Pages with the headers in dist/_headers.
import { build } from "esbuild";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";

// The same public project values as the app (see apps/desktop config.rs).
const SUPABASE_URL = process.env.KEYLESS_SUPABASE_URL ?? "https://ednfhgbjtgkrmtnudcjr.supabase.co";
const SUPABASE_KEY = process.env.KEYLESS_SUPABASE_KEY ?? "sb_publishable_3SSYrJqgt-zB30WaRHnuSw_YN7WaHqD";

// Field and category names, from the app's own translations.
async function labels() {
  const out = {};
  for (const lang of ["pt-BR", "en", "es"]) {
    const result = await build({ entryPoints: [`../desktop/src/i18n/${lang}.ts`], bundle: true, format: "esm", write: false, platform: "neutral" });
    const module = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString("base64")}`);
    out[lang] = { fieldLabels: module.default.fieldLabels, categories: module.default.categories };
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
  entryPoints: { "share/app": "src/share.ts", home: "src/home.ts" },
  bundle: true,
  minify: true,
  format: "esm",
  target: ["chrome120", "firefox120", "safari16"],
  outdir: "dist",
  define: { __SUPABASE_URL__: JSON.stringify(SUPABASE_URL), __SUPABASE_KEY__: JSON.stringify(SUPABASE_KEY) },
  legalComments: "none",
  plugins: [virtualLabels],
});

// Only this site's own files run, nothing can frame it, and links never
// tell the next site where they came from. Each page may connect only where
// it needs: the share page to the Keyless server, the home page to GitHub
// (for the newest release). The rules for pages do not overlap, since
// Cloudflare would join two policies for one page.
const csp = (connect) =>
  [
    "default-src 'none'",
    "script-src 'self'",
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
/share/*
  Content-Security-Policy: ${csp(SUPABASE_URL)}
  Cache-Control: no-store
  X-Robots-Tag: noindex
`,
);
console.log("built dist");

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

await build({
  entryPoints: { "share/app": "src/share.ts" },
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
// tell the next site where they came from.
const csp = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  `connect-src ${SUPABASE_URL}`,
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");
writeFileSync(
  "dist/_headers",
  `/*
  Content-Security-Policy: ${csp}
  Referrer-Policy: no-referrer
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Cross-Origin-Opener-Policy: same-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Strict-Transport-Security: max-age=31536000; includeSubDomains
/share/*
  Cache-Control: no-store
  X-Robots-Tag: noindex
`,
);
console.log("built dist");

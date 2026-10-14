// Writes app/src/main/assets/labels.json from the desktop app: field, field
// kind and category names, Sentinel's and the strength levels' texts from its
// translations, and each category's template (the fields a new item starts
// with). Run with node from the
// repository root after they change; uses the site's esbuild.
import { build } from "../../site/node_modules/esbuild/lib/main.js";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = (path) => fileURLToPath(new URL(path, import.meta.url));

async function load(entry, plugins = []) {
  const result = await build({ entryPoints: [entry], bundle: true, format: "esm", write: false, platform: "neutral", plugins });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString("base64")}`);
}

const out = {};
for (const lang of ["pt-BR", "en", "es"]) {
  const t = (await load(here(`../../desktop/src/i18n/${lang}.ts`))).default;
  out[lang] = { fieldLabels: t.fieldLabels, fieldKinds: t.fieldKinds, categories: t.categories, categoriesPlural: t.categoriesPlural, sentinel: t.sentinel, strength: t.strength };
}

// categories.ts also imports icons and the app's i18n, which the templates
// do not need.
const stubs = {
  name: "stubs",
  setup(b) {
    b.onResolve({ filter: /^lucide-react$|\/i18n$|^\.\.\/i18n$/ }, (args) => ({ path: args.path, namespace: "stub" }));
    b.onLoad({ filter: /.*/, namespace: "stub" }, () => ({
      contents: "export default new Proxy({}, { get: () => () => '' }); export const Asterisk = 0, Award = 0, BadgeCheck = 0, BookUser = 0, Box = 0, Braces = 0, Car = 0, CreditCard = 0, Database = 0, FileText = 0, HeartPulse = 0, IdCard = 0, KeyRound = 0, Landmark = 0, Mail = 0, Server = 0, StickyNote = 0, Terminal = 0, Wallet = 0, Wifi = 0;",
      loader: "js",
    }));
  },
};
const { CATEGORIES } = await load(here("../../desktop/src/lib/categories.ts"), [stubs]);
out.templates = CATEGORIES.map((c) => ({
  id: c.id,
  fields: c.fields.map((f) => ({ label: f.label, kind: f.kind, purpose: f.purpose ?? null })),
  hasWebsite: !!c.hasWebsite,
  hidden: !!c.hidden,
}));

writeFileSync(here("../app/src/main/assets/labels.json"), JSON.stringify(out) + "\n");
console.log("labels.json written");

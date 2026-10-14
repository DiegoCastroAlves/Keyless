// Writes app/src/main/assets/labels.json: field and category names from the
// desktop app's translations (run with node from the repository root after
// they change; uses the site's esbuild).
import { build } from "../../site/node_modules/esbuild/lib/main.js";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = (path) => fileURLToPath(new URL(path, import.meta.url));
const out = {};
for (const lang of ["pt-BR", "en", "es"]) {
  const result = await build({ entryPoints: [here(`../../desktop/src/i18n/${lang}.ts`)], bundle: true, format: "esm", write: false, platform: "neutral" });
  const module = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString("base64")}`);
  const t = module.default;
  out[lang] = { fieldLabels: t.fieldLabels, categories: t.categories, categoriesPlural: t.categoriesPlural };
}
writeFileSync(here("../app/src/main/assets/labels.json"), JSON.stringify(out) + "\n");
console.log("labels.json written");

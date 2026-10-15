// The privacy policy's articles for /privacy/, from docs/PRIVACY.md and its
// translations (docs/PRIVACY.pt-BR.md, docs/PRIVACY.es.md), so the page and
// the documents cannot say different things. The documents use a little
// Markdown: headings, paragraphs, lists, **bold**, `code`, and email
// addresses and https links written out. The line under the title (when it
// was updated) goes above it, as the page shows it.
import { readFileSync } from "node:fs";

const DOCUMENTS = { en: "../../docs/PRIVACY.md", "pt-BR": "../../docs/PRIVACY.pt-BR.md", es: "../../docs/PRIVACY.es.md" };

const escape = (text) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function inline(text) {
  return escape(text)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, (address) => `<a href="mailto:${address}">${address}</a>`)
    .replace(/https:\/\/[^\s<]*[^\s<.,;:)]/g, (url) => `<a href="${url}">${url}</a>`);
}

function article(markdown, lang, hidden) {
  const blocks = markdown.trim().split(/\n\s*\n/);
  const out = [];
  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i].trim();
    if (block.startsWith("# ")) {
      const updated = blocks[++i].trim();
      out.push(`<p class="eyebrow mono">${inline(updated)}</p>`, `<h1>${inline(block.slice(2))}</h1>`);
    } else if (block.startsWith("## ")) {
      out.push(`<h2>${inline(block.slice(3))}</h2>`);
    } else if (block.startsWith("- ")) {
      const items = block.split(/\n(?=- )/).map((item) => item.slice(2).replace(/\s*\n\s*/g, " "));
      out.push("<ul>", ...items.map((item) => `  <li>${inline(item)}</li>`), "</ul>");
    } else {
      out.push(`<p>${inline(block.replace(/\s*\n\s*/g, " "))}</p>`);
    }
  }
  const body = out.map((line) => `        ${line}`).join("\n");
  return `      <article lang="${lang}" data-policy="${lang}"${hidden ? " hidden" : ""}>\n${body}\n      </article>`;
}

/** Every language's article, English first (shown until the page picks the visitor's). */
export function policyArticles() {
  return Object.entries(DOCUMENTS)
    .map(([lang, path], i) => article(readFileSync(new URL(path, import.meta.url), "utf8"), lang, i > 0))
    .join("\n\n");
}

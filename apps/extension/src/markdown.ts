// Notes in Markdown for the popup, as the app shows them (apps/desktop/src/
// lib/markdown.tsx), built as DOM nodes only: no HTML from the note ever
// reaches the page, links open through `onLink` (http, https and mailto, and
// links to items), and images show as links, so a note cannot load anything
// from the network.

type Block =
  | { kind: "heading"; level: number; text: string }
  | { kind: "paragraph"; text: string }
  | { kind: "code"; text: string }
  | { kind: "quote"; children: Block[] }
  | { kind: "list"; ordered: boolean; start: number; items: ListItem[] }
  | { kind: "rule" };

interface ListItem {
  text: string;
  checked: boolean | null;
  children: Block[];
}

const SAFE_LINK = /^(https?:\/\/|mailto:|keyless:\/\/item\/)/i;

/** The note, rendered; `onLink` opens a link the user clicked. */
export function renderMarkdown(text: string, onLink: (href: string) => void): HTMLElement {
  const box = document.createElement("div");
  box.className = "markdown";
  box.append(...renderBlocks(parseBlocks(text.replace(/\r\n?/g, "\n").split("\n")), onLink));
  return box;
}

// ----- blocks -------------------------------------------------------------------------

function indentOf(line: string): number {
  return line.match(/^ */)?.[0].length ?? 0;
}

const LIST_ITEM = /^(\s*)([-*+]|\d{1,9}[.)])\s+(.*)$/;

function parseBlocks(lines: string[]): Block[] {
  const blocks: Block[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    const fence = line.match(/^\s*(```|~~~)/);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith(fence[1])) body.push(lines[i++]);
      i++;
      blocks.push({ kind: "code", text: body.join("\n") });
      continue;
    }
    const heading = line.match(/^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (heading) {
      blocks.push({ kind: "heading", level: heading[1].length, text: heading[2] });
      i++;
      continue;
    }
    if (/^\s{0,3}([-*_])(\s*\1){2,}\s*$/.test(line)) {
      blocks.push({ kind: "rule" });
      i++;
      continue;
    }
    if (/^\s{0,3}>/.test(line)) {
      const body: string[] = [];
      while (i < lines.length && /^\s{0,3}>/.test(lines[i])) body.push(lines[i++].replace(/^\s{0,3}>\s?/, ""));
      blocks.push({ kind: "quote", children: parseBlocks(body) });
      continue;
    }
    if (LIST_ITEM.test(line)) {
      const [list, next] = parseList(lines, i);
      blocks.push(list);
      i = next;
      continue;
    }
    const body: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^\s*(```|~~~)/.test(lines[i]) && !/^\s{0,3}(#{1,6}\s|>)/.test(lines[i]) && !LIST_ITEM.test(lines[i])) {
      body.push(lines[i++]);
    }
    blocks.push({ kind: "paragraph", text: body.join("\n") });
  }
  return blocks;
}

function parseList(lines: string[], from: number): [Block, number] {
  const first = lines[from].match(LIST_ITEM)!;
  const indent = first[1].length;
  const ordered = /\d/.test(first[2]);
  const items: ListItem[] = [];
  let i = from;
  while (i < lines.length) {
    const match = lines[i].match(LIST_ITEM);
    if (!match || match[1].length !== indent || /\d/.test(match[2]) !== ordered) break;
    let text = match[3];
    let checked: boolean | null = null;
    const task = text.match(/^\[([ xX])\]\s+(.*)$/);
    if (task) {
      checked = task[1] !== " ";
      text = task[2];
    }
    i++;
    const nested: string[] = [];
    while (i < lines.length && (lines[i].trim() === "" ? i + 1 < lines.length && indentOf(lines[i + 1]) > indent : indentOf(lines[i]) > indent)) {
      nested.push(lines[i].slice(Math.min(indentOf(lines[i]), indent + 2)));
      i++;
    }
    items.push({ text, checked, children: parseBlocks(nested) });
  }
  return [{ kind: "list", ordered, start: ordered ? parseInt(first[2], 10) || 1 : 1, items }, i];
}

function node<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.append(...children);
  return element;
}

function renderBlocks(blocks: Block[], onLink: (href: string) => void): Node[] {
  return blocks.map((block) => {
    switch (block.kind) {
      case "heading": {
        const heading = node("div", `md-h md-h${Math.min(block.level, 3)}`, ...renderInline(block.text, onLink));
        heading.setAttribute("role", "heading");
        heading.setAttribute("aria-level", String(block.level));
        return heading;
      }
      case "paragraph":
        return node("p", "", ...renderInline(block.text, onLink));
      case "code":
        return node("pre", "", block.text);
      case "quote":
        return node("blockquote", "", ...renderBlocks(block.children, onLink));
      case "rule":
        return node("hr");
      case "list": {
        const list = node(block.ordered ? "ol" : "ul");
        if (block.ordered && list instanceof HTMLOListElement) list.start = block.start;
        for (const item of block.items) {
          const li = node("li", item.checked !== null ? "task" : "");
          if (item.checked !== null) {
            const box = node("input");
            box.type = "checkbox";
            box.checked = item.checked;
            box.disabled = true;
            li.append(box);
          }
          li.append(...renderInline(item.text, onLink));
          if (item.children.length > 0) li.append(...renderBlocks(item.children, onLink));
          list.append(li);
        }
        return list;
      }
    }
  });
}

// ----- inline -------------------------------------------------------------------------

const INLINE =
  /(`[^`]+`)|(!\[[^\]]*\]\([^)\s]+\))|(\[[^\]]+\]\([^)\s]+\))|(\*\*[^*]+\*\*|__[^_]+__)|(~~[^~]+~~)|(\*[^*\s][^*]*\*|_[^_\s][^_]*_)|(<?(?:https?:\/\/|mailto:|keyless:\/\/item\/)[^\s<>()]+>?)/;

function renderInline(text: string, onLink: (href: string) => void): Node[] {
  const out: Node[] = [];
  let rest = text;
  while (rest) {
    const match = rest.match(INLINE);
    if (!match || match.index === undefined) {
      out.push(document.createTextNode(rest));
      break;
    }
    if (match.index > 0) out.push(document.createTextNode(rest.slice(0, match.index)));
    const token = match[0];
    rest = rest.slice(match.index + token.length);
    if (match[1]) {
      out.push(node("code", "", token.slice(1, -1)));
    } else if (match[2]) {
      // The app shows the item's own files here; the popup, their names.
      const [, alt, src] = token.match(/^!\[([^\]]*)\]\(([^)\s]+)\)$/)!;
      out.push(link(src, alt || safeDecode(src), onLink));
    } else if (match[3]) {
      const [, label, href] = token.match(/^\[([^\]]+)\]\(([^)\s]+)\)$/)!;
      out.push(link(href, label, onLink));
    } else if (match[4]) {
      out.push(node("strong", "", ...renderInline(token.slice(2, -2), onLink)));
    } else if (match[5]) {
      out.push(node("s", "", ...renderInline(token.slice(2, -2), onLink)));
    } else if (match[6]) {
      out.push(node("em", "", ...renderInline(token.slice(1, -1), onLink)));
    } else {
      const href = token.replace(/^<|>$/g, "");
      out.push(link(href, href, onLink));
    }
  }
  return out;
}

function safeDecode(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

function link(href: string, label: string, onLink: (href: string) => void): Node {
  if (!SAFE_LINK.test(href)) return node("span", "", label);
  const anchor = node("a", "link", label);
  anchor.href = href;
  anchor.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    onLink(href);
  });
  return anchor;
}

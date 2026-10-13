// Notes in Markdown, rendered as React elements only: no HTML from the note
// ever reaches the page, links open in the system browser (http, https and
// mailto only) or, for links to items (keyless://item/…), in Keyless, and
// images show only the item's own attachments, so a note cannot load
// anything from the network.
//
// Supported: headings, paragraphs, **bold**, *italic*, ~~strikethrough~~,
// `code`, fenced code blocks, quotes, bulleted, numbered and task lists
// (nested by indentation), horizontal rules, [links](https://…), autolinks
// and ![images](attachment name).

import { Fragment, type ReactNode } from "react";

export interface MarkdownOptions {
  /** Opens a link in the system browser. */
  onLink: (href: string) => void;
  /** An attachment of the item, by name, to show as an image; null when
   * the item has no such file. */
  image?: (name: string, alt: string) => ReactNode | null;
}

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

/** Web and mail links open in the browser; links to items open in Keyless. */
const SAFE_LINK = /^(https?:\/\/|mailto:|keyless:\/\/item\/)/i;

/** Whether a note looks like it uses Markdown (worth rendering it so). */
export function looksLikeMarkdown(text: string): boolean {
  return /(^|\n)\s{0,3}(#{1,6}\s|[-*+]\s|\d+[.)]\s|>|```|---\s*$)|\*\*[^*]+\*\*|\[[^\]]+\]\([^)]+\)|`[^`]+`/.test(text);
}

export function Markdown({ text, options }: { text: string; options: MarkdownOptions }) {
  const blocks = parseBlocks(text.replace(/\r\n?/g, "\n").split("\n"));
  return <div className="markdown space-y-2.5 text-sm leading-relaxed">{renderBlocks(blocks, options)}</div>;
}

// ----- blocks -------------------------------------------------------------------------

function indentOf(line: string): number {
  const match = line.match(/^ */);
  return match ? match[0].length : 0;
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
    // Fenced code.
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
    // A paragraph runs until a blank line or another kind of block.
    const body: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !/^\s*(```|~~~)/.test(lines[i]) &&
      !/^\s{0,3}(#{1,6}\s|>)/.test(lines[i]) &&
      !LIST_ITEM.test(lines[i])
    ) {
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
    // Lines indented further belong to this item (nested lists, more text).
    const nested: string[] = [];
    while (i < lines.length && (lines[i].trim() === "" ? i + 1 < lines.length && indentOf(lines[i + 1]) > indent : indentOf(lines[i]) > indent)) {
      nested.push(lines[i].slice(Math.min(indentOf(lines[i]), indent + 2)));
      i++;
    }
    items.push({ text, checked, children: parseBlocks(nested) });
  }
  return [{ kind: "list", ordered, start: ordered ? parseInt(first[2], 10) || 1 : 1, items }, i];
}

function renderBlocks(blocks: Block[], options: MarkdownOptions): ReactNode {
  return blocks.map((block, index) => {
    switch (block.kind) {
      case "heading": {
        const sizes = ["text-lg", "text-base", "text-[15px]", "text-sm", "text-sm", "text-sm"];
        return (
          <div key={index} role="heading" aria-level={block.level} className={`font-semibold tracking-tight ${sizes[block.level - 1]}`}>
            {renderInline(block.text, options)}
          </div>
        );
      }
      case "paragraph":
        return (
          <p key={index} className="whitespace-pre-wrap break-words">
            {renderInline(block.text, options)}
          </p>
        );
      case "code":
        return (
          <pre key={index} className="overflow-x-auto rounded-lg bg-panel-3 px-3 py-2 font-mono text-[13px]">
            {block.text}
          </pre>
        );
      case "quote":
        return (
          <blockquote key={index} className="space-y-2 border-l-2 border-line-strong pl-3 text-muted">
            {renderBlocks(block.children, options)}
          </blockquote>
        );
      case "rule":
        return <hr key={index} className="border-line" />;
      case "list": {
        const items = block.items.map((item, i) => (
          <li key={i} className={item.checked !== null ? "list-none" : undefined}>
            {item.checked !== null && (
              <input type="checkbox" checked={item.checked} readOnly disabled className="mr-2 align-middle accent-[var(--accent)]" />
            )}
            {renderInline(item.text, options)}
            {item.children.length > 0 && <div className="mt-1 space-y-1">{renderBlocks(item.children, options)}</div>}
          </li>
        ));
        return block.ordered ? (
          <ol key={index} start={block.start} className="list-decimal space-y-1 pl-5">
            {items}
          </ol>
        ) : (
          <ul key={index} className="list-disc space-y-1 pl-5">
            {items}
          </ul>
        );
      }
    }
  });
}

// ----- inline -------------------------------------------------------------------------

const INLINE =
  /(`[^`]+`)|(!\[[^\]]*\]\([^)\s]+\))|(\[[^\]]+\]\([^)\s]+\))|(\*\*[^*]+\*\*|__[^_]+__)|(~~[^~]+~~)|(\*[^*\s][^*]*\*|_[^_\s][^_]*_)|(<?(?:https?:\/\/|mailto:|keyless:\/\/item\/)[^\s<>()]+>?)/;

function renderInline(text: string, options: MarkdownOptions): ReactNode {
  const out: ReactNode[] = [];
  let rest = text;
  let key = 0;
  while (rest) {
    const match = rest.match(INLINE);
    if (!match || match.index === undefined) {
      out.push(rest);
      break;
    }
    if (match.index > 0) out.push(rest.slice(0, match.index));
    const token = match[0];
    rest = rest.slice(match.index + token.length);
    const k = key++;
    if (match[1]) {
      out.push(
        <code key={k} className="rounded bg-panel-3 px-1 py-0.5 font-mono text-[12.5px]">
          {token.slice(1, -1)}
        </code>,
      );
    } else if (match[2]) {
      const [, alt, src] = token.match(/^!\[([^\]]*)\]\(([^)\s]+)\)$/)!;
      const image = SAFE_LINK.test(src) ? null : options.image?.(decodeURIComponent(src), alt);
      out.push(image ? <Fragment key={k}>{image}</Fragment> : <LinkText key={k} href={src} label={alt || src} options={options} />);
    } else if (match[3]) {
      const [, label, href] = token.match(/^\[([^\]]+)\]\(([^)\s]+)\)$/)!;
      out.push(<LinkText key={k} href={href} label={label} options={options} />);
    } else if (match[4]) {
      out.push(<strong key={k}>{renderInline(token.slice(2, -2), options)}</strong>);
    } else if (match[5]) {
      out.push(<s key={k}>{renderInline(token.slice(2, -2), options)}</s>);
    } else if (match[6]) {
      out.push(<em key={k}>{renderInline(token.slice(1, -1), options)}</em>);
    } else {
      const href = token.replace(/^<|>$/g, "");
      out.push(<LinkText key={k} href={href} label={href} options={options} />);
    }
  }
  return out;
}

function LinkText({ href, label, options }: { href: string; label: ReactNode; options: MarkdownOptions }) {
  if (!SAFE_LINK.test(href)) return <span>{label}</span>;
  return (
    <a
      href={href}
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        options.onLink(href);
      }}
      className="text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent"
    >
      {label}
    </a>
  );
}

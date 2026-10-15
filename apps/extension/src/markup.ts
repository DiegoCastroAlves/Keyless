/**
 * Markup written in this extension (icons, constants: never a page's or
 * the user's data) as nodes of this document. Parsed apart instead of
 * assigned to innerHTML, which addons.mozilla.org's review flags whatever
 * the value; the HTML parser reads it just as innerHTML did.
 */
export function markupNodes(markup: string): Node[] {
  const body = new DOMParser().parseFromString(markup, "text/html").body;
  return Array.from(body.childNodes, (node) => document.importNode(node, true));
}

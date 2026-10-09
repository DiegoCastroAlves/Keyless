// Loaded first in each test page (test/pages): runs Keyless's field
// detection (src/fields.ts) on the page and compares it with what the page
// says it expects (a JSON script with id "expect", and data-k on fields).
//
// Closed shadow roots: the extension sees them through the browser's
// chrome.dom API, which plain pages lack; here attachShadow keeps them so a
// stand-in for that API can hand them back.

import { composedParent, deepQuery, fieldKind, hasCodeForm, hasLoginForm, isNewPassword, loginFields, partOf, signals, viewable, visible } from "../src/fields";

const roots = new WeakMap<Element, ShadowRoot>();
const attach = Element.prototype.attachShadow;
Element.prototype.attachShadow = function (init: ShadowRootInit) {
  const root = attach.call(this, init);
  roots.set(this, root);
  return root;
};
(globalThis as unknown as { chrome: unknown }).chrome = { dom: { openOrClosedShadowRoot: (el: Element) => roots.get(el) ?? null } };

interface Expect {
  /** data-k -> "username" | "password" | "new-password" | "otp" | "none" | "card:<part>" | "identity:<part>" | "hidden" */
  fields?: Record<string, string>;
  login?: { username: string | null; password: string | null; otp?: string | null };
  loginForm?: boolean;
  codeForm?: boolean;
}

function keyOf(el: Element | null): string | null {
  return el?.getAttribute("data-k") ?? null;
}

function describe(input: HTMLInputElement | HTMLSelectElement): string {
  if (input instanceof HTMLInputElement) {
    if (!viewable(input) && input.type !== "hidden") return "hidden";
    const kind = fieldKind(input);
    if (kind === "password") return isNewPassword(input) ? "new-password" : "password";
    if (kind) return kind;
  }
  const part = partOf(input);
  return part ? `${part[0]}:${part[1]}` : "none";
}

function check(): { ok: boolean; problems: string[]; seen: Record<string, string> } {
  const expect: Expect = JSON.parse(document.getElementById("expect")?.textContent ?? "{}");
  const problems: string[] = [];
  const seen: Record<string, string> = {};
  const controls = deepQuery<HTMLInputElement | HTMLSelectElement>(document, "input, select");
  for (const control of controls) {
    const key = keyOf(control);
    if (!key) continue;
    seen[key] = describe(control);
  }
  for (const [key, wanted] of Object.entries(expect.fields ?? {})) {
    const got = seen[key];
    if (got === undefined) problems.push(`${key}: field not found`);
    // "hidden" fields only need to be skipped; "card"/"identity" without a
    // part only need the kind.
    else if (wanted !== got && !(wanted.endsWith(":*") && got.startsWith(wanted.slice(0, -1)))) problems.push(`${key}: expected ${wanted}, got ${got}`);
  }
  if (expect.login) {
    const fields = loginFields(null);
    const got = { username: keyOf(fields.username), password: keyOf(fields.password), otp: keyOf(fields.otp) };
    if (got.username !== expect.login.username) problems.push(`login username: expected ${expect.login.username}, got ${got.username}`);
    if (got.password !== expect.login.password) problems.push(`login password: expected ${expect.login.password}, got ${got.password}`);
    if (expect.login.otp !== undefined && got.otp !== expect.login.otp) problems.push(`login otp: expected ${expect.login.otp}, got ${got.otp}`);
  }
  if (expect.loginForm !== undefined && hasLoginForm() !== expect.loginForm) problems.push(`loginForm: expected ${expect.loginForm}`);
  if (expect.codeForm !== undefined && hasCodeForm() !== expect.codeForm) problems.push(`codeForm: expected ${expect.codeForm}`);
  return { ok: problems.length === 0, problems, seen };
}

/** For pages from the web: what Keyless finds, without expectations. */
function survey() {
  const inputs = deepQuery<HTMLInputElement>(document, "input");
  const fields = loginFields(null);
  const name = (el: HTMLInputElement | null) =>
    el ? `${el.type}#${el.id || el.name || el.getAttribute("autocomplete") || el.getAttribute("aria-label") || el.placeholder || "?"}` : null;
  return {
    inputs: inputs.filter((i) => viewable(i)).map((i) => `${name(i)}=${describe(i)}`),
    login: { username: name(fields.username), password: name(fields.password), otp: name(fields.otp) },
    loginForm: hasLoginForm(),
    codeForm: hasCodeForm(),
    shadowInputs: inputs.filter((i) => i.getRootNode() instanceof ShadowRoot).length,
    details: inputs
      .filter((i) => i.type !== "hidden" && visible(i))
      .map((i) => {
        const r = i.getBoundingClientRect();
        const top = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
        const describeEl = (el: Element | null) => (el ? `${el.localName}.${String(el.className).slice(0, 40)} opacity=${getComputedStyle(el).opacity}` : null);
        return { field: name(i), seen: describe(i), viewable: viewable(i), why: viewable(i) ? [] : whyHidden(i), rect: [r.x, r.y, r.width, r.height].map(Math.round), top: top === i ? "itself" : describeEl(top), autocomplete: i.autocomplete, inputMode: i.inputMode, maxLength: i.maxLength, signals: signals(i) };
      }),
  };
}

/** Why viewable() says a field cannot be seen (mirrors its checks). */
function whyHidden(el: HTMLElement): string[] {
  const reasons: string[] = [];
  const rect = el.getBoundingClientRect();
  if (rect.width < 10 || rect.height < 10) reasons.push("tiny");
  if (el.checkVisibility && !el.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true })) reasons.push("checkVisibility");
  let opacity = 1;
  for (let node: Element | null = el; node; node = composedParent(node)) {
    const style = getComputedStyle(node);
    if (style.display === "none" || style.visibility !== "visible") reasons.push(`display/visibility on ${node.localName}.${String(node.className).slice(0, 30)}`);
    opacity *= Number(style.opacity);
    if (opacity < 0.1) reasons.push(`opacity ${opacity} at ${node.localName}.${String(node.className).slice(0, 30)}`);
    if (node !== el && /hidden|clip/.test(style.overflow)) {
      const box = node.getBoundingClientRect();
      if (rect.right <= box.left || rect.left >= box.right || rect.bottom <= box.top || rect.top >= box.bottom) reasons.push(`clipped by ${node.localName}.${String(node.className).slice(0, 30)}`);
    }
  }
  return reasons;
}

/** Why a field reads as it does. */
function explain(key: string) {
  const control = deepQuery<HTMLInputElement>(document, `[data-k="${key}"]`)[0];
  if (!control) return null;
  const rect = control.getBoundingClientRect();
  return { describe: describe(control), signals: signals(control), viewable: viewable(control), rect: [rect.x, rect.y, rect.width, rect.height], html: control.outerHTML };
}

(globalThis as unknown as { __keyless: unknown }).__keyless = { check, survey, explain };

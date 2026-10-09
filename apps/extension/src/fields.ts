// Finding a page's fields: login fields (username, password, one-time code),
// new passwords, card and address fields, and whether the user can see them.
// Shared by the content script and the field-detection tests (test/).
//
// Fields are also found inside shadow roots, open or closed (web components),
// which plain DOM queries miss, in document order.
//
// A text field is classified by its signals, scored: its type and
// autocomplete, its name, id, placeholder, aria label, title and test ids,
// its labels (also by aria-labelledby), and the text next to it (a span
// before it, a floating label after it), against words in English,
// Portuguese and Spanish; words that rule a field out (search, newsletter,
// coupon, captcha, address…) count against it.

import type { FieldInfo, FormKind } from "./types";

/** The page itself, not a frame inside it. */
const TOP = window === window.top;

/** Keyless's own element in the page (its button and menus): never a field,
 * and not something covering one. */
let ownElement: Element | null = null;
export function setOwnElement(el: Element) {
  ownElement = el;
}

/** The field the user went to last (the Keyless menu takes the focus from
 * it while open). */
let userField: Element | null = null;
export function setUserField(el: Element | null) {
  userField = el;
}

// ----- Shadow roots -----------------------------------------------------------------

/** The page's own shadow root of `el`, also a closed one where the browser
 * lets extensions see it. */
export function shadowOf(el: Element): ShadowRoot | null {
  if (el === ownElement) return null;
  try {
    const dom = (globalThis as { chrome?: { dom?: { openOrClosedShadowRoot?: (el: HTMLElement) => ShadowRoot | null } } }).chrome?.dom;
    if (dom?.openOrClosedShadowRoot) return el instanceof HTMLElement ? dom.openOrClosedShadowRoot(el) : el.shadowRoot;
    const firefox = (el as Element & { openOrClosedShadowRoot?: () => ShadowRoot | null }).openOrClosedShadowRoot;
    return firefox ? firefox.call(el) : el.shadowRoot;
  } catch {
    return el.shadowRoot;
  }
}

/** A shadow root of `el` worth looking into: open ones on any element, closed
 * ones on custom elements (asking for every element would be slow). */
function rootOf(el: Element): ShadowRoot | null {
  if (el === ownElement) return null;
  return el.shadowRoot ?? (el.localName.includes("-") ? shadowOf(el) : null);
}

const MAX_DEPTH = 8;
let shadowCache: { at: number; any: boolean } = { at: 0, any: false };

/** Whether the page uses shadow roots at all (checked again after a moment). */
function pageHasShadows(): boolean {
  if (Date.now() - shadowCache.at < 1000) return shadowCache.any;
  let any = false;
  const walker = document.createTreeWalker(document.documentElement ?? document, NodeFilter.SHOW_ELEMENT);
  for (let node = walker.nextNode(); node && !any; node = walker.nextNode()) any = rootOf(node as Element) !== null;
  shadowCache = { at: Date.now(), any };
  return any;
}

/** Every element matching `selector` under `root`, in document order, also
 * inside shadow roots (each shadow tree where its host is). */
export function deepQuery<T extends Element = Element>(root: ParentNode, selector: string): T[] {
  if (!pageHasShadows()) return Array.from(root.querySelectorAll<T>(selector));
  const out: T[] = [];
  const visit = (node: Node, depth: number) => {
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
    for (let current = walker.nextNode(); current; current = walker.nextNode()) {
      const el = current as Element;
      if (el.matches(selector)) out.push(el as T);
      const shadow = depth < MAX_DEPTH ? rootOf(el) : null;
      if (shadow) visit(shadow, depth + 1);
    }
  };
  visit(root as Node, 0);
  return out;
}

/** The element's parent, also across a shadow root to its host. */
export function composedParent(node: Element): Element | null {
  if (node.parentElement) return node.parentElement;
  const root = node.getRootNode();
  return root instanceof ShadowRoot ? root.host : null;
}

/** The field that has the focus, also inside shadow roots. */
export function focusedField(): Element | null {
  let el: Element | null = document.activeElement;
  for (let depth = 0; el && depth < MAX_DEPTH; depth++) {
    const inner = rootOf(el)?.activeElement;
    if (!inner) break;
    el = inner;
  }
  return el;
}

/** The innermost element at a point, also inside shadow roots. */
function deepElementFromPoint(x: number, y: number): Element | null {
  let el = document.elementFromPoint(x, y);
  for (let depth = 0; el && depth < MAX_DEPTH; depth++) {
    const inner = rootOf(el)?.elementFromPoint(x, y);
    if (!inner || inner === el) break;
    el = inner;
  }
  return el;
}

/** The field an event really happened in, also inside shadow roots (where
 * the page sees only the host). */
export function eventTarget(event: Event): EventTarget | null {
  let target = event.composedPath()[0] ?? event.target;
  // A closed shadow root hides its inside even from the event's path.
  for (let depth = 0; target instanceof Element && depth < MAX_DEPTH; depth++) {
    const inner = rootOf(target)?.activeElement;
    if (!inner || inner === target) break;
    target = inner;
  }
  return target;
}

/** Where a field's form ends: its form, or the whole page. */
function scopeOf(el: Element | null): ParentNode {
  return (el as HTMLInputElement | null)?.form ?? document;
}

// ----- Seeing a field -----------------------------------------------------------------

export function visible(el: HTMLElement): boolean {
  const rect = el.getBoundingClientRect();
  const style = getComputedStyle(el);
  return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
}

/** clip-path values that leave nothing of an element to see. */
const CLIPPED_AWAY = /^(inset\((50|100)%\)|circle\(0(px)?( at .*)?\)|polygon\((0(px)? 0(px)?,? ?){3,}0(px)? 0(px)?\))$/;

/** A field the user can actually see: not tiny, not transparent or clipped
 * away, not moved out of the page or out of a box that hides what
 * overflows it, and not covered where it is on screen. Pages hide
 * "honeypot" fields to collect what a password manager fills into them. */
export function viewable(el: HTMLElement): boolean {
  const rect = el.getBoundingClientRect();
  if (rect.width < 10 || rect.height < 10) return false;
  // Some pages keep a field transparent until the user is in it (its label
  // shows meanwhile): the field the user is in (or was in, before opening
  // the Keyless menu) is seen. A honeypot is never that field unless the
  // user clicked it.
  const focused = el === focusedField() || el === userField;
  // Outside the page, where no scrolling brings it.
  const root = document.documentElement;
  if (rect.right + scrollX <= 0 || rect.bottom + scrollY <= 0) return false;
  if (rect.left + scrollX >= root.scrollWidth || rect.top + scrollY >= root.scrollHeight) return false;
  if (el.checkVisibility && !el.checkVisibility({ opacityProperty: !focused, visibilityProperty: true, contentVisibilityAuto: true })) return false;
  let opacity = 1;
  // Whether a box that hides its overflow still clips the field on each
  // axis: not once a scrolling box is passed (the user can scroll to it),
  // and not the boxes an absolutely positioned field escapes.
  let clipX = true;
  let clipY = true;
  /** Positioned out of the boxes up to its containing block, which are
   * skipped. */
  let escaping: "" | "absolute" | "fixed" = "";
  for (let node: Element | null = el; node; node = composedParent(node)) {
    const style = getComputedStyle(node);
    if (style.display === "none" || style.visibility !== "visible") return false;
    opacity *= Number(style.opacity);
    if ((opacity < 0.1 && !focused) || CLIPPED_AWAY.test(style.clipPath)) return false;
    if (escaping) {
      const holdsFixed =
        style.transform !== "none" || style.perspective !== "none" || style.filter !== "none" || /paint|layout|strict|content/.test(style.contain);
      if (holdsFixed || (escaping === "absolute" && style.position !== "static")) escaping = "";
      else continue;
    }
    if (node !== el && node !== root && node !== document.body && style.display !== "contents") {
      const box = node.getBoundingClientRect();
      if (clipX && /hidden|clip/.test(style.overflowX) && (rect.right <= box.left || rect.left >= box.right)) return false;
      if (clipY && /hidden|clip/.test(style.overflowY) && (rect.bottom <= box.top || rect.top >= box.bottom)) return false;
      if (/auto|scroll/.test(style.overflowX)) clipX = false;
      if (/auto|scroll/.test(style.overflowY)) clipY = false;
    }
    if (style.position === "absolute" || style.position === "fixed") escaping = style.position;
  }
  const fixed = escaping === "fixed";
  // The window: a fixed field off screen, or a page that cannot be scrolled
  // to where the field is.
  const view = getComputedStyle(root).overflow !== "visible" ? getComputedStyle(root) : document.body ? getComputedStyle(document.body) : null;
  const offX = rect.right <= 0 || rect.left >= innerWidth;
  const offY = rect.bottom <= 0 || rect.top >= innerHeight;
  if (fixed && (offX || offY)) return false;
  if (view && clipX && /hidden|clip/.test(view.overflowX) && offX) return false;
  if (view && clipY && /hidden|clip/.test(view.overflowY) && offY) return false;
  const x = rect.left + rect.width / 2;
  const y = rect.top + rect.height / 2;
  if (x >= 0 && y >= 0 && x < innerWidth && y < innerHeight) {
    const top = deepElementFromPoint(x, y);
    // A floating label drawn over its own field does not hide it.
    const label = top?.closest("label");
    const ownLabel = label !== null && label !== undefined && Array.from((el as HTMLInputElement).labels ?? []).includes(label);
    if (top && top !== el && !el.contains(top) && top !== ownElement && !ownLabel && !seeThrough(top)) return false;
  }
  return true;
}

/** Something on top that cannot be seen (a transparent "honeypot" field
 * laid over the real one) does not hide what is under it. */
function seeThrough(el: Element): boolean {
  let opacity = 1;
  for (let node: Element | null = el; node; node = composedParent(node)) {
    const style = getComputedStyle(node);
    if (style.visibility !== "visible") return true;
    opacity *= Number(style.opacity);
    if (opacity < 0.1) return true;
  }
  return false;
}

// ----- Signals ------------------------------------------------------------------------

/** Attributes pages name their fields with. */
const NAMING_ATTRIBUTES = ["name", "id", "placeholder", "aria-label", "title", "data-testid", "data-test", "data-qa", "formcontrolname", "ng-model", "v-model"];

function textOf(node: Node | null | undefined, max = 80): string {
  return (node?.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, max);
}

/** The text of the field's labels, also by aria-labelledby. */
function labelsOf(control: HTMLInputElement | HTMLSelectElement): string {
  const parts = control.labels ? Array.from(control.labels, (label) => textOf(label)) : [];
  const ids = (control.getAttribute("aria-labelledby") ?? "").split(/\s+/).filter(Boolean);
  const root = control.getRootNode() as Document | ShadowRoot;
  for (const id of ids.slice(0, 4)) parts.push(textOf(root.getElementById?.(id)));
  return parts.join(" ");
}

const FIELDS = "input, select, textarea";

/** Text next to a field that labels it without saying so: a span or text
 * before it, a floating label after it, a little way up while the box holds
 * no other field. */
function nearbyText(control: Element): string {
  const parts: string[] = [];
  let node: Element | null = control;
  for (let level = 0; node && level < 3 && parts.length === 0; level++) {
    for (let sibling = node.previousSibling; sibling; sibling = sibling.previousSibling) {
      if (sibling instanceof Element && sibling.matches("style, script, template, noscript")) continue;
      if (sibling instanceof Element && sibling.matches(`${FIELDS}, button`)) break;
      if (sibling instanceof Element && sibling.querySelector(FIELDS)) break;
      const text = textOf(sibling, 60);
      if (text) {
        parts.push(text);
        break;
      }
    }
    // A floating label after the field (not the next field's label).
    const next = node.nextElementSibling;
    const forOther = next instanceof HTMLLabelElement && next.control !== null && next.control !== control;
    if ((next?.localName === "label" || next?.getAttribute("role") === "label") && !forOther) parts.push(textOf(next, 60));
    const parent = composedParent(node);
    if (!parent || parent.querySelectorAll(FIELDS).length > 1) break;
    node = parent;
  }
  return parts.join(" ");
}

interface Signals {
  /** What the page itself calls the field: attributes and labels. */
  strong: string;
  /** Text next to it. */
  near: string;
}

const signalCache = new WeakMap<Element, { at: number; value: Signals }>();

export function signals(control: HTMLInputElement | HTMLSelectElement): Signals {
  const cached = signalCache.get(control);
  if (cached && Date.now() - cached.at < 500) return cached.value;
  // "mfa_code", "verificationCode": words.
  const attributes = NAMING_ATTRIBUTES.map((name) => control.getAttribute(name) ?? "")
    .join(" ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/_/g, " ");
  const value = { strong: `${attributes} ${labelsOf(control)}`.replace(/\s+/g, " "), near: nearbyText(control) };
  signalCache.set(control, { at: Date.now(), value });
  return value;
}

function tokens(autocomplete: string): string[] {
  return (autocomplete || "").toLowerCase().split(/\s+/).filter(Boolean);
}

// ----- Login fields -------------------------------------------------------------------

export type Kind = "username" | "password" | "otp";

const USERNAME_WORDS =
  /user(.?name|.?id)?|log.?in|e-?mail|account|identi(fier|fica)|ident\b|usu[aá]rio|correo|cpf|cnpj|matr[ií]cula|member|customer.?(id|number)|n[uú]mero.?de.?cliente|apple.?id|conta\b|cuenta|benutzer/i;
const PHONE_WORDS = /phone|telefone|celular|m[oó]vil|mobile|tel[eé]fono|whats/i;
/** Fields that are not a login's, whatever else they say. */
const NOT_USERNAME =
  /search|busca|pesquis|newsletter|subscri|assin(e|ar|atura)|inscrev|suscr|coupon|cupom|cup[oó]n|promo|voucher|gift|presente|captcha|refer(ral|ence)|indica[cç]|\bzip\b|\bcep\b|postal|company|empresa|first.?name|last.?name|full.?name|nome completo|sobrenome|apellido|address|endere[cç]o|direcci[oó]n|\bcity\b|cidade|ciudad|message|mensagem|mensaje|comment|coment|subject|assunto|asunto|friend|amigo/i;
/** Words for a one-time code: sure ones, "token" (what Brazilian banks call
 * it, but also API keys), and plain "code". */
const OTP_SURE =
  /\botp\b|totp|\b2fa\b|\bmfa\b|one.?time|verifica[tcç]|authenticat|autentica|\bsms\b|two.?factor|dois fatores|dos factores|2.?step|duas etapas|dos pasos|\b\d\s?-?\s?(digit|d[ií]gito)s?\b/i;
const OTP_TOKEN = /token/i;
const OTP_CODE = /c[oó]digo|\bcode\b|passcode|\bpin\b/i;
const OTP_WORDS = new RegExp(`${OTP_SURE.source}|${OTP_TOKEN.source}|${OTP_CODE.source}`, "i");
const NOT_OTP = /card|cart[aã]o|tarjeta|cvv|cvc|\bcep\b|\bzip\b|postal|phone|telefone|celular|tel[eé]fono|coupon|cupom|cup[oó]n|promo|captcha|gift|referral|discount|desconto|descuento|country|pa[ií]s/i;
/** Password fields that are not a login's: card codes, PINs, one-time codes. */
const NOT_LOGIN_PASSWORD = /cvv|cvc|csc|security.?code|\bpin\b|otp|token|one.?time|verification|c[oó]digo|card|cart[aã]o|tarjeta/i;
/** "Email address" is an email, not an address. */
const EMAIL_ADDRESS =
  /e-?mail address|endere[cç]o (d[eo] )?(seu |sua )?e-?mail|direcci[oó]n (de )?(tu |su )?(correo( electr[oó]nico)?|e-?mail)|address of (your )?e-?mail/gi;

/** Fields whose autocomplete says what they are: not a login's. (Pages put
 * "new-password" on any field to keep browsers from filling it, and "tel"
 * on "phone or email" fields: those say nothing.) */
const OTHER_AUTOCOMPLETE = /^(cc-|address|street|postal|country|given-name|family-name|additional-name|honorific|organization|bday|sex|url|photo|transaction)/;

/** A short field: a code, not a name. */
function short(input: HTMLInputElement): boolean {
  return input.maxLength > 0 && input.maxLength <= 10;
}

/** One box of a code split over several (a box per digit). */
function splitBox(input: HTMLInputElement): boolean {
  if (input.maxLength !== 1) return false;
  const parent = composedParent(input)?.parentElement ?? composedParent(input);
  const boxes = parent ? Array.from(parent.querySelectorAll<HTMLInputElement>("input")).filter((i) => i.maxLength === 1) : [];
  return boxes.length >= 4 && boxes.length <= 8;
}

/** The box a field belongs to: its form, or the nearest box around it with
 * a button (pages without forms). */
function boxOf(input: HTMLInputElement): Element | null {
  if (input.form) return input.form;
  let node: Element | null = composedParent(input);
  for (let level = 0; node && level < 4; level++, node = composedParent(node)) {
    if (node.querySelector('button, input[type="submit"], [role="button"]')) return node;
  }
  return null;
}

/** The only field in its box: a sign-in's first step, or its code step. */
function aloneIn(input: HTMLInputElement, box: Element | null): boolean {
  return box !== null && Array.from(box.querySelectorAll("input")).filter((i) => i.type !== "hidden" && (i === input || visible(i))).length === 1;
}

/** What the field's box says about itself: its buttons, its action. */
function boxSays(box: Element | null, pattern: RegExp): boolean {
  if (!box) return false;
  const buttons = Array.from(box.querySelectorAll<HTMLElement>('button, input[type="submit"], [role="button"]'))
    .slice(0, 4)
    .map((b) => (b instanceof HTMLInputElement ? b.value : textOf(b, 40)))
    .join(" ");
  return pattern.test(`${buttons} ${box.getAttribute("action") ?? ""} ${box.getAttribute("role") ?? ""} ${box.id} ${typeof box.className === "string" ? box.className : ""}`);
}

const NEWSLETTER_BOX = /newsletter|subscri|assin|inscrev|suscr|search|busca|pesquis|offers|ofertas|bolet[ií]n/i;

export function fieldKind(input: HTMLInputElement): Kind | null {
  if (input.disabled || input.readOnly) return null;
  const type = (input.type || "text").toLowerCase();
  const autocomplete = tokens(input.autocomplete);
  if (type === "password") {
    // Some pages mask one-time codes, card codes and PINs too.
    if (autocomplete.includes("one-time-code")) return "otp";
    if (autocomplete.some((t) => t.startsWith("cc-"))) return null;
    const { strong } = signals(input);
    if (NOT_LOGIN_PASSWORD.test(strong)) return OTP_WORDS.test(strong) && short(input) ? "otp" : null;
    // A short numeric secret.
    if (input.maxLength > 0 && input.maxLength <= 6 && /numeric|decimal|tel/.test(input.inputMode)) return null;
    return "password";
  }
  if (autocomplete.includes("one-time-code")) return "otp";
  if (!["text", "email", "tel", "number", ""].includes(type)) return null;
  const said = autocomplete.find((t) => t !== "on" && t !== "off" && t !== "webauthn" && !t.startsWith("section-") && t !== "shipping" && t !== "billing");
  if (said && OTHER_AUTOCOMPLETE.test(said)) return null;
  const { strong, near } = signals(input);

  const box = boxOf(input);
  const withPassword = box?.querySelector('input[type="password"]') !== null && box !== null;

  // Scores: 2 or more for a username, 3 or more for a code.
  let user = 0;
  if (said === "username" || said === "email" || autocomplete.includes("webauthn")) user += 4;
  if (type === "email") user += 2;
  if (USERNAME_WORDS.test(strong)) user += 2;
  else if (USERNAME_WORDS.test(near)) user += 1.5;
  const telephone = said === "tel" || said === "tel-national";
  if (telephone) user += USERNAME_WORDS.test(strong) ? 1 : 0.5;
  if (PHONE_WORDS.test(strong) || PHONE_WORDS.test(near)) user += 0.5;
  // Next to a password: a sign-in's username, most likely. Alone with a
  // button: its first step.
  const alone = aloneIn(input, box);
  if (withPassword) user += 1;
  else if (alone) user += 0.5;
  const notUser = (text: string) => NOT_USERNAME.test(text.replace(EMAIL_ADDRESS, "email"));
  if (notUser(strong) || (!USERNAME_WORDS.test(strong) && notUser(near))) user -= 4;
  // A box with a message to write is a contact form (captchas keep their
  // answer in a hidden textarea).
  const message = box !== null && Array.from(box.querySelectorAll("textarea")).some((t) => visible(t));
  if (!withPassword && (boxSays(box, NEWSLETTER_BOX) || message)) user -= 4;
  if (type === "number") user = 0;

  let otp = 0;
  for (const [text, weight] of [
    [strong, 1],
    [near, 0.75],
  ] as const) {
    const words = OTP_SURE.test(text) ? 3 : OTP_TOKEN.test(text) ? 2 : OTP_CODE.test(text) ? 1.5 : 0;
    if (words) {
      otp += words * weight;
      break;
    }
  }
  if (short(input)) otp += 1;
  if (splitBox(input)) otp += 2;
  // The only field in its box (the sign-in's code step).
  if (alone && (short(input) || /numeric|decimal/.test(input.inputMode) || type === "number" || type === "tel")) otp += 0.5;
  if (/numeric|decimal/.test(input.inputMode) || type === "number" || type === "tel") otp += 0.5;
  if (NOT_OTP.test(strong) || (!OTP_WORDS.test(strong) && NOT_OTP.test(near))) otp -= 4;

  if (otp >= 3 && otp >= user) return "otp";
  if (user >= 2) return "username";
  return null;
}

/** A field that offers passkeys (autocomplete "username webauthn"). */
export function wantsPasskey(input: HTMLInputElement): boolean {
  return tokens(input.autocomplete).includes("webauthn");
}

const NEW_PASSWORD_HINT = /new|confirm|repeat|again|retype|regist|sign.?up|create|nova|novo|nueva|nuevo|confirma|repit|repet|cadastr|crear|escolha|choose/i;
const CURRENT_PASSWORD_HINT = /current|old|existing|atual|actual|anterior/i;

const LOGIN_BOX = /\b(log ?in|sign ?in|entrar|acessar|iniciar sesi[oó]n|ingresar)\b/i;
const SIGNUP_BOX = /sign ?up|regist|creat|criar|cadastr|crear|join|inscrev|cr[eé]e/i;

/** A password being chosen (sign-up, change password), not typed from memory. */
export function isNewPassword(input: HTMLInputElement): boolean {
  if (fieldKind(input) !== "password") return false;
  const autocomplete = tokens(input.autocomplete);
  const passwords = () => deepQuery<HTMLInputElement>(scopeOf(input), 'input[type="password"]').filter((p) => visible(p) && fieldKind(p) === "password");
  if (autocomplete.includes("new-password")) {
    // Some sign-in pages mark their only password "new" to keep browsers
    // away: its button says so.
    const box = boxOf(input);
    const signIn = boxSays(box, LOGIN_BOX) && !boxSays(box, SIGNUP_BOX) && passwords().length === 1;
    return !signIn;
  }
  const { strong } = signals(input);
  if (autocomplete.includes("current-password") || CURRENT_PASSWORD_HINT.test(strong)) return false;
  if (NEW_PASSWORD_HINT.test(strong)) return true;
  // Password and confirmation (sign-up); current, new and confirmation.
  const all = passwords();
  return all.length === 2 || (all.length >= 3 && all.indexOf(input) > 0);
}

/** The fields to fill a login into: the password, the username before it
 * (or the page's username field), and a field for the one-time code. */
export function loginFields(anchor: HTMLInputElement | null) {
  const inputs = deepQuery<HTMLInputElement>(scopeOf(anchor), "input").filter(viewable);
  const password = inputs.find((i) => fieldKind(i) === "password" && !isNewPassword(i)) ?? inputs.find((i) => fieldKind(i) === "password") ?? null;
  let username: HTMLInputElement | null = null;
  if (password) {
    const before = inputs.slice(0, inputs.indexOf(password)).filter((i) => fieldKind(i) === "username");
    // An email or user name over a phone number (sign-up forms ask both).
    const named = before.filter(namesAccount);
    username = named[named.length - 1] ?? before[before.length - 1] ?? null;
  }
  if (!username) username = inputs.find((i) => fieldKind(i) === "username") ?? null;
  const otp = inputs.find((i) => fieldKind(i) === "otp") ?? null;
  return { username, password, otp };
}

/** A username field that names an account (email, user name), not only a
 * phone number. */
function namesAccount(input: HTMLInputElement): boolean {
  const autocomplete = tokens(input.autocomplete);
  return input.type === "email" || autocomplete.includes("username") || autocomplete.includes("email") || USERNAME_WORDS.test(signals(input).strong);
}

/** Every input of the page, also inside shadow roots. */
export function pageInputs(): HTMLInputElement[] {
  return deepQuery<HTMLInputElement>(document, "input");
}

/** True when the page shows a form to sign in (not just any email field,
 * and not a sign-up form). */
export function hasLoginForm(): boolean {
  const inputs = pageInputs().filter(visible);
  const passwords = inputs.filter((input) => fieldKind(input) === "password");
  if (passwords.length > 0) return passwords.some((input) => !isNewPassword(input));
  // A first step that asks only for the username: one that says so, or the
  // only field in its box.
  return inputs.some((input) => fieldKind(input) === "username" && (tokens(input.autocomplete).some((t) => t === "username" || t === "webauthn") || aloneIn(input, boxOf(input))));
}

/** True when the page asks only for a one-time code (the sign-in's next
 * step). */
export function hasCodeForm(): boolean {
  const inputs = pageInputs().filter(visible);
  return !inputs.some((input) => fieldKind(input) === "password") && inputs.some((input) => fieldKind(input) === "otp");
}

const SUBMIT_TEXT = /^(log ?in|sign ?in|entrar|acessar|iniciar sesi[oó]n|ingresar|continue|continuar|next|avan[cç]ar|pr[oó]ximo|siguiente)$/i;

export function submitButton(field: HTMLInputElement): HTMLElement | null {
  const candidates = deepQuery<HTMLElement>(scopeOf(field), 'button, input[type="submit"], input[type="image"], [role="button"]').filter(visible);
  const label = (el: HTMLElement) => (el instanceof HTMLInputElement ? el.value : (el.textContent ?? "")).trim();
  // Outside a form, a submit button could belong to anything (a search box):
  // only one that reads like signing in will do.
  return (
    (field.form ? candidates.find((el) => (el as HTMLButtonElement).type === "submit") : undefined) ??
    candidates.find((el) => SUBMIT_TEXT.test(label(el))) ??
    null
  );
}

// ----- Payment and address forms ------------------------------------------------------

export type FormControl = HTMLInputElement | HTMLSelectElement;

const AUTOCOMPLETE_PARTS: Record<string, [FormKind, string]> = {
  "cc-number": ["card", "number"],
  "cc-name": ["card", "holder"],
  "cc-csc": ["card", "code"],
  "cc-exp": ["card", "exp"],
  "cc-exp-month": ["card", "expMonth"],
  "cc-exp-year": ["card", "expYear"],
  "cc-type": ["card", "brand"],
  "given-name": ["identity", "firstName"],
  "family-name": ["identity", "lastName"],
  name: ["identity", "name"],
  tel: ["identity", "phone"],
  "tel-national": ["identity", "phone"],
  "street-address": ["identity", "street"],
  "address-line1": ["identity", "street"],
  "address-line2": ["identity", "line2"],
  "address-level2": ["identity", "city"],
  "address-level1": ["identity", "state"],
  "postal-code": ["identity", "zip"],
  country: ["identity", "country"],
  "country-name": ["identity", "country"],
  organization: ["identity", "company"],
  bday: ["identity", "birthDate"],
};

const CARD_HINTS: [string, RegExp][] = [
  ["number", /card.?num|cc.?num|cardnumber|n[uú]mero.?(do|de)?.?cart[aã]o|n[uú]mero.?(de|da)?.?tarjeta|credit.?card|card.?no\b/i],
  ["holder", /card.?holder|holder.?name|name.{0,8}card|cc.?name|titular|nome.{0,16}cart[aã]o|nombre.{0,14}tarjeta/i],
  ["code", /cvv|cvc|csc|security.?code|card.?code|c[oó]digo.?(de)?.?seguran|c[oó]d.?seg/i],
  ["expMonth", /exp.*(month|m[eê]s)|(month|m[eê]s).*(exp|valid)/i],
  ["expYear", /exp.*(year|ano|a[ñn]o)|(year|ano|a[ñn]o).*(exp|valid)/i],
  ["exp", /expir|exp.?date|valid|validade|vencim|mm.?\/?.?(yy|aa)/i],
];

const IDENTITY_HINTS: [string, RegExp][] = [
  ["firstName", /first.?name|given.?name|fname|primeiro.?nome/i],
  ["lastName", /last.?name|surname|family.?name|lname|sobrenome|apellido/i],
  ["zip", /zip|postal|\bcep\b|c[oó]digo.?postal/i],
  ["city", /city|cidade|ciudad|munic[ií]pio|localidad/i],
  ["state", /\bstate\b|province|estado|provincia|\buf\b|region/i],
  ["country", /country|pa[ií]s/i],
  ["line2", /address.?(line)?.?2|complemento|apartment|apto/i],
  ["street", /address|street|endere[cç]o|logradouro|\brua\b|direcci[oó]n|calle/i],
  ["phone", /phone|telefone|celular|tel[eé]fono|mobile/i],
  ["company", /company|empresa|organi[sz]ation/i],
];

/** What a field of a payment or address form asks for. */
export function partOf(control: FormControl): [FormKind, string] | null {
  const autocomplete = tokens(control.autocomplete);
  const explicit = AUTOCOMPLETE_PARTS[autocomplete[autocomplete.length - 1] ?? ""];
  if (explicit) return explicit;
  if (control instanceof HTMLInputElement && !["text", "tel", "number", "month", "date", ""].includes(control.type)) return null;
  const { strong, near } = signals(control);
  for (const text of [strong, near]) {
    for (const [part, pattern] of CARD_HINTS) if (pattern.test(text)) return ["card", part];
    for (const [part, pattern] of IDENTITY_HINTS) if (pattern.test(text)) return ["identity", part];
  }
  return null;
}

/** The form's fields of this kind, with what each asks for: the first
 * visible field for each thing asked. */
export function formParts(anchor: Element | null, kind: FormKind, check: (el: HTMLElement) => boolean = viewable): Map<FormControl, string> {
  const parts = new Map<FormControl, string>();
  const taken = new Set<string>();
  for (const control of deepQuery<FormControl>(scopeOf(anchor), "input, select")) {
    // Selects are often hidden under a page's own drop-down: only inputs
    // can be "honeypots" worth worrying about.
    if (control.disabled || !(control instanceof HTMLSelectElement ? visible(control) : check(control))) continue;
    let part: string | null = null;
    if (control instanceof HTMLInputElement && fieldKind(control)) {
      // Login fields stay login fields; an address form's email is filled too.
      const email = control.type === "email" || tokens(control.autocomplete).includes("email");
      if (kind === "identity" && email) part = "email";
    } else {
      const found = partOf(control);
      if (found?.[0] === kind) part = found[1];
    }
    if (part && !taken.has(part)) {
      taken.add(part);
      parts.set(control, part);
    }
  }
  return parts;
}

/** A payment service's frame holding one or a few of a card's fields (each
 * often in a frame of its own). */
export function hostedFields(): boolean {
  return !TOP && pageInputs().length <= 4;
}

/** A payment or address form field. A hint in its name alone is not
 * enough: the form must ask for at least two such things (a card field in a
 * payment service's frame is enough on its own). */
export function formKindOf(control: FormControl): FormKind | null {
  const part = partOf(control);
  if (!part) return null;
  const needed = part[0] === "card" && hostedFields() ? 1 : 2;
  return formParts(control, part[0], visible).size >= needed ? part[0] : null;
}

/** The kinds of payment and address fields this frame shows: for cards,
 * also a single field the page marks as one (the name on the card next to a
 * payment service's frames). */
export function formKinds(): { card: boolean; identity: boolean } {
  const found = { card: 0, identity: 0, marked: 0 };
  for (const control of deepQuery<FormControl>(document, "input, select")) {
    if (control.disabled || !visible(control) || (control instanceof HTMLInputElement && fieldKind(control))) continue;
    const part = partOf(control);
    if (!part) continue;
    found[part[0]]++;
    if (part[0] === "card" && /\bcc-/.test((control.autocomplete || "").toLowerCase())) found.marked++;
  }
  return { card: found.marked >= 1 || found.card >= (hostedFields() ? 1 : 2), identity: found.identity >= 2 };
}

/** What the Keyless menu should offer in a field. */
export function fieldInfo(input: HTMLInputElement): FieldInfo {
  const kind = fieldKind(input);
  const newPassword = isNewPassword(input);
  return {
    newPassword,
    rules: newPassword ? (input.getAttribute("passwordrules")?.slice(0, 1024) ?? undefined) : undefined,
    maxLength: input.maxLength > 0 ? input.maxLength : null,
    form: kind ? null : formKindOf(input),
    code: kind === "otp",
    passkeys: kind === "username" && wantsPasskey(input),
  };
}

// ----- Signing in ---------------------------------------------------------------------

const TYPED = new Set(["text", "email", "password", "tel", "number", "search", "url"]);

/** After filling a login: the form can be sent as it is. Not when a field
 * the user can see is still empty (a captcha, a password the login lacks),
 * nor in a sign-up or change-password form. */
export function readyToSubmit(filled: HTMLInputElement[]): boolean {
  const anchor = filled[0];
  if (!anchor) return false;
  const scope: ParentNode = anchor.form ?? boxOf(anchor) ?? composedParent(anchor) ?? document;
  const inputs = deepQuery<HTMLInputElement>(scope, "input").filter((i) => !i.disabled && !i.readOnly && viewable(i));
  if (inputs.some((i) => fieldKind(i) === "password" && isNewPassword(i))) return false;
  return !inputs.some((i) => TYPED.has(i.type || "text") && !filled.includes(i) && i.value === "");
}

/** The field of a sign-in's next step, once the page shows it: the password
 * after the username, the one-time code after the password. Only an empty
 * one the user can see. */
export function nextStepField(step: "password" | "otp"): HTMLInputElement | null {
  const fields = loginFields(null);
  const field = step === "password" ? fields.password : fields.otp;
  if (!field || field.value !== "" || field.disabled || field.readOnly) return null;
  if (step === "password" && isNewPassword(field)) return null;
  return field;
}

// ----- Filling -----------------------------------------------------------------------

/** Sets a value the way frameworks (React, Vue, Angular) notice. */
export function setValue(input: HTMLInputElement, value: string) {
  input.focus();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
}

/** Fills a value split over several boxes when the page asks for it that
 * way (a one-time code in 6 boxes, a card number in 4). */
export function setSplit(first: HTMLInputElement, value: string) {
  const size = first.maxLength;
  if (size > 0 && size < value.length) {
    const scope = composedParent(first)?.parentElement ?? composedParent(first) ?? document;
    const all = deepQuery<HTMLInputElement>(scope, "input").filter((i) => i.maxLength === size && viewable(i));
    const boxes = all.slice(Math.max(0, all.indexOf(first)));
    if (boxes.length * size >= value.length) {
      boxes.slice(0, Math.ceil(value.length / size)).forEach((box, i) => setValue(box, value.slice(i * size, (i + 1) * size)));
      return;
    }
  }
  setValue(first, value);
}

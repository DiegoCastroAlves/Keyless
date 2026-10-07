// Content script: finds login fields, puts the Keyless button in them and
// hosts the Keyless menus: the list below a login field (with a suggested
// password in sign-up forms), the sign-in card at the top of the page and
// the "Save login?" prompt.
//
// Runs only in the top frame. The menus are extension pages (inline.html) in
// iframes inside a closed shadow root: the page cannot read the logins they
// list, and only they (or the popup) can ask Keyless to fill or save. This
// script learns nothing about the logins except how many match the page,
// gets credentials only to type them into the page once the user picked one,
// and reports what the user typed when a login form is submitted.

import type { Credentials, FieldInfo, FormKind, PageState, Status } from "./types";

const t = (key: string) => chrome.i18n.getMessage(key) || key;

const EXTENSION_ORIGIN = new URL(chrome.runtime.getURL("")).origin;
/** Transparent margin around the menus, room for their shadow. */
const PAD = 10;
const MENU_WIDTH = 320;
const CARD_WIDTH = 400;
const SAVE_WIDTH = 380;

/** Proves to the background that a menu was opened by this script. Not
 * crypto.randomUUID: that needs a secure context, and http pages are not. */
const token = Array.from(crypto.getRandomValues(new Uint8Array(24)), (b) => b.toString(16).padStart(2, "0")).join("");

const USERNAME_HINT = /user|email|e-mail|login|account|identifier|usuario|correo|cpf/i;
const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|token|c[oó]digo|code/i;
const SUBMIT_TEXT = /^(log ?in|sign ?in|entrar|acessar|iniciar sesi[oó]n|ingresar|continue|continuar|next|avan[cç]ar|pr[oó]ximo|siguiente)$/i;
/** Buttons that send a login, sign-up or change-password form. */
const SEND_TEXT =
  /\b(log ?in|sign ?in|sign ?up|entrar|acessar|iniciar sesi[oó]n|ingresar|continu[ea]r?|next|avan[cç]ar|pr[oó]ximo|siguiente|register|registr\w*|cadastr\w*|criar|create|crear|join|save|salvar|guardar|change|alterar|cambiar|update|atualizar|actualizar|submit|enviar)\b/i;
/** Password fields for a new password, and for the current one. */
const NEW_PASSWORD_HINT = /new|confirm|repeat|again|retype|regist|sign.?up|create|nova|novo|nueva|nuevo|confirma|cadastr|crear/i;
const CURRENT_PASSWORD_HINT = /current|old|existing|atual|actual|anterior/i;

type Kind = "username" | "password" | "otp";

function fieldKind(input: HTMLInputElement): Kind | null {
  if (input.disabled || input.readOnly) return null;
  const type = (input.type || "text").toLowerCase();
  const autocomplete = (input.autocomplete || "").toLowerCase();
  const hints = `${input.name} ${input.id} ${input.placeholder} ${input.getAttribute("aria-label") ?? ""}`;
  if (type === "password") return "password";
  if (autocomplete.includes("one-time-code")) return "otp";
  if (!["text", "email", "tel", ""].includes(type)) return null;
  if (autocomplete.includes("username") || autocomplete.includes("email") || type === "email") return "username";
  if (OTP_HINT.test(hints) && input.maxLength > 0 && input.maxLength <= 10) return "otp";
  if (USERNAME_HINT.test(hints)) return "username";
  return null;
}

function visible(el: HTMLElement): boolean {
  const rect = el.getBoundingClientRect();
  const style = getComputedStyle(el);
  return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
}

/** Sets a value the way frameworks (React, Vue, Angular) notice. */
function setValue(input: HTMLInputElement, value: string) {
  input.focus();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function loginFields(anchor: HTMLInputElement | null) {
  const scope: ParentNode = anchor?.form ?? document;
  const inputs = Array.from(scope.querySelectorAll<HTMLInputElement>("input")).filter(visible);
  const password = inputs.find((i) => i.type === "password") ?? null;
  let username: HTMLInputElement | null = null;
  if (password) {
    const before = inputs.slice(0, inputs.indexOf(password)).filter((i) => fieldKind(i) === "username");
    username = before[before.length - 1] ?? null;
  }
  if (!username) username = inputs.find((i) => fieldKind(i) === "username") ?? null;
  const otp = inputs.find((i) => fieldKind(i) === "otp") ?? null;
  return { username, password, otp };
}

function fill(anchor: HTMLInputElement | null, credentials: Credentials) {
  const fields = loginFields(anchor);
  if (fields.username && credentials.username) setValue(fields.username, credentials.username);
  if (fields.password && credentials.password) setValue(fields.password, credentials.password);
  if (fields.otp && credentials.totp && !fields.password) setValue(fields.otp, credentials.totp);
  return fields;
}

function hintsOf(input: HTMLInputElement): string {
  return `${input.name} ${input.id} ${input.placeholder} ${input.getAttribute("aria-label") ?? ""}`;
}

/** A password being chosen (sign-up, change password), not typed from memory. */
function isNewPassword(input: HTMLInputElement): boolean {
  if (input.type !== "password") return false;
  const autocomplete = (input.autocomplete || "").toLowerCase();
  if (autocomplete.includes("new-password")) return true;
  if (autocomplete.includes("current-password") || CURRENT_PASSWORD_HINT.test(hintsOf(input))) return false;
  if (NEW_PASSWORD_HINT.test(hintsOf(input))) return true;
  // Password and confirmation (sign-up); current, new and confirmation.
  const scope: ParentNode = input.form ?? document;
  const passwords = Array.from(scope.querySelectorAll<HTMLInputElement>('input[type="password"]')).filter(visible);
  return passwords.length === 2 || (passwords.length >= 3 && passwords.indexOf(input) > 0);
}

// ----- Payment and address forms --------------------------------------------------

type FormControl = HTMLInputElement | HTMLSelectElement;

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
  ["number", /card.?num|cc.?num|cardnumber|n[uú]mero.?(do|de)?.?cart[aã]o|n[uú]mero.?(de)?.?tarjeta/i],
  ["holder", /card.?holder|holder.?name|name.?on.?card|cc.?name|titular|nome.?(no|do|impresso)?.?cart[aã]o|nombre.?(en|del)?.?tarjeta/i],
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

const MONTHS = [
  ["jan", "january", "janeiro", "enero"],
  ["feb", "february", "fevereiro", "febrero", "fev"],
  ["mar", "march", "março", "marzo"],
  ["apr", "april", "abril", "abr"],
  ["may", "maio", "mayo", "mai"],
  ["jun", "june", "junho", "junio"],
  ["jul", "july", "julho", "julio"],
  ["aug", "august", "agosto", "ago"],
  ["sep", "september", "setembro", "septiembre", "set"],
  ["oct", "october", "outubro", "octubre", "out"],
  ["nov", "november", "novembro", "noviembre"],
  ["dec", "december", "dezembro", "diciembre", "dez", "dic"],
];

function labelText(control: FormControl): string {
  return control.labels ? Array.from(control.labels, (label) => label.textContent ?? "").join(" ") : "";
}

/** What a field of a payment or address form asks for. */
function partOf(control: FormControl): [FormKind, string] | null {
  const tokens = (control.autocomplete || "").toLowerCase().split(/\s+/).filter(Boolean);
  const explicit = AUTOCOMPLETE_PARTS[tokens[tokens.length - 1] ?? ""];
  if (explicit) return explicit;
  if (control instanceof HTMLInputElement && !["text", "tel", "number", "month", "date", ""].includes(control.type)) return null;
  const hints = `${control.name} ${control.id} ${control.getAttribute("placeholder") ?? ""} ${control.getAttribute("aria-label") ?? ""} ${labelText(control)}`;
  for (const [part, pattern] of CARD_HINTS) if (pattern.test(hints)) return ["card", part];
  for (const [part, pattern] of IDENTITY_HINTS) if (pattern.test(hints)) return ["identity", part];
  return null;
}

/** The form's fields of this kind, with what each asks for. */
function formParts(anchor: Element | null, kind: FormKind): Map<FormControl, string> {
  const scope: ParentNode = (anchor as FormControl | null)?.form ?? document;
  const parts = new Map<FormControl, string>();
  for (const control of scope.querySelectorAll<FormControl>("input, select")) {
    if (control.disabled || !visible(control)) continue;
    if (control instanceof HTMLInputElement && fieldKind(control)) {
      // Login fields stay login fields; an address form's email is filled too.
      const email = control.type === "email" || (control.autocomplete || "").toLowerCase().includes("email");
      if (kind === "identity" && email) parts.set(control, "email");
      continue;
    }
    const part = partOf(control);
    if (part?.[0] === kind) parts.set(control, part[1]);
  }
  return parts;
}

/** A payment or address form field. A hint in its name alone is not
 * enough: the form must ask for at least two such things. */
function formKindOf(control: FormControl): FormKind | null {
  const part = partOf(control);
  if (!part) return null;
  return formParts(control, part[0]).size >= 2 ? part[0] : null;
}

function fieldInfo(input: HTMLInputElement): FieldInfo {
  return {
    newPassword: isNewPassword(input),
    maxLength: input.maxLength > 0 ? input.maxLength : null,
    form: fieldKind(input) ? null : formKindOf(input),
  };
}

function valuesFor(kind: FormKind, part: string, data: Record<string, unknown>, control: FormControl): string[] {
  const text = (key: string) => (typeof data[key] === "string" ? (data[key] as string) : "");
  if (kind === "identity") return text(part) ? [text(part)] : [];
  const month = Number(data.expMonth) || 0;
  const year = Number(data.expYear) || 0;
  const mm = String(month).padStart(2, "0");
  const yyyy = String(year);
  switch (part) {
    case "expMonth":
      return month ? [mm, String(month), ...MONTHS[month - 1]] : [];
    case "expYear":
      return year ? [yyyy, yyyy.slice(2)] : [];
    case "exp": {
      if (!month || !year) return [];
      if (control instanceof HTMLInputElement && control.type === "month") return [`${yyyy}-${mm}`];
      const hint = `${control.getAttribute("placeholder") ?? ""} ${control.name} ${control.id}`;
      const long = /yyyy|aaaa/i.test(hint) || (control instanceof HTMLInputElement && control.maxLength >= 7);
      return [long ? `${mm}/${yyyy}` : `${mm}/${yyyy.slice(2)}`];
    }
    default:
      return text(part) ? [text(part)] : [];
  }
}

function setControl(control: FormControl, values: string[]) {
  if (control instanceof HTMLSelectElement) {
    const wanted = values.map((v) => v.toLowerCase().trim()).filter(Boolean);
    const options = Array.from(control.options);
    const normalize = (s: string) => s.toLowerCase().trim();
    const option =
      options.find((o) => wanted.includes(normalize(o.value)) || wanted.includes(normalize(o.text))) ??
      options.find((o) => wanted.some((w) => w.length > 2 && normalize(o.text).startsWith(w)));
    if (!option) return;
    control.value = option.value;
    control.dispatchEvent(new Event("input", { bubbles: true }));
    control.dispatchEvent(new Event("change", { bubbles: true }));
  } else if (values[0]) {
    setValue(control, values[0]);
  }
}

/** Fills a card or an identity into the form around the focused field. */
function fillForm(kind: FormKind, data: Record<string, unknown>) {
  filling = true;
  try {
    for (const [control, part] of formParts(current, kind)) setControl(control, valuesFor(kind, part, data, control));
  } finally {
    filling = false;
  }
  closeMenu();
}

/** True when the page shows a form to sign in (not just any email field,
 * and not a sign-up form). */
function hasLoginForm(): boolean {
  const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input")).filter(visible);
  const passwords = inputs.filter((input) => fieldKind(input) === "password");
  if (passwords.length > 0) return passwords.some((input) => !isNewPassword(input));
  return inputs.some((input) => fieldKind(input) === "username" && (input.autocomplete || "").toLowerCase().includes("username"));
}

function submitButton(field: HTMLInputElement): HTMLElement | null {
  const scope: ParentNode = field.form ?? document;
  const candidates = Array.from(
    scope.querySelectorAll<HTMLElement>('button, input[type="submit"], input[type="image"], [role="button"]'),
  ).filter(visible);
  const label = (el: HTMLElement) => (el instanceof HTMLInputElement ? el.value : el.textContent ?? "").trim();
  // Outside a form, a submit button could belong to anything (a search box):
  // only one that reads like signing in will do.
  return (
    (field.form ? candidates.find((el) => (el as HTMLButtonElement).type === "submit") : undefined) ??
    candidates.find((el) => SUBMIT_TEXT.test(label(el))) ??
    null
  );
}

/** Signs in after filling: clicks the form's button once the page enabled it. */
async function submitAfterFill(field: HTMLInputElement) {
  let button: HTMLElement | null = null;
  for (let attempt = 0; attempt < 10; attempt++) {
    // Pages often enable the button only after reacting to the new values.
    await new Promise((resolve) => setTimeout(resolve, 100));
    button = submitButton(field);
    if (button && !(button as HTMLButtonElement).disabled && button.getAttribute("aria-disabled") !== "true") {
      button.click();
      return;
    }
  }
  if (!button && field.form) field.form.requestSubmit();
}

// ----- UI ---------------------------------------------------------------------

const LOGO = `<svg class="logo" viewBox="0 0 1024 1024" width="18" height="18" aria-hidden="true"><circle cx="512" cy="512" r="452" fill="#14B8A6"/><circle cx="512" cy="512" r="318" fill="#073b37"/><circle cx="512" cy="438" r="94" fill="#fff"/><path d="M470 486H554L586 676Q590 702 564 702H460Q434 702 438 676Z" fill="#fff"/></svg>`;

const STYLE = `
:host { all: initial; }
.btn { position: fixed; z-index: 2147483646; height: 24px; min-width: 24px; border: 0; margin: 0; padding: 0 3px; border-radius: 12px;
  background: transparent; color: #fff; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 3px; }
.btn:hover { background: rgba(20,184,166,.15); }
.btn.pill { padding: 0 3px 0 6px; background: rgba(17,24,39,.85); box-shadow: 0 0 0 1px rgba(255,255,255,.16); }
.btn.pill:hover { background: rgba(31,41,55,.95); }
.btn.busy { opacity: .55; cursor: progress; }
.btn svg { flex: none; display: block; }
iframe { position: fixed; z-index: 2147483647; border: 0; margin: 0; padding: 0; background: transparent; color-scheme: light;
  visibility: hidden; pointer-events: none; width: 0; height: 0; }
/* Same as the menus' own pages (inline.css). When they differ, the browser
   paints an opaque background behind the menu. */
@media (prefers-color-scheme: dark) { iframe { color-scheme: dark; } }
iframe.open { visibility: visible; pointer-events: auto; }
iframe.card { top: 0; left: 50%; transform: translateX(-50%); }
iframe.save { top: 0; right: 12px; }
`;

const host = document.createElement("keyless-autofill");
const root = host.attachShadow({ mode: "closed" });
root.innerHTML = `<style>${STYLE}</style>`;
const button = document.createElement("button");
button.className = "btn";
button.type = "button";
button.title = "Keyless";
button.innerHTML = LOGO;
button.title = "Keyless";
button.style.display = "none";
root.append(button);

const LOCK = `<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2.5"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>`;
const CHEVRON = `<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>`;

type ButtonKind = "locked" | "logins" | "plain";
let buttonKind: ButtonKind | null = null;

/** Something for the menu to offer in this field. */
function offers(state: PageState | null, field: HTMLInputElement | null): boolean {
  if (state?.state !== "ready" || !field) return false;
  const form = fieldKind(field) ? null : formKindOf(field);
  if (form === "card") return (state.cards ?? 0) > 0;
  if (form === "identity") return (state.identities ?? 0) > 0;
  return state.count > 0 || isNewPassword(field);
}

function kindFor(state: PageState | null, field: HTMLInputElement | null = current): ButtonKind {
  if (state?.state === "locked") return "locked";
  return offers(state, field) ? "logins" : "plain";
}

/** Locked: a padlock, and a click unlocks. With logins for the page: an
 * arrow, and a click opens the list. Like 1Password's button. */
function renderButton(kind: ButtonKind) {
  if (kind === buttonKind) return;
  buttonKind = kind;
  button.className = kind === "plain" ? "btn" : "btn pill";
  button.innerHTML = (kind === "locked" ? LOCK : kind === "logins" ? CHEVRON : "") + LOGO;
  button.title = kind === "locked" ? t("unlockApp") : kind === "logins" ? t("showLogins") : "Keyless";
  place();
}

function mount() {
  if (!host.isConnected && document.documentElement) document.documentElement.appendChild(host);
}

function send<T>(message: unknown): Promise<{ ok: boolean; data?: T; error?: string }> {
  // Rejects when the extension was updated or reloaded under this page.
  return chrome.runtime.sendMessage(message).catch(() => ({ ok: false, error: "error" }));
}

let registered: Promise<unknown> | null = null;
function register() {
  registered ??= send({ type: "register", token });
  return registered;
}
window.addEventListener("pageshow", (event) => {
  // Back from the back/forward cache: another page of this tab may have
  // registered since.
  if (event.persisted) {
    registered = null;
    void register();
  }
});

/** A Keyless menu: inline.html in an iframe. */
class Frame {
  readonly iframe = document.createElement("iframe");
  private loading: Promise<void> | null = null;
  open = false;
  height = 0;

  constructor(readonly mode: "menu" | "card" | "save") {
    this.iframe.className = mode;
    this.iframe.title = "Keyless";
    const width = { menu: MENU_WIDTH, card: CARD_WIDTH, save: SAVE_WIDTH }[mode];
    this.iframe.style.width = `${width + 2 * PAD}px`;
    root.append(this.iframe);
  }

  /** Shows the menu; it appears once it has rendered and reported its size.
   * `activate`: opened with the Keyless button (unlocks when locked).
   * `field`: the field it was opened for. */
  show(options: { activate?: boolean; field?: FieldInfo } = {}) {
    mount();
    this.open = true;
    const details = { activate: options.activate ?? false, field: options.field ?? null };
    if (this.loading) {
      this.post({ type: "show", ...details });
      if (this.height > 0) this.iframe.classList.add("open");
      return;
    }
    this.loading = register().then(
      () =>
        new Promise<void>((resolve) => {
          this.iframe.addEventListener(
            "load",
            () => {
              this.post({ type: "init", ...details });
              resolve();
            },
            { once: true },
          );
          this.iframe.src = chrome.runtime.getURL(`inline.html#${this.mode}`);
        }),
    );
  }

  hide() {
    this.open = false;
    this.iframe.classList.remove("open");
  }

  resize(height: number) {
    this.height = height;
    this.iframe.style.height = `${height}px`;
    if (this.open && height > 0) this.iframe.classList.add("open");
    place();
  }

  post(message: Record<string, unknown>) {
    this.iframe.contentWindow?.postMessage({ ...message, keyless: token }, EXTENSION_ORIGIN);
  }
}

let current: HTMLInputElement | null = null;
let menu: Frame | null = null;
let card: Frame | null = null;
let cardDismissed = false;
let filling = false;
let lastUserInput = 0;

/** Asked once per address, and again when the window gets the focus back
 * or Keyless was unlocked (not on every change of a busy page). */
let pageState: { url: string; value: Promise<PageState | null> } | null = null;
function getPageState(): Promise<PageState | null> {
  if (pageState?.url !== location.href) {
    const value = send<PageState>({ type: "page_state" }).then((reply) => (reply.ok ? (reply.data ?? null) : null));
    pageState = { url: location.href, value };
  }
  return pageState.value;
}

function place() {
  if (!current) return;
  const rect = current.getBoundingClientRect();
  button.style.top = `${rect.top + (rect.height - 24) / 2}px`;
  button.style.left = `${rect.right - (button.offsetWidth || 24) - 6}px`;
  if (menu?.open) {
    const width = Math.min(MENU_WIDTH, window.innerWidth - 16);
    const outer = width + 2 * PAD;
    let top = rect.bottom + 4 - PAD;
    // Above the field when it does not fit below.
    if (rect.bottom + 4 + menu.height - 2 * PAD > window.innerHeight && rect.top - menu.height > 0) {
      top = rect.top - 4 - menu.height + PAD;
    }
    const left = Math.max(0, Math.min(rect.left - PAD, window.innerWidth - outer));
    menu.iframe.style.width = `${outer}px`;
    menu.iframe.style.top = `${top}px`;
    menu.iframe.style.left = `${left}px`;
  }
}

/** Keeps the open menu under its field when the page layout moves. */
let follow: ReturnType<typeof setInterval> | undefined;

function openMenu(activate = false) {
  if (!current) return;
  menu ??= new Frame("menu");
  menu.show({ activate, field: fieldInfo(current) });
  place();
  follow ??= setInterval(place, 200);
}

/** Focus moved back to the field by Keyless itself: not a reason to open. */
let refocusing = false;

function closeMenu(refocus = false) {
  menu?.hide();
  clearInterval(follow);
  follow = undefined;
  if (refocus && current) {
    refocusing = true;
    current.focus();
    refocusing = false;
  }
}

/** Opens the menu by itself when there are logins to pick or a password to
 * suggest. When Keyless is locked the button shows a padlock instead, like
 * 1Password. */
async function autoOpen(field: HTMLInputElement) {
  const state = await getPageState();
  if (field !== current || document.activeElement !== field || menu?.open) return;
  if (offers(state, field)) openMenu();
}

/** The padlock button: Keyless asks for the password itself (the system's
 * prompt or its own small window); nothing goes through the page. */
async function unlockFromButton() {
  if (button.classList.contains("busy")) return;
  button.classList.add("busy");
  const reply = await send({ type: "unlock" });
  button.classList.remove("busy");
  if (!reply.ok) return;
  pageState = null;
  const state = await getPageState();
  renderButton(kindFor(state));
  if (current && document.activeElement === current && state?.state === "ready" && state.count > 0) openMenu();
  void scan();
}

/** Keyless locked, unlocked or disconnected (from the background). */
function onState(state: Status["state"]) {
  if (state === "ready") {
    pageState = null;
    void getPageState().then((fresh) => renderButton(kindFor(fresh)));
    void scan();
  } else {
    pageState = { url: location.href, value: Promise.resolve({ state, count: 0 }) };
    renderButton(kindFor({ state, count: 0 }));
    closeMenu();
  }
}

/** Shows the sign-in card on login pages with saved logins. */
async function scan() {
  if (cardDismissed || card?.open || !hasLoginForm()) return;
  const state = await getPageState();
  if (cardDismissed || card?.open || state?.state !== "ready" || state.count === 0) return;
  card ??= new Frame("card");
  card.show();
}

function dismissCard() {
  cardDismissed = true;
  card?.hide();
  observer.disconnect();
}

// The Keyless button in the field: unlocks right away when Keyless is locked,
// otherwise opens or closes the list (the menu decides, it knows the state).
button.addEventListener("click", (e) => {
  if (!e.isTrusted) return;
  e.preventDefault();
  if (buttonKind === "locked") void unlockFromButton();
  else if (menu?.open) menu.post({ type: "activate" });
  else openMenu(true);
});
// The field keeps the focus when the button is pressed.
button.addEventListener("mousedown", (e) => e.preventDefault());

for (const type of ["mousedown", "keydown", "touchstart"]) {
  document.addEventListener(type, (e) => e.isTrusted && (lastUserInput = Date.now()), true);
}

document.addEventListener(
  "focusin",
  (e) => {
    const target = e.target;
    if (!(target instanceof HTMLInputElement) || !visible(target) || !(fieldKind(target) || formKindOf(target))) return;
    mount();
    if (current !== target) closeMenu();
    current = target;
    button.style.display = "flex";
    place();
    void getPageState().then((state) => current === target && renderButton(kindFor(state)));
    // Not when the page focuses a field by itself on load: the card is there
    // for that.
    if (!filling && !refocusing && Date.now() - lastUserInput < 1000) void autoOpen(target);
  },
  true,
);

document.addEventListener(
  "click",
  (e) => {
    if (e.isTrusted && current && e.target === current && !menu?.open && !filling) void autoOpen(current);
  },
  true,
);

document.addEventListener(
  "mousedown",
  (e) => {
    // Clicks inside the menus happen in their own frames and never get here.
    if (e.composedPath().includes(host) || e.target === current) return;
    closeMenu();
    button.style.display = "none";
    current = null;
  },
  true,
);

document.addEventListener(
  "keydown",
  (e) => {
    if (!menu?.open || e.target !== current) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      menu.iframe.focus();
      menu.post({ type: "focus" });
    } else if (e.key === "Escape" || e.key === "Tab") {
      closeMenu();
    }
  },
  true,
);

document.addEventListener(
  "input",
  (e) => {
    // Typing by hand: the menu would only be in the way.
    if (e.isTrusted && e.target === current && !filling) closeMenu();
  },
  true,
);

window.addEventListener("scroll", place, true);
window.addEventListener("resize", place);
window.addEventListener("focus", () => {
  // Back from the popup or the computer password prompt: Keyless may have
  // been unlocked meanwhile.
  pageState = null;
  if (menu?.open) menu.post({ type: "refresh" });
  void scan();
});

// Messages from the menus. Only their frames can be the source; the page
// cannot pretend to be them.
window.addEventListener("message", (event) => {
  const frame = [menu, card, saveFrame].find((f) => f && event.source === f.iframe.contentWindow) ?? null;
  if (!frame || event.origin !== EXTENSION_ORIGIN) return;
  const data = event.data;
  switch (data?.type) {
    case "size":
      frame.resize(Math.max(0, Math.min(Number(data.height) || 0, 640)));
      break;
    case "close":
      if (frame === menu) closeMenu(Boolean(data.refocus));
      else if (frame === card) dismissCard();
      else frame.hide();
      break;
    case "hide":
      frame.hide();
      break;
    case "unlocked":
      pageState = null;
      void scan();
      break;
  }
});

// Login forms that appear later (single-page apps, dialogs).
let scanTimer: ReturnType<typeof setTimeout> | undefined;
const observer = new MutationObserver(() => {
  scanTimer ??= setTimeout(() => {
    scanTimer = undefined;
    void scan();
  }, 500);
});
observer.observe(document.documentElement, { childList: true, subtree: true });
void scan();

// ----- Saving logins -------------------------------------------------------------

let saveFrame: Frame | null = null;
/** What Keyless filled, and the password it suggested here. */
let filledKey = "";
let suggested = "";
let lastCapture = { key: "", at: 0 };

function showSavePrompt() {
  saveFrame ??= new Frame("save");
  saveFrame.show();
}

/** The user sends a login, sign-up or change-password form: report what was
 * typed, for the "Save login?" prompt. */
function capture(anchor: HTMLInputElement | null) {
  const scope: ParentNode = anchor?.form ?? document;
  const passwords = Array.from(scope.querySelectorAll<HTMLInputElement>('input[type="password"]')).filter((i) => visible(i) && i.value);
  // The new password of a sign-up or change-password form.
  const chosen = passwords.find(isNewPassword) ?? passwords[0] ?? null;
  const username = loginFields(chosen ?? anchor).username?.value.trim() ?? "";
  const password = chosen?.value ?? "";
  if (!password && !username) return;
  const key = `${username}\n${password}`;
  if (key === filledKey || (key === lastCapture.key && Date.now() - lastCapture.at < 5000)) return;
  lastCapture = { key, at: Date.now() };
  void send({ type: "capture", username, password, generated: password !== "" && password === suggested });
}

/** Fills a password Keyless suggested into the new-password fields. */
function fillNewPassword(password: string) {
  const scope: ParentNode = current?.form ?? document;
  const targets = Array.from(scope.querySelectorAll<HTMLInputElement>('input[type="password"]')).filter((i) => visible(i) && isNewPassword(i));
  if (targets.length === 0 && current?.type === "password") targets.push(current);
  filling = true;
  try {
    targets.forEach((target) => setValue(target, password));
  } finally {
    filling = false;
  }
  suggested = password;
  closeMenu();
}

document.addEventListener(
  "submit",
  (e) => {
    const form = e.target instanceof HTMLFormElement ? e.target : null;
    if (form) capture(form.querySelector<HTMLInputElement>('input[type="password"]') ?? form.querySelector<HTMLInputElement>("input"));
  },
  true,
);

// Many sign-in pages never submit a form: a click on their button, or Enter.
document.addEventListener(
  "click",
  (e) => {
    if (!e.isTrusted || !(e.target instanceof Element)) return;
    const control = e.target.closest<HTMLElement>('button, input[type="submit"], input[type="button"], [role="button"]');
    if (!control || control.closest("keyless-autofill")) return;
    const label = (control instanceof HTMLInputElement ? control.value : (control.textContent ?? control.getAttribute("aria-label") ?? "")).trim();
    if (label.length > 40 || !SEND_TEXT.test(label)) return;
    const form = control.closest("form");
    const password = (form ?? document).querySelector<HTMLInputElement>('input[type="password"]');
    if (password || form) capture(password ?? form?.querySelector<HTMLInputElement>("input") ?? null);
  },
  true,
);

document.addEventListener(
  "keydown",
  (e) => {
    if (e.isTrusted && e.key === "Enter" && e.target instanceof HTMLInputElement && fieldKind(e.target)) capture(e.target);
  },
  true,
);

// A prompt left from the previous page (signing in usually navigates).
void send<boolean>({ type: "save_pending" }).then((reply) => reply.ok && reply.data && showSavePrompt());

// Fill requested from a Keyless menu, the popup or the keyboard shortcut;
// Keyless locked or unlocked; a login to offer saving.
chrome.runtime.onMessage.addListener((message, sender) => {
  if (sender.id !== chrome.runtime.id) return;
  if (message?.type === "keyless-state" && typeof message.state === "string") {
    onState(message.state);
    return;
  }
  if (message?.type === "keyless-save") {
    showSavePrompt();
    return;
  }
  if (message?.type === "keyless-fill-form" && (message.kind === "card" || message.kind === "identity")) {
    if (message.origin === location.origin) fillForm(message.kind, message[message.kind] ?? {});
    return;
  }
  if (message?.type === "keyless-fill-new" && typeof message.password === "string") {
    if (message.origin === location.origin) fillNewPassword(message.password);
    return;
  }
  if (message?.type !== "keyless-fill") return;
  // The credentials were checked against this origin; the tab may have
  // navigated since.
  if (message.origin !== location.origin) return;
  const anchor = current?.isConnected ? current : document.activeElement instanceof HTMLInputElement ? document.activeElement : null;
  filling = true;
  let fields;
  try {
    fields = fill(anchor, message);
  } finally {
    filling = false;
  }
  // Submitting it unchanged is no reason to offer saving it.
  filledKey = `${message.username ?? ""}\n${message.password ?? ""}`;
  closeMenu();
  if (card?.open) dismissCard();
  const target = fields.password ?? fields.username ?? fields.otp;
  if (message.submit && target) void submitAfterFill(target);
});

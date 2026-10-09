// Content script: finds login fields, puts the Keyless button in them and
// hosts the Keyless menus: the list below a login field (with a suggested
// password in sign-up forms), the sign-in card at the top of the page and
// the "Save login?" prompt.
//
// In frames inside the page it also tells the background whether the frame
// has a login form (so the popup and the shortcuts can fill it) or, when
// asked, card and address fields (filled with the page's), and shows the
// button and the menu
// for the frame's own address: in frames of the page's site, and in other
// sites' frames only where the browser can tell the menu is really seen
// (IntersectionObserver v2, in Chromium), since the page around such a frame
// could hide or cover it unnoticed. The sign-in card and the "Save login?"
// prompt are the page's only. Sandboxed frames, with no origin of their own,
// are left alone.
//
// It also shows the prompt for a site's passkey request (save one, or sign
// in with one), at the top of the page with the page dimmed.
//
// The menus are extension pages (inline.html) in
// iframes inside a closed shadow root: the page cannot read the logins they
// list, and only they (or the popup) can ask Keyless to fill or save. This
// script learns nothing about the logins except how many match the page,
// gets credentials only to type them into the page once the user picked one,
// and reports what the user typed when a login form is submitted.
//
// Against clickjacking (a page hiding or covering the menus to trick a click
// on them), the menus live in the browser's top layer under a random tag, the
// page's changes to them are undone, this script tells them when it sees
// them altered, and they ignore clicks while they cannot be seen (see
// inline.ts). Only fields the user can see are filled, so hidden "honeypot"
// fields get nothing.

import {
  composedParent,
  focusedField,
  deepQuery,
  eventTarget,
  fieldInfo,
  fieldKind,
  formKindOf,
  formKinds,
  formParts,
  hasCodeForm,
  hasLoginForm,
  isNewPassword,
  loginFields,
  setOwnElement,
  setUserField,
  setSplit,
  setValue,
  shadowOf,
  submitButton,
  viewable,
  visible,
  wantsPasskey,
  type FormControl,
} from "./fields";
import type { Credentials, FieldInfo, FormKind, PageState, Status } from "./types";

const t = (key: string) => chrome.i18n.getMessage(key) || key;

const EXTENSION_ORIGIN = new URL(chrome.runtime.getURL("")).origin;
/** Transparent margin around the menus, room for their shadow. */
const PAD = 10;
const MENU_WIDTH = 320;
const CARD_WIDTH = 400;
const SAVE_WIDTH = 380;
const PASSKEY_WIDTH = 380;

/** The page itself, not a frame inside it. */
const TOP = window === window.top;
/** A sandboxed frame: never filled. */
const SANDBOXED = location.origin === "null";

/** Proves to the background that a menu was opened by this script. Not
 * crypto.randomUUID: that needs a secure context, and http pages are not. */
const token = Array.from(crypto.getRandomValues(new Uint8Array(24)), (b) => b.toString(16).padStart(2, "0")).join("");

const SEND_TEXT =
  /\b(log ?in|sign ?in|sign ?up|entrar|acessar|iniciar sesi[oó]n|ingresar|continu[ea]r?|next|avan[cç]ar|pr[oó]ximo|siguiente|register|registr\w*|cadastr\w*|criar|create|crear|join|save|salvar|guardar|change|alterar|cambiar|update|atualizar|actualizar|submit|enviar)\b/i;
/** Fills a login; `codeOnly`: only its one-time code. The code goes into
 * the field the user is in when it asks for one, otherwise the form's (also
 * one asked next to the password). Returns the fields filled. */
function fill(anchor: HTMLInputElement | null, credentials: Credentials, codeOnly = false) {
  const fields = loginFields(anchor);
  if (anchor && fieldKind(anchor) === "otp" && viewable(anchor)) fields.otp = anchor;
  if (!codeOnly) {
    if (fields.username && credentials.username) setValue(fields.username, credentials.username);
    if (fields.password && credentials.password) setValue(fields.password, credentials.password);
  }
  const otp = fields.otp && credentials.totp ? fields.otp : null;
  if (otp && credentials.totp) setSplit(otp, credentials.totp);
  return codeOnly ? { username: null, password: null, otp } : { ...fields, otp };
}

// ----- Payment and address forms --------------------------------------------------

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
    setSplit(control, values[0]);
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
:host { all: initial; position: fixed; inset: 0 auto auto 0; width: 0; height: 0; margin: 0; padding: 0; border: 0;
  overflow: visible; background: transparent; }
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
iframe.card { top: 0; left: max(0px, calc(50% - ${(CARD_WIDTH + 2 * PAD) / 2}px)); }
iframe.detached { top: 0; left: max(0px, calc(50% - ${(MENU_WIDTH + 2 * PAD) / 2}px)); }
iframe.save, iframe.passkey { top: 0; right: 12px; }
/* Dims the page behind the passkey prompt; clicks on the page wait. */
.scrim { position: fixed; z-index: 2147483645; inset: 0; width: 100vw; height: 100vh; background: rgba(0,0,0,.42); display: none; }
`;

/** A random tag: page styles cannot target it by name. */
const host = document.createElement(`keyless-${token.slice(0, 10)}`);
/** The top layer puts the menus above everything the page draws. */
const topLayer = typeof host.showPopover === "function";
/** What the page had in the top layer when the menus were last put above
 * it: anything else the page shows may be above them. */
let below = new Set<Element>();
if (topLayer) host.popover = "manual";
setOwnElement(host);
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
const scrim = document.createElement("div");
scrim.className = "scrim";
root.append(scrim);

const LOCK = `<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2.5"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>`;
const CHEVRON = `<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>`;

type ButtonKind = "locked" | "logins" | "plain";
let buttonKind: ButtonKind | null = null;

/** Something for the menu to offer in this field. */
function offers(state: PageState | null, field: HTMLInputElement | null): boolean {
  if (state?.state !== "ready" || !field) return false;
  const kind = fieldKind(field);
  const form = kind ? null : formKindOf(field);
  if (form === "card") return (state.cards ?? 0) > 0;
  if (form === "identity") return (state.identities ?? 0) > 0;
  if (kind === "otp") return (state.codes ?? 0) > 0;
  if (wantsPasskey(field) && (state.passkeys ?? 0) > 0) return true;
  return state.count > 0 || isNewPassword(field);
}

/** Visibility the browser checks (IntersectionObserver v2, Chromium). */
const tracksVisibility = typeof IntersectionObserverEntry !== "undefined" && "isVisible" in IntersectionObserverEntry.prototype;

/** The button and the menu may show in this frame: the page itself, a
 * frame of its site, or another site's frame where the menu can tell it is
 * really seen. */
function inlineAllowed(state: PageState | null): boolean {
  if (TOP) return true;
  if (SANDBOXED || !state?.frame) return false;
  return state.frame === "same-site" || (state.frame === "cross-site" && tracksVisibility);
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

/** Where the menus go: in the page's open modal dialog, if any, since a
 * modal dialog makes everything outside it inert (unclickable). */
function container(): Element | null {
  let dialogs: HTMLDialogElement[] = [];
  try {
    dialogs = Array.from(document.querySelectorAll<HTMLDialogElement>("dialog:modal"));
  } catch {
    // An older browser without :modal.
  }
  return dialogs[dialogs.length - 1] ?? document.documentElement;
}

type MovableParent = Element & { moveBefore?: (node: Node, child: Node | null) => void };

function mount() {
  const parent = container() as MovableParent | null;
  if (!parent) return;
  if (host.parentNode !== parent) {
    // Moved without reloading the menus where the browser can; otherwise
    // they reload and are set up again (see Frame).
    try {
      if (host.isConnected && parent.moveBefore) parent.moveBefore(host, null);
      else parent.appendChild(host);
    } catch {
      parent.appendChild(host);
    }
    guard.observe(host, { attributes: true });
    removal.disconnect();
    removal.observe(parent, { childList: true });
  }
  if (topLayer && host.isConnected && !host.matches(":popover-open")) raise();
}

/** Shows the menus above anything else in the top layer, including dialogs
 * and popovers the page opened after them. */
function raise() {
  if (!topLayer || !host.isConnected) return;
  try {
    if (host.matches(":popover-open")) host.hidePopover();
    host.showPopover();
  } catch {
    // Not connected, or the page made it impossible: the menus refuse clicks.
  }
  below = pageTopLayer();
  // Chrome stops updating the menus' view of their visibility after this:
  // they start watching it again.
  for (const frame of openFrames()) if (frame?.open) frame.post({ type: "recheck" });
}

/** What the page has in the top layer (dialogs, popovers, full screen),
 * also inside its shadow roots, which are watched from then on. */
function pageTopLayer(): Set<Element> {
  const found = new Set<Element>();
  if (!topLayer) return found;
  const visit = (root: Document | ShadowRoot) => {
    try {
      for (const el of root.querySelectorAll(":popover-open, :modal, :fullscreen")) if (el !== host) found.add(el);
    } catch {
      // A selector the browser does not know.
    }
    for (const el of root.querySelectorAll("*")) {
      const shadow = shadowOf(el);
      if (!shadow) continue;
      watchTopLayer(shadow);
      visit(shadow);
    }
  };
  visit(document);
  return found;
}

/** The page has something of its own in the top layer (a dialog, a popover),
 * which may be above the menus. */
function outranked(): boolean {
  return pageTopLayer().size > 0;
}

/** The page may have put something over the menus, even something clicks go
 * through (which only Chrome notices on its own): the menus refuse clicks,
 * are put back on top, and wait to have been seen a moment again. */
function covered() {
  if (!openFrames().some((f) => f?.open)) return;
  for (const frame of openFrames()) {
    if (!frame?.open) continue;
    lastSafe.set(frame, false);
    frame.post({ type: "safety", safe: false });
  }
  // Once the page's element is shown: this runs while it is being opened.
  setTimeout(raise, 0);
}

const watchedRoots = new WeakSet<Document | ShadowRoot>();
function watchTopLayer(root: Document | ShadowRoot) {
  if (watchedRoots.has(root)) return;
  watchedRoots.add(root);
  root.addEventListener(
    "beforetoggle",
    (event) => {
      if (event.target !== host && (event as ToggleEvent).newState === "open") covered();
    },
    true,
  );
}
if (topLayer) {
  watchTopLayer(document);
  document.addEventListener("fullscreenchange", covered, true);
}

/** Undoes what the page does to the menus' element. */
const guard = new MutationObserver(() => {
  for (const name of host.getAttributeNames()) if (name !== "popover") host.removeAttribute(name);
  if (topLayer && host.getAttribute("popover") !== "manual") host.popover = "manual";
  raise();
});
const removal = new MutationObserver(() => {
  // Removed by the page: put back while something is shown.
  if (!host.isConnected && (button.style.display !== "none" || openFrames().some((f) => f?.open))) mount();
});
host.addEventListener("toggle", (event) => {
  if ((event as ToggleEvent).newState === "closed" && openFrames().some((f) => f?.open)) raise();
});

/** What the menus' element must look like (computed): anything else may hide,
 * shrink, clip or blend the menus. A property the browser does not know
 * reads as "" and is skipped. */
const EXPECTED_STYLE: Record<string, string> = {
  position: "fixed",
  display: "block",
  visibility: "visible",
  opacity: "1",
  overflow: "visible",
  filter: "none",
  "backdrop-filter": "none",
  transform: "none",
  translate: "none",
  rotate: "none",
  scale: "none",
  zoom: "1",
  perspective: "none",
  "clip-path": "none",
  "mask-image": "none",
  "mix-blend-mode": "normal",
  contain: "none",
  "will-change": "auto",
  "content-visibility": "visible",
};

/** Nothing the page did makes the menus invisible or see-through. The menus
 * also check this themselves where the browser can (see inline.ts). */
function untouched(): boolean {
  if (!host.isConnected || (topLayer && !host.matches(":popover-open"))) return false;
  const style = getComputedStyle(host);
  for (const [name, expected] of Object.entries(EXPECTED_STYLE)) {
    const value = style.getPropertyValue(name);
    if (value && value !== expected) return false;
  }
  if (!topLayer) {
    // Outside the top layer the page's own opacity applies to the menus.
    for (const el of [document.documentElement, document.body]) if (el && Number(getComputedStyle(el).opacity) < 0.99) return false;
  }
  return true;
}

/** Nothing the page put on screen later sits over the menu. */
function uncovered(frame: Frame): boolean {
  const rect = frame.iframe.getBoundingClientRect();
  const points = [
    [rect.left + rect.width / 2, rect.top + rect.height / 2],
    [rect.left + PAD + 4, rect.top + PAD + 4],
    [rect.right - PAD - 4, rect.bottom - PAD - 4],
  ];
  return points.every(([x, y]) => x < 0 || y < 0 || x >= innerWidth || y >= innerHeight || document.elementFromPoint(x, y) === host);
}

const lastSafe = new Map<Frame, boolean>();
/** Tells the open menus whether they can be trusted to be seen. */
function reportSafety() {
  if (topLayer && openFrames().some((f) => f?.open)) {
    const now = pageTopLayer();
    if ([...now].some((el) => !below.has(el))) return covered();
    // Closed since: shown again, they are new.
    below = now;
  }
  const style = untouched();
  for (const frame of openFrames()) {
    if (!frame?.open || frame.height === 0) continue;
    const safe = style && uncovered(frame);
    if (lastSafe.get(frame) === safe) continue;
    lastSafe.set(frame, safe);
    frame.post({ type: "safety", safe });
  }
}
setInterval(() => openFrames().some((f) => f?.open) && reportSafety(), 250);

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
  if (!TOP) return;
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
  /** The token the menu presents: this script's, or a small frame's (see
   * `detached`). */
  token = token;
  private loading: Promise<void> | null = null;
  /** What the menu was last shown for, to set it up again if it reloads. */
  private details: { activate: boolean; field: FieldInfo | null } = { activate: false, field: null };
  open = false;
  height = 0;

  constructor(
    readonly mode: "menu" | "card" | "save" | "passkey",
    className: string = mode,
  ) {
    this.iframe.className = className;
    this.iframe.title = "Keyless";
    const width = { menu: MENU_WIDTH, card: CARD_WIDTH, save: SAVE_WIDTH, passkey: PASSKEY_WIDTH }[mode];
    this.iframe.style.width = `${width + 2 * PAD}px`;
    root.append(this.iframe);
  }

  /** Shows the menu; it appears once it has rendered and reported its size.
   * `activate`: opened with the Keyless button (unlocks when locked).
   * `field`: the field it was opened for. */
  show(options: { activate?: boolean; field?: FieldInfo } = {}) {
    mount();
    // Above whatever the page put in the top layer since.
    if (!this.open) {
      if (outranked()) raise();
      else below = new Set();
    }
    this.open = true;
    const details = { activate: options.activate ?? false, field: options.field ?? null };
    this.details = { activate: false, field: details.field };
    // Told again once it has its size (see resize).
    lastSafe.delete(this);
    if (this.loading) {
      this.post({ type: "show", ...details });
      if (this.height > 0) this.iframe.classList.add("open");
      return;
    }
    this.loading = register().then(
      () =>
        new Promise<void>((resolve) => {
          let first = true;
          // Also when it reloads after being moved (see mount).
          this.iframe.addEventListener("load", () => {
            this.post({ type: "init", ...(first ? details : this.details) });
            first = false;
            resolve();
          });
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
    lastSafe.delete(this);
    reportSafety();
  }

  post(message: Record<string, unknown>) {
    this.iframe.contentWindow?.postMessage({ ...message, keyless: this.token }, EXTENSION_ORIGIN);
  }
}

let current: HTMLInputElement | null = null;
let menu: Frame | null = null;
/** The page's menu for a field in a frame too small to show one (a payment
 * service's card field, a small sign-in box): at the top of the page, acting
 * for that frame with its token. */
let detached: Frame | null = null;
/** A site's passkey request (see background.ts). */
let passkeyFrame: Frame | null = null;

function openFrames(): (Frame | null)[] {
  return [menu, card, saveFrame, detached, passkeyFrame];
}

function hidePasskey() {
  passkeyFrame?.hide();
  scrim.style.display = "none";
  // The sign-in card comes back if the page still wants it.
  void scan();
}
let card: Frame | null = null;
let cardDismissed = false;
let filling = false;

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
    const below = rect.bottom + 4 + menu.height - 2 * PAD <= window.innerHeight;
    const above = rect.top - menu.height > 0;
    if (!TOP && menu.height > 0 && !below && !above) {
      // Cut off by the frame's edges, it could not be trusted to be seen
      // (and Chromium refuses clicks on it): the page shows it instead.
      menuElsewhere(current);
      return;
    }
    const width = Math.min(MENU_WIDTH, window.innerWidth - 16);
    const outer = width + 2 * PAD;
    let top = rect.bottom + 4 - PAD;
    // Above the field when it does not fit below.
    if (rect.bottom + 4 + menu.height - 2 * PAD > window.innerHeight && rect.top - menu.height > 0) {
      top = rect.top - 4 - menu.height + PAD;
    }
    const left = Math.max(0, Math.min(rect.left - PAD, window.innerWidth - outer));
    const moved = Math.abs(parseFloat(menu.iframe.style.top) - top) > 2 || Math.abs(parseFloat(menu.iframe.style.left) - left) > 2;
    menu.iframe.style.width = `${outer}px`;
    menu.iframe.style.top = `${top}px`;
    menu.iframe.style.left = `${left}px`;
    // Moved under the pointer: no click is accepted right away.
    if (moved) menu.post({ type: "moved" });
  }
}

/** Keeps the open menu under its field when the page layout moves. */
let follow: ReturnType<typeof setInterval> | undefined;

/** A frame too small for the menu under its field. */
function tooSmall(): boolean {
  return !TOP && (innerHeight < 220 || innerWidth < 260);
}

/** The page shows the menu for this frame (see `detached`). */
function menuElsewhere(field: HTMLInputElement, activate = false) {
  closeMenu();
  const info = fieldInfo(field);
  void register().then(() => send({ type: "menu_elsewhere", field: info, activate }));
}

function openMenu(activate = false) {
  if (!current) return;
  if (tooSmall()) return menuElsewhere(current, activate);
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
 * suggest, in a field the user clicked or tabbed to. Card and address menus
 * open only with the Keyless button. When Keyless is locked the button
 * shows a padlock instead, like 1Password. */
async function autoOpen(field: HTMLInputElement) {
  const state = await getPageState();
  if (field !== current || focusedField() !== field || menu?.open || !userWentTo(field)) return;
  if (!fieldKind(field) || !offers(state, field) || state?.autoOpen === false || state?.hidden || !inlineAllowed(state)) return;
  openMenu();
}

let lastPointer: { target: EventTarget | null; at: number } = { target: null, at: 0 };
let lastTab = 0;
document.addEventListener("pointerdown", (e) => e.isTrusted && (lastPointer = { target: eventTarget(e), at: Date.now() }), true);
document.addEventListener("keydown", (e) => e.isTrusted && e.key === "Tab" && (lastTab = Date.now()), true);

/** The user clicked the field or reached it with Tab just now. A click in
 * a closed shadow root shows only its host (and the focus has not moved
 * yet), so a click on a host of the field counts. */
function userWentTo(field: HTMLInputElement): boolean {
  let clicked = false;
  for (let node: Element | null = field; node && !clicked; node = composedParent(node)) clicked = lastPointer.target === node;
  return (clicked && Date.now() - lastPointer.at < 1500) || Date.now() - lastTab < 1000;
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
  if (current && focusedField() === current && state?.state === "ready" && state.count > 0) openMenu();
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

let reportedLogin = "";
/** Tells the background whether this frame has a login form (or asks for a
 * one-time code). */
function reportForms() {
  if (SANDBOXED) return;
  const code = !hasLoginForm() && hasCodeForm();
  const login = code ? "code" : hasLoginForm() ? "login" : "";
  if (login !== reportedLogin) {
    reportedLogin = login;
    void send({ type: "frame_login", login: login !== "", code });
  }
}

/** Shows the sign-in card on login pages with saved logins, and on pages
 * asking for a one-time code that a login for the page has. */
async function scan() {
  reportForms();
  // Not over the passkey prompt; it comes back after.
  if (!TOP || passkeyFrame?.open) return;
  const login = hasLoginForm();
  const code = !login && hasCodeForm();
  // Signed in without leaving the page: the card has nothing left to fill.
  if (card?.open && !login && !code) card.hide();
  if (cardDismissed || card?.open || (!login && !code)) return;
  const state = await getPageState();
  if (cardDismissed || card?.open || state?.state !== "ready" || state.card === false) return;
  if (code ? (state.codes ?? 0) === 0 : state.count === 0 && (state.passkeys ?? 0) === 0) return;
  card ??= new Frame("card");
  card.show({ field: { newPassword: false, maxLength: null, code } });
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

document.addEventListener(
  "focusin",
  (e) => {
    const target = eventTarget(e);
    if (SANDBOXED || !(target instanceof HTMLInputElement) || !visible(target) || !(fieldKind(target) || formKindOf(target))) return;
    watchRoot(target);
    if (current !== target) closeMenu();
    current = target;
    setUserField(target);
    void getPageState().then((state) => {
      // Shown once Keyless knows the site, unless the user hid it there, and
      // in frames only where it may be (see inlineAllowed).
      if (current !== target || state?.hidden || !inlineAllowed(state)) return;
      mount();
      button.style.display = "flex";
      renderButton(kindFor(state));
      place();
    });
    // Not when the page focuses a field by itself: the card is there for that.
    if (!filling && !refocusing) void autoOpen(target);
  },
  true,
);

document.addEventListener(
  "click",
  (e) => {
    if (e.isTrusted && current && eventTarget(e) === current && !menu?.open && !filling) void autoOpen(current);
  },
  true,
);

document.addEventListener(
  "mousedown",
  (e) => {
    // Clicks inside the menus happen in their own frames and never get here.
    if (e.composedPath().includes(host) || eventTarget(e) === current) return;
    closeMenu();
    detached?.hide();
    button.style.display = "none";
    current = null;
    setUserField(null);
  },
  true,
);

document.addEventListener(
  "keydown",
  (e) => {
    if (!menu?.open || eventTarget(e) !== current) return;
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
    if (e.isTrusted && eventTarget(e) === current && !filling) closeMenu();
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
  const frame = openFrames().find((f) => f && event.source === f.iframe.contentWindow) ?? null;
  if (!frame || event.origin !== EXTENSION_ORIGIN) return;
  const data = event.data;
  switch (data?.type) {
    case "size":
      frame.resize(Math.max(0, Math.min(Number(data.height) || 0, 640)));
      break;
    case "close":
      if (frame === menu) closeMenu(Boolean(data.refocus));
      else if (frame === card) dismissCard();
      else if (frame === passkeyFrame) hidePasskey();
      else frame.hide();
      break;
    case "hide":
      if (frame === passkeyFrame) hidePasskey();
      else frame.hide();
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

function isLoginPassword(input: HTMLInputElement): boolean {
  return fieldKind(input) === "password" && input.value !== "" && viewable(input);
}

/** The user sends a login, sign-up or change-password form: report what was
 * typed, for the "Save login?" prompt, which waits until the login worked. */
function capture(anchor: HTMLInputElement | null) {
  if (SANDBOXED) return;
  const scope: ParentNode = anchor?.form ?? document;
  // Payment forms are not logins.
  if (formParts(anchor, "card").size >= 2) return;
  const passwords = deepQuery<HTMLInputElement>(scope, 'input[type="password"]').filter(isLoginPassword);
  // Sign-up and change-password forms: the new password, and the current one.
  let chosen = passwords.find(isNewPassword) ?? null;
  let currentPassword = passwords.find((p) => !isNewPassword(p) && p.value !== chosen?.value) ?? null;
  if (!chosen && passwords.length >= 2) {
    // Forms that do not say which is which: the same password twice is a
    // new one and its confirmation; before them, the current one.
    const last = passwords[passwords.length - 1];
    const repeated = passwords.filter((p) => p.value === last.value);
    if (repeated.length >= 2) {
      chosen = last;
      currentPassword = passwords.find((p) => p.value !== last.value) ?? null;
    }
  }
  const field = chosen ?? currentPassword;
  const username = loginFields(field ?? anchor).username?.value.trim() ?? "";
  const password = field?.value ?? "";
  if (!password && !username) return;
  const key = `${username}\n${password}`;
  if (key === filledKey || (key === lastCapture.key && Date.now() - lastCapture.at < 5000)) return;
  lastCapture = { key, at: Date.now() };
  void send({
    type: "capture",
    username,
    password,
    current: chosen && currentPassword ? currentPassword.value : "",
    generated: password !== "" && password === suggested,
  });
  if (field) watchOutcome(field);
}

/** Signing in worked when the form goes away for good (pages that do not
 * navigate; for those that do, the next page tells). Not when it only hides
 * while the page checks the password, then comes back with an error. */
function watchOutcome(field: HTMLInputElement) {
  const started = Date.now();
  let goneSince: number | null = null;
  const timer = setInterval(() => {
    const gone = !field.isConnected || !visible(field);
    if (!gone) goneSince = null;
    else goneSince ??= Date.now();
    if (goneSince !== null && Date.now() - goneSince >= 1500 && !hasLoginForm()) {
      clearInterval(timer);
      void send({ type: "capture_done" });
    } else if (Date.now() - started > 30_000) {
      clearInterval(timer);
    }
  }, 300);
}

/** Fills a password Keyless suggested into the new-password fields. */
function fillNewPassword(password: string) {
  const scope: ParentNode = current?.form ?? document;
  const targets = deepQuery<HTMLInputElement>(scope, 'input[type="password"]').filter((i) => viewable(i) && isNewPassword(i));
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

function onSubmit(e: Event) {
  // A page script submitting a form is not the user signing in.
  if (!e.isTrusted) return;
  const form = e.target instanceof HTMLFormElement ? e.target : null;
  if (form) capture(deepQuery<HTMLInputElement>(form, 'input[type="password"]')[0] ?? deepQuery<HTMLInputElement>(form, "input")[0] ?? null);
}
document.addEventListener("submit", onSubmit, true);

/** Forms inside shadow roots: their submit events stay there. */
const watchedFieldRoots = new WeakSet<ShadowRoot>();
function watchRoot(field: Element) {
  const root = field.getRootNode();
  if (!(root instanceof ShadowRoot) || watchedFieldRoots.has(root)) return;
  watchedFieldRoots.add(root);
  root.addEventListener("submit", onSubmit, true);
}

// Many sign-in pages never submit a form: a click on their button, or Enter.
document.addEventListener(
  "click",
  (e) => {
    const origin = e.composedPath()[0];
    if (!e.isTrusted || !(origin instanceof Element)) return;
    const control = origin.closest<HTMLElement>('button, input[type="submit"], input[type="button"], [role="button"]');
    if (!control || e.composedPath().includes(host)) return;
    const label = (control instanceof HTMLInputElement ? control.value : (control.textContent ?? control.getAttribute("aria-label") ?? "")).trim();
    if (label.length > 40 || !SEND_TEXT.test(label)) return;
    const form = control.closest("form");
    const password = deepQuery<HTMLInputElement>(form ?? document, 'input[type="password"]')[0];
    if (password || form) capture(password ?? (form ? (deepQuery<HTMLInputElement>(form, "input")[0] ?? null) : null));
  },
  true,
);

document.addEventListener(
  "keydown",
  (e) => {
    const target = eventTarget(e);
    if (e.isTrusted && e.key === "Enter" && target instanceof HTMLInputElement && fieldKind(target)) capture(target);
  },
  true,
);

// A prompt left from the previous page (signing in usually navigates). When
// the new page shows the login form again, signing in failed. Waits a bit
// for pages that draw their forms with scripts.
setTimeout(() => {
  if (!TOP) return;
  void send<boolean>({ type: "save_pending", loginForm: hasLoginForm() }).then((reply) => reply.ok && reply.data && showSavePrompt());
}, 700);

// Fill requested from a Keyless menu, the popup or the keyboard shortcuts;
// Keyless locked or unlocked; passkeys the page now offers in its fields; a
// login to offer saving (the page only).
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || SANDBOXED) return;
  if (message?.type === "keyless-state" && typeof message.state === "string") {
    onState(message.state);
    return;
  }
  if (message?.type === "keyless-forms" && typeof message.nonce === "string") {
    // Which frames have card or address fields, for a card being filled.
    const forms = formKinds();
    if (forms.card || forms.identity) void send({ type: "frame_form", nonce: message.nonce, ...forms });
    return;
  }
  if (message?.type === "keyless-passkeys" && typeof message.count === "number") {
    void getPageState().then((state) => {
      if (state) state.passkeys = message.count;
      renderButton(kindFor(state));
      // Signed in with one, or the page stopped offering them.
      if (menu?.open) {
        if (message.count === 0 && current && wantsPasskey(current) && !offers(state, current)) closeMenu();
        else menu.post({ type: "refresh" });
      }
      // The card at the top offers the passkey first.
      if (card?.open) card.post({ type: "refresh" });
      if (detached?.open) detached.post({ type: "refresh" });
      void scan();
    });
    return;
  }
  if (message?.type === "keyless-save") {
    if (TOP) showSavePrompt();
    return;
  }
  if (message?.type === "keyless-passkey-prompt") {
    // The page's own prompt; the background opens its window instead when
    // this cannot show.
    if (!TOP || !document.documentElement) return;
    passkeyFrame ??= new Frame("passkey");
    // Nothing else of Keyless's on top of the dimmed page.
    closeMenu();
    card?.hide();
    scrim.style.display = "block";
    passkeyFrame.show();
    sendResponse(true);
    return;
  }
  if (message?.type === "keyless-passkey-close") {
    if (TOP) hidePasskey();
    return;
  }
  if (message?.type === "keyless-menu-for" && typeof message.token === "string" && message.token.length >= 32) {
    // A small frame's menu, shown here for it.
    if (!TOP) return;
    if (detached && detached.token !== message.token) {
      detached.iframe.remove();
      detached = null;
    }
    detached ??= new Frame("menu", "detached");
    detached.token = message.token;
    detached.show({ activate: message.activate === true, field: message.field });
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
  const focused = focusedField();
  const anchor = current?.isConnected ? current : focused instanceof HTMLInputElement ? focused : null;
  filling = true;
  let fields;
  try {
    fields = fill(anchor, message, message.codeOnly === true);
  } finally {
    filling = false;
  }
  // Submitting it unchanged is no reason to offer saving it.
  if (message.codeOnly !== true) filledKey = `${message.username ?? ""}\n${message.password ?? ""}`;
  closeMenu();
  if (card?.open) dismissCard();
  // The background copies the code when it was not filled here.
  sendResponse({ otp: fields.otp !== null });
  const target = fields.password ?? fields.username ?? fields.otp;
  if (message.submit && target) void submitAfterFill(target);
});

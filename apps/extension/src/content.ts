// Content script: finds login fields, puts the Keyless button in them and
// hosts the Keyless menus: the list below a login field and the sign-in card
// at the top of the page.
//
// Runs only in the top frame. The menus are extension pages (inline.html) in
// iframes inside a closed shadow root: the page cannot read the logins they
// list, and only they (or the popup) can ask Keyless to fill. This script
// learns nothing about the logins except how many match the page, and gets
// credentials only to type them into the page once the user picked one.

import type { Credentials, PageState, Status } from "./types";

const t = (key: string) => chrome.i18n.getMessage(key) || key;

const EXTENSION_ORIGIN = new URL(chrome.runtime.getURL("")).origin;
/** Transparent margin around the menus, room for their shadow. */
const PAD = 10;
const MENU_WIDTH = 320;
const CARD_WIDTH = 400;

/** Proves to the background that a menu was opened by this script. Not
 * crypto.randomUUID: that needs a secure context, and http pages are not. */
const token = Array.from(crypto.getRandomValues(new Uint8Array(24)), (b) => b.toString(16).padStart(2, "0")).join("");

const USERNAME_HINT = /user|email|e-mail|login|account|identifier|usuario|correo|cpf/i;
const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|token|c[oó]digo|code/i;
const SUBMIT_TEXT = /^(log ?in|sign ?in|entrar|acessar|iniciar sesi[oó]n|ingresar|continue|continuar|next|avan[cç]ar|pr[oó]ximo|siguiente)$/i;

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

/** True when the page shows a form to sign in (not just any email field). */
function hasLoginForm(): boolean {
  return Array.from(document.querySelectorAll<HTMLInputElement>("input")).some((input) => {
    const kind = fieldKind(input);
    const explicit = kind === "password" || (kind === "username" && (input.autocomplete || "").toLowerCase().includes("username"));
    return explicit && visible(input);
  });
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

function kindFor(state: PageState | null): ButtonKind {
  if (state?.state === "locked") return "locked";
  return state?.state === "ready" && state.count > 0 ? "logins" : "plain";
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

  constructor(readonly mode: "menu" | "card") {
    this.iframe.className = mode;
    this.iframe.title = "Keyless";
    this.iframe.style.width = `${(mode === "card" ? CARD_WIDTH : MENU_WIDTH) + 2 * PAD}px`;
    root.append(this.iframe);
  }

  /** Shows the menu; it appears once it has rendered and reported its size.
   * `activate`: opened with the Keyless button (unlocks when locked). */
  show(activate = false) {
    mount();
    this.open = true;
    if (this.loading) {
      this.post({ type: "show", activate });
      if (this.height > 0) this.iframe.classList.add("open");
      return;
    }
    this.loading = register().then(
      () =>
        new Promise<void>((resolve) => {
          this.iframe.addEventListener(
            "load",
            () => {
              this.post({ type: "init", activate });
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
  menu.show(activate);
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

/** Opens the menu by itself when there are logins to pick. When Keyless is
 * locked the button shows a padlock instead, like 1Password. */
async function autoOpen(field: HTMLInputElement) {
  const state = await getPageState();
  if (field !== current || document.activeElement !== field || menu?.open) return;
  if (state?.state === "ready" && state.count > 0) openMenu();
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
    if (!(target instanceof HTMLInputElement) || !fieldKind(target) || !visible(target)) return;
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
  const frame = event.source === menu?.iframe.contentWindow ? menu : event.source === card?.iframe.contentWindow ? card : null;
  if (!frame || event.origin !== EXTENSION_ORIGIN) return;
  const data = event.data;
  switch (data?.type) {
    case "size":
      frame.resize(Math.max(0, Math.min(Number(data.height) || 0, 640)));
      break;
    case "close":
      if (frame === menu) closeMenu(Boolean(data.refocus));
      else dismissCard();
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

// Fill requested from a Keyless menu, the popup or the keyboard shortcut; or
// Keyless locked or unlocked.
chrome.runtime.onMessage.addListener((message, sender) => {
  if (sender.id !== chrome.runtime.id) return;
  if (message?.type === "keyless-state" && typeof message.state === "string") {
    onState(message.state);
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
  closeMenu();
  if (card?.open) dismissCard();
  const target = fields.password ?? fields.username ?? fields.otp;
  if (message.submit && target) void submitAfterFill(target);
});

// The Keyless menus shown inside web pages, in an iframe the content script
// creates: the list below a login field (#menu), the sign-in card at the
// top of the page (#card), the "Save login?" prompt (#save), the prompt
// for a site's passkey request (#passkey) and the warning about a breach of
// the website (#alert).
//
// This is an extension page, isolated from the web page: the page can
// neither read it nor script it. It only works with the token its content
// script registered with the background, which it receives by postMessage
// (addressed to the extension origin, so the page never sees it).
//
// The page can still draw over it or make it see-through, to get a click on
// it the user did not mean (clickjacking). So clicks only count when the
// menu has been on screen, unchanged and fully visible, for a moment: the
// browser says so where it can (IntersectionObserver v2, in Chromium), and
// the content script reports what the page did to the menu.

import { avatar } from "./avatar";
import { markupNodes } from "./markup";
import { providerName } from "./providers";
import { hasWords, searchWords } from "./search";
import type { AlertView, FieldInfo, FormItems, InlineState, Login, PasskeyEntry, SaveState } from "./types";

const t = (key: string, ...subs: string[]) => chrome.i18n.getMessage(key, subs) || key;
const MODES = ["card", "save", "passkey", "alert", "ssh"] as const;
const mode: "menu" | (typeof MODES)[number] = MODES.find((m) => location.hash === `#${m}`) ?? "menu";
document.documentElement.dataset.mode = mode;
const app = document.getElementById("app")!;
/** Same as in the content script. */
const PAD = 10;
const MAX_SEARCH_RESULTS = 8;

let token: string | null = null;
let state: InlineState | null = null;
/** Card: "Other logins" is open. */
let expanded = false;

type Reply<T> = { ok: boolean; data?: T; error?: string };
const send = <T>(message: Record<string, unknown>): Promise<Reply<T>> =>
  chrome.runtime.sendMessage({ ...message, token }).catch(() => ({ ok: false, error: "error" }));

function toParent(type: string, extra: Record<string, unknown> = {}) {
  window.parent.postMessage({ type, ...extra }, "*");
}

/** Tells the content script how tall the iframe must be. */
function report() {
  toParent("size", { height: Math.ceil(app.getBoundingClientRect().height) + 2 * PAD });
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
  const node = Object.assign(document.createElement(tag), props) as HTMLElementTagNameMap[K];
  node.append(...children);
  return node;
}

// ----- Click guard --------------------------------------------------------------

/** How long the menu must have been visible, unmoved, before a click counts. */
const SETTLE_MS = 500;
/** Since when the browser has seen the menu fully visible (null: not now). */
let seenSince: number | null = null;
/** The content script found nothing hiding or covering the menu. */
let pageSafe = false;
/** Shown or moved: clicks wait until then. */
let quietUntil = 0;

const tracksVisibility = typeof IntersectionObserverEntry !== "undefined" && "isVisible" in IntersectionObserverEntry.prototype;
let visibility: IntersectionObserver | null = null;

/** Asks the browser to tell whenever the menu stops or starts being fully
 * visible. Started again when the content script asks: after the menus
 * were put back on top, Chrome's answer can get stuck. */
function watchVisibility() {
  if (!tracksVisibility) return;
  visibility?.disconnect();
  seenSince = null;
  visibility = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        const isVisible = (entry as IntersectionObserverEntry & { isVisible: boolean }).isVisible;
        seenSince = isVisible ? (seenSince ?? Date.now()) : null;
      }
    },
    { threshold: [0], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
  );
  visibility.observe(document.documentElement);
}
watchVisibility();

function settle() {
  quietUntil = Date.now() + SETTLE_MS;
}

/** A menu in a frame the browser never sees whole (the page around the
 * frame blurs or fades it) would never take a click: it tells the content
 * script, and the page shows it instead (where the same checks apply). */
const UNSEEN_MS = 1200;
let unseenTimer: ReturnType<typeof setTimeout> | undefined;
function watchUnseen() {
  clearTimeout(unseenTimer);
  if (!tracksVisibility || mode !== "menu") return;
  unseenTimer = setTimeout(() => seenSince === null && toParent("unseen"), UNSEEN_MS);
}

function clickable(): boolean {
  const now = Date.now();
  if (!pageSafe || now < quietUntil) return false;
  return !tracksVisibility || (seenSince !== null && now - seenSince >= SETTLE_MS);
}

// Before any button's own handler. Pressing Enter or Space on a button
// clicks it too, so this covers the keyboard as well.
window.addEventListener(
  "click",
  (e) => {
    if (clickable()) return;
    e.preventDefault();
    e.stopImmediatePropagation();
  },
  true,
);

function svg(markup: string): HTMLElement {
  const span = el("span", { className: "svg" });
  span.append(...markupNodes(markup));
  return span;
}

const LOGO = `<svg viewBox="0 0 1024 1024" width="20" height="20" aria-hidden="true"><circle cx="512" cy="512" r="452" fill="#14B8A6"/><circle cx="512" cy="512" r="318" fill="#073b37"/><circle cx="512" cy="438" r="94" fill="#fff"/><path d="M470 486H554L586 676Q590 702 564 702H460Q434 702 438 676Z" fill="#fff"/></svg>`;
const ICON_CLOSE = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>`;
const ICON_CHEVRON = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>`;
const ICON_REFRESH = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/></svg>`;
const ICON_WAND = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 4 1.5 1.5M19 8l1.5 1.5M18 3v2M21 6h-2M4 20 15 9l1 1L5 21z"/></svg>`;
const ICON_PASSKEY = `<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="9" cy="7" r="4"/><path d="M2 21a7 7 0 0 1 11.5-5.4"/><circle cx="18" cy="15" r="2.5"/><path d="M18 17.5V22M18 20h2"/></svg>`;
const ICON_KEY = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M17 6l3 3M15 8l2 2"/></svg>`;

/** Icon for a login; matches show the icon of the page they are for. */
function icon(login: Login): HTMLElement {
  const matches = state?.logins.some((match) => match.id === login.id);
  return avatar(login, matches ? (state?.url ?? undefined) : undefined);
}

function texts(login: Login): HTMLElement {
  return el("span", { className: "text" }, el("span", { className: "title", textContent: login.title }), el("span", { className: "sub", textContent: subtitle(login) }));
}

/** Who a login signs in as: its username, or its provider and the account
 * there ("Google · ana@gmail.com"). */
function subtitle(login: Login): string {
  if (!login.signInWith) return login.username || login.vault;
  const provider = providerName(login.signInWith);
  return login.providerAccount ? t("signInWithAccount", provider, login.providerAccount) : t("signInWith", provider);
}

function closeButton(run: () => void): HTMLButtonElement {
  const button = el("button", { className: "x", type: "button", title: t("close") }, svg(ICON_CLOSE));
  button.addEventListener("click", run);
  return button;
}

function showError(text: string) {
  app.querySelector(".error")?.remove();
  app.querySelector(".box")?.append(el("p", { className: "error", textContent: text }));
  report();
}

function unlockError(code: string | undefined): string {
  switch (code) {
    case "busy":
      return t("unlockBusy");
    case "no_account":
      return t("noAccount");
    default:
      return t("unlockFailed");
  }
}

// ----- Actions ------------------------------------------------------------------

/** In a field for a one-time code (or the card on such a page), a login
 * fills only its code. */
async function fillLogin(login: Login, submit: boolean, insecureConfirmed = false) {
  if (login.signInWith) return signInWith(login);
  const reply = await send({ type: "fill", id: login.id, submit, code: field.code === true, insecureConfirmed });
  // The content script closes the menu, but not one the page shows for its
  // frame (see content.ts, `detached`).
  if (reply.ok) return toParent("close");
  if (reply.error === "locked") await refresh();
  else if (reply.error === "insecure_confirm") confirmBox(t("insecureFillWarning", state?.host ?? ""), () => void fillLogin(login, submit, true));
  else showError(t("fillFailed"));
}

/** Asks before filling, in place of the menu's contents; Cancel brings them
 * back. */
function confirmBox(text: string, onConfirm: () => void) {
  const cancel = el("button", { type: "button", className: "link", textContent: t("cancel") });
  cancel.addEventListener("click", () => void refresh(true));
  const go = el("button", { type: "button", className: "primary", textContent: t("fillAnyway") });
  go.addEventListener("click", onConfirm);
  app.replaceChildren(el("div", { className: "box confirm" }, el("p", { className: "note", textContent: text }), el("div", { className: "save-foot" }, cancel, go)));
  report();
}

function loginRow(login: Login, options: { submit: boolean }): HTMLButtonElement {
  const row = el("button", { className: "row", type: "button" }, icon(login), texts(login));
  if (mode === "card") row.append(svg(ICON_KEY));
  row.addEventListener("click", () => void fillLogin(login, options.submit));
  return row;
}

/** A login that signs in through a provider: presses the page's button for
 * it, and Keyless picks the account on the provider's page. */
async function signInWith(login: Login) {
  const reply = await send({ type: "sign_in_with", id: login.id });
  if (reply.ok) return toParent("close");
  if (reply.error === "locked") await refresh();
  else showError(t("signInWithMissing", providerName(login.signInWith ?? "")));
}

const ICON_SAVE = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 3h11l3 3v13a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M7 3v5h8V3M7 21v-7h10v7"/></svg>`;

/** "Save in Keyless": the login typed in the form, saved before sending it. */
function saveNowRow(): HTMLButtonElement {
  const row = el(
    "button",
    { className: "row", type: "button" },
    el("span", { className: "glyph" }, svg(ICON_SAVE)),
    el("span", { className: "text" }, el("span", { className: "title", textContent: t("ctxSaveLogin") })),
  );
  row.addEventListener("click", () => toParent("save_now"));
  return row;
}

const ICON_QR = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3"/></svg>`;

/** "Read the QR code on this page": keeps the site's one-time password in
 * one of its logins and fills the code it gives now. */
function scanRow(logins: Login[]): HTMLButtonElement {
  const row = el(
    "button",
    { className: "row", type: "button" },
    el("span", { className: "glyph" }, svg(ICON_QR)),
    el("span", { className: "text" }, el("span", { className: "title", textContent: t("scanQr") }), el("span", { className: "sub", textContent: t("scanQrHint") })),
  );
  row.addEventListener("click", async () => {
    const reply = await send<{ uri: string; issuer: string | null; account: string | null }>({ type: "scan_qr" });
    if (!reply.ok || !reply.data) return showError(t("qrNotFound"));
    const uri = reply.data.uri;
    const save = async (login: Login) => {
      const saved = await send({ type: "save_totp_fill", id: login.id, uri });
      if (saved.ok) toParent("close");
      else showError(t("fillFailed"));
    };
    // The account the code is for, when the QR code says it.
    const account = reply.data.account?.trim().toLowerCase() ?? "";
    const same = logins.filter((login) => account !== "" && login.username.trim().toLowerCase() === account);
    if (logins.length === 1 || same.length === 1) return void save(same[0] ?? logins[0]);
    // Which login the code goes in: those for that account first.
    const ordered = [...same, ...logins.filter((login) => !same.includes(login))];
    const box = el("div", { className: "box menu" }, el("div", { className: "head", textContent: t("saveCodeIn") }));
    for (const login of ordered) {
      const choice = el("button", { className: "row", type: "button" }, icon(login), texts(login));
      choice.addEventListener("click", () => void save(login));
      box.append(choice);
    }
    app.replaceChildren(box);
    report();
  });
  return row;
}

/** Signs in with a passkey the page offers in its fields: the page gets it
 * at once, nothing is typed. */
async function usePasskey(key: PasskeyEntry) {
  const reply = await send({ type: "passkey_pick", credentialId: key.credentialId });
  if (reply.ok) return toParent("close");
  if (reply.error === "locked") await refresh();
  else showError(t("pkFailed"));
}

function passkeyLogin(key: PasskeyEntry): Login {
  return { id: key.itemId, title: key.title, username: key.userName, url: state?.url ?? "", vault: "", favorite: false };
}

function passkeyRow(key: PasskeyEntry): HTMLButtonElement {
  const login = passkeyLogin(key);
  const row = el(
    "button",
    { className: "row", type: "button" },
    avatar(login, state?.url ?? undefined),
    el("span", { className: "text" }, el("span", { className: "title", textContent: key.title }), el("span", { className: "sub", textContent: key.userName || t("passkey") })),
    el("span", { className: "badge" }, svg(ICON_PASSKEY), el("span", { textContent: t("passkey") })),
  );
  row.addEventListener("click", () => void usePasskey(key));
  return row;
}

/** What the menu and the card offer: the page's logins (only those with a
 * code, in a field for one) and the passkeys its field asks for. */
function offered(): { logins: Login[]; passkeys: PasskeyEntry[] } {
  const logins = (state?.logins ?? []).filter((login) => !field.code || login.totp);
  const passkeys = field.code ? [] : mode === "card" || field.passkeys ? (state?.passkeys ?? []) : [];
  return { logins, passkeys };
}

function rows(): HTMLElement[] {
  return Array.from(app.querySelectorAll<HTMLElement>(".row"));
}

function focusRow(index: number) {
  const list = rows();
  list[Math.max(0, Math.min(index, list.length - 1))]?.focus();
}

document.addEventListener("keydown", (e) => {
  const list = rows();
  const index = list.indexOf(document.activeElement as HTMLElement);
  if (e.key === "ArrowDown" && index >= 0) {
    e.preventDefault();
    focusRow(index + 1);
  } else if (e.key === "ArrowUp" && index >= 0) {
    e.preventDefault();
    if (index === 0) {
      const search = app.querySelector<HTMLInputElement>("input");
      if (search) search.focus();
      else toParent("close", { refocus: true });
    } else focusRow(index - 1);
  } else if (e.key === "Escape") {
    e.preventDefault();
    if (mode === "passkey") closePasskey();
    else if (mode === "menu") toParent("close", { refocus: true });
    else if (expanded) {
      expanded = false;
      render();
    } else toParent("close");
  }
});

// ----- Views --------------------------------------------------------------------

let unlocking = false;

/** Keyless asks for the password itself (the computer password or its own
 * small window): never in the page, never in the extension. */
async function unlock() {
  const text = app.querySelector<HTMLElement>(".locked .note");
  const button = app.querySelector<HTMLButtonElement>(".locked button");
  if (unlocking || !text || !button) return;
  unlocking = true;
  button.disabled = true;
  text.textContent = t("waitingUnlock");
  report();
  const reply = await send({ type: "unlock" });
  unlocking = false;
  if (reply.ok) {
    toParent("unlocked");
    await refresh();
    return;
  }
  button.disabled = false;
  text.textContent = reply.error === "cancelled" ? t("lockedNote") : unlockError(reply.error);
  report();
}

function lockedView(): HTMLElement {
  const text = el("p", { className: "note", textContent: t("lockedNote") });
  const button = el("button", { className: "primary", type: "button", textContent: t("unlockApp") });
  button.addEventListener("click", () => void unlock());
  return el("div", { className: "locked" }, el("div", { className: "head" }, svg(LOGO), el("span", { textContent: "Keyless" })), text, button);
}

/** A click on the Keyless button in the field: unlock when locked,
 * otherwise open or close the list. */
async function activate(opening: boolean) {
  if (state?.state === "locked") void unlock();
  else if (!opening) toParent("close", { refocus: true });
}

function noteFor(current: InlineState["state"]): string {
  return current === "app_not_running" ? t("notRunningBody") : t("notConnectedNote");
}

// ----- Suggested password (sign-up and change-password forms) -------------------

/** The field this menu was opened for. */
let field: FieldInfo = { newPassword: false, maxLength: null };
let suggestion: string | null = null;
let symbols = true;

/** Generated by the app; the background keeps it to fill exactly this one. */
async function newSuggestion() {
  const reply = await send<string>({ type: "suggest", maxLength: field.maxLength ?? 0, symbols, rules: field.rules ?? "" });
  suggestion = reply.ok ? (reply.data ?? null) : null;
}

/** Digits and symbols coloured, like the app's generator. */
function colorized(password: string): HTMLElement {
  const text = el("span", { className: "generated" });
  for (const char of password) {
    text.append(el("span", { className: /[0-9]/.test(char) ? "digit" : /[A-Za-z]/.test(char) ? "" : "symbol", textContent: char }));
  }
  return text;
}

function generatorView(): HTMLElement {
  const use = el(
    "button",
    { className: "row suggest", type: "button" },
    svg(ICON_WAND),
    el("span", { className: "text" }, el("span", { className: "title", textContent: t("useSuggested") }), suggestion ? colorized(suggestion) : el("span", { className: "sub", textContent: "…" })),
  );
  use.addEventListener("click", async () => {
    const reply = await send({ type: "use_suggested" });
    // The content script fills the fields and closes this menu.
    if (!reply.ok) {
      await newSuggestion();
      render();
    }
  });
  const again = el("button", { className: "x", type: "button", title: t("regenerate") }, svg(ICON_REFRESH));
  again.addEventListener("click", async () => {
    await newSuggestion();
    render();
  });
  const toggle = el("input", { type: "checkbox", checked: symbols });
  toggle.addEventListener("change", async () => {
    symbols = toggle.checked;
    await newSuggestion();
    render();
  });
  return el(
    "div",
    { className: "generator" },
    el("div", { className: "suggest-line" }, use, again),
    el("label", { className: "option" }, toggle, el("span", { textContent: t("symbols") })),
  );
}

// ----- Cards and identities (payment and address forms) --------------------------

let formItems: FormItems | null = null;

async function loadFormItems() {
  const reply = await send<FormItems>({ type: "form_items" });
  formItems = reply.ok ? (reply.data ?? null) : null;
}

const ICON_CARD = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="5" width="19" height="14" rx="2.5"/><path d="M2.5 10h19M6.5 15h3"/></svg>`;
const ICON_PERSON = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>`;

function formRow(id: string, glyph: string, title: string, sub: string): HTMLButtonElement {
  const row = el(
    "button",
    { className: "row", type: "button" },
    el("span", { className: "glyph" }, svg(glyph)),
    el("span", { className: "text" }, el("span", { className: "title", textContent: title }), el("span", { className: "sub", textContent: sub })),
  );
  const fillForm = async (confirmed: boolean) => {
    const reply = await send({ type: "fill_form", id, confirmed });
    if (reply.ok) return; // The content script fills and closes this menu.
    if (reply.error === "insecure_confirm") confirmBox(t("insecureFillWarning", state?.host ?? ""), () => void fillForm(true));
    else if (reply.error === "confirm_form") confirmBox(t("confirmFormFill", title, state?.host ?? ""), () => void fillForm(true));
    else showError(reply.error === "insecure_page" ? t("insecurePage") : t("fillFailed"));
  };
  row.addEventListener("click", () => void fillForm(false));
  return row;
}

function formView(box: HTMLElement) {
  if (field.form === "card") {
    const cards = formItems?.cards ?? [];
    box.append(el("div", { className: "head", textContent: t("cards") }));
    if (cards.length === 0) box.append(el("p", { className: "note", textContent: t("noCards") }));
    for (const card of cards) {
      const brand = card.brand ? `${card.brand.charAt(0).toUpperCase()}${card.brand.slice(1)} ` : "";
      box.append(formRow(card.id, ICON_CARD, card.title, `${brand}•••• ${card.last4}${card.holder ? ` · ${card.holder}` : ""}`));
    }
  } else {
    const identities = formItems?.identities ?? [];
    box.append(el("div", { className: "head", textContent: t("identities") }));
    if (identities.length === 0) box.append(el("p", { className: "note", textContent: t("noIdentities") }));
    for (const person of identities) {
      box.append(formRow(person.id, ICON_PERSON, person.title, [person.name, person.email || person.city].filter(Boolean).join(" · ")));
    }
  }
}

function renderMenu() {
  const box = el("div", { className: "box menu" });
  if (field.form && state?.state === "ready") {
    formView(box);
    app.replaceChildren(box);
    return;
  }
  if (!state || state.state === "ready") {
    const { logins, passkeys } = offered();
    if (passkeys.length > 0) {
      box.append(el("div", { className: "head", textContent: t("passkeys") }));
      passkeys.forEach((key) => box.append(passkeyRow(key)));
      if (logins.length > 0 || field.newPassword) box.append(el("div", { className: "head", textContent: t("savedLogins") }));
    }
    if (field.newPassword) {
      box.append(generatorView());
      if (logins.length > 0 && passkeys.length === 0) box.append(el("div", { className: "head", textContent: t("savedLogins") }));
    } else if (logins.length === 0 && passkeys.length === 0) {
      box.append(el("p", { className: "note", textContent: field.code ? t("noCodes") : t("noMatches") }));
    }
    logins.forEach((login) => box.append(loginRow(login, { submit: true })));
    // A two-factor setup: the code the site asks for comes from its QR code.
    const withoutCode = (state?.logins ?? []).filter((login) => !login.totp);
    if (field.code && state?.state === "ready" && withoutCode.length > 0) box.append(scanRow(withoutCode));
    if (field.savable && state?.state === "ready") box.append(saveNowRow());
  } else if (state.state === "locked") {
    box.append(lockedView());
  } else {
    box.append(el("div", { className: "head" }, svg(LOGO), el("span", { textContent: "Keyless" })));
    box.append(el("p", { className: "note", textContent: noteFor(state.state) }));
  }
  app.replaceChildren(box);
}

/** The card at the top of a login page: sign in with the best login (or a
 * passkey the page offers in its fields); on a page asking for a one-time
 * code, fill the code of the best login that has one. */
function renderCard() {
  const { logins, passkeys } = offered();
  if (state?.state !== "ready" || (logins.length === 0 && passkeys.length === 0)) {
    // Locked meanwhile, or nothing left to offer.
    app.replaceChildren();
    toParent("hide");
    return;
  }
  if (expanded) return renderSearch({ ...state, logins });
  const key = passkeys[0];
  const best = key ? passkeyLogin(key) : logins[0];
  const label = key ? t("signInPasskey") : field.code ? t("fillCode") : t("signIn");
  const signIn = el("button", { className: "signin", type: "button", textContent: label });
  signIn.addEventListener("click", () => void (key ? usePasskey(key) : fillLogin(best, true)));
  const others = el("button", { className: "others", type: "button" }, el("span", { textContent: t("otherLogins") }), svg(ICON_CHEVRON));
  others.addEventListener("click", () => {
    expanded = true;
    render();
  });
  const head = key ? avatar(best, state.url ?? undefined) : icon(best);
  app.replaceChildren(
    el("div", { className: "box card" }, head, texts(best), signIn, closeButton(() => toParent("close"))),
    ...(logins.length > 0 ? [others] : []),
  );
}

function renderSearch(current: InlineState) {
  const input = el("input", { type: "text", placeholder: t("findLogin"), spellcheck: false, autocomplete: "off" });
  const list = el("div", { className: "list" });
  const close = closeButton(() => {
    expanded = false;
    render();
  });
  app.replaceChildren(el("div", { className: "box search" }, el("div", { className: "bar" }, svg(LOGO), input, close), list));

  // Only the page's logins. Logins saved for other sites are filled from
  // the toolbar popup, which the page cannot cover.
  const show = (logins: Login[]) => {
    list.replaceChildren(...logins.slice(0, MAX_SEARCH_RESULTS).map((login) => loginRow(login, { submit: true })));
    if (logins.length === 0) list.append(el("p", { className: "note", textContent: t("noResults") }));
    list.append(el("p", { className: "note small", textContent: t("otherSitesInPopup") }));
    report();
  };
  show(current.logins);

  input.addEventListener("input", () => {
    // Each word anywhere, case and accents aside.
    const words = searchWords(input.value);
    show(current.logins.filter((login) => hasWords(words, [login.title, login.username, login.url])));
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      focusRow(0);
    }
  });
  input.focus();
}

// ----- "Save login?" prompt ----------------------------------------------------

let saving: SaveState | null = null;
let saveMode: "new" | "update" = "new";
let chosenId: string | null = null;
let editing = false;
let draftTitle = "";
let draftUser = "";
let vaultId = "";
let busy = false;
let done: string | null = null;

async function loadSave() {
  const reply = await send<SaveState | null>({ type: "save_state" });
  saving = reply.ok ? (reply.data ?? null) : null;
  if (!saving) {
    toParent("close");
    return;
  }
  saveMode = saving.state;
  // The login being changed: the one with the current password typed, or
  // the only one with this username. Otherwise the user picks.
  const sameUser = saving.candidates.filter((c) => c.sameUser);
  chosenId = saving.candidates.find((c) => c.current)?.id ?? (sameUser.length === 1 ? sameUser[0].id : null);
  draftTitle = saving.title;
  draftUser = saving.username;
  vaultId = saving.vaults[0]?.id ?? "";
  editing = false;
  done = null;
  render();
}

async function doSave() {
  if (!saving || busy) return;
  busy = true;
  render();
  if (saving.locked) {
    // Keyless asks for the password itself; then the user confirms again,
    // since the comparison may change once the logins can be read.
    const reply = await send({ type: "unlock" });
    busy = false;
    if (reply.ok) await loadSave();
    else render();
    return;
  }
  const reply = saving.form
    ? await send({ type: "save_form", title: draftTitle, vaultId })
    : await send({ type: "save", mode: saveMode, itemId: chosenId, title: draftTitle, username: draftUser, vaultId });
  busy = false;
  if (reply.ok) {
    done = saveMode === "update" ? t("updated") : t("saved");
    render();
    setTimeout(() => toParent("close"), 1600);
  } else if (reply.error === "expired") {
    toParent("close");
  } else {
    render();
    showError(t("saveFailed"));
  }
}

function input(value: string, placeholder: string, onInput: (value: string) => void): HTMLInputElement {
  const field = el("input", { type: "text", value, placeholder, spellcheck: false, autocomplete: "off" });
  field.addEventListener("input", () => onInput(field.value));
  field.addEventListener("keydown", (e) => e.key === "Enter" && void doSave());
  return field;
}

/** "Save card?" / "Save address?": a payment or address form the user
 * sent. */
function formSaveTitle(form: NonNullable<SaveState["form"]>): string {
  if (form.kind === "card") return t("saveCard");
  if (form.kind === "identity") return t("saveIdentity");
  if (form.kind === "api_key") return t("saveApiKey");
  return t("saveSignInWith", form.provider ?? "");
}

function renderFormSave() {
  const s = saving!;
  const form = s.form!;
  const close = closeButton(async () => {
    await send({ type: "dismiss_save" });
    toParent("close");
  });
  const box = el(
    "div",
    { className: "box save" },
    el("div", { className: "save-head" }, svg(LOGO), el("strong", { textContent: formSaveTitle(form) }), close),
  );
  if (done) {
    box.append(el("p", { className: "done", textContent: done }));
    app.replaceChildren(box);
    return;
  }
  const glyph = el("span", { className: "glyph" }, svg(form.kind === "card" ? ICON_CARD : form.kind === "identity" ? ICON_PERSON : ICON_KEY));
  const details = el("div", { className: "edit" }, input(draftTitle, t("titleOptional"), (value) => (draftTitle = value)), el("span", { className: "sub", textContent: form.summary }));
  box.append(el("div", { className: "save-item" }, glyph, details));
  const footer = el("div", { className: "save-foot" });
  if (s.vaults.length > 1) {
    const select = el("select", { title: t("vaultLabel") });
    for (const vault of s.vaults) select.append(el("option", { value: vault.id, textContent: vault.name, selected: vault.id === vaultId }));
    select.addEventListener("change", () => (vaultId = select.value));
    footer.append(select);
  } else {
    footer.append(el("span", { className: "vault", textContent: s.vaults[0]?.name ?? "" }));
  }
  const action = el("button", { type: "button", className: "primary", disabled: busy, textContent: s.locked ? t("unlockToSave") : t("save") });
  action.addEventListener("click", () => void doSave());
  footer.append(action);
  box.append(footer);
  const never = el("button", { type: "button", className: "link never", textContent: t("neverForSite", s.host) });
  never.addEventListener("click", async () => {
    await send({ type: "never_save" });
    toParent("close");
  });
  box.append(never);
  app.replaceChildren(box);
}

function renderSave() {
  const s = saving!;
  if (s.form) return renderFormSave();
  const close = closeButton(async () => {
    await send({ type: "dismiss_save" });
    toParent("close");
  });
  const box = el(
    "div",
    { className: "box save" },
    el("div", { className: "save-head" }, svg(LOGO), el("strong", { textContent: saveMode === "update" ? t("updateLogin") : t("saveLogin") }), close),
  );
  if (done) {
    box.append(el("p", { className: "done", textContent: done }));
    app.replaceChildren(box);
    return;
  }

  if (s.candidates.length > 0) {
    const tabs = el("div", { className: "tabs" });
    for (const option of ["new", "update"] as const) {
      const tab = el("button", { type: "button", className: option === saveMode ? "active" : "", textContent: option === "new" ? t("newItem") : t("updateExisting") });
      tab.addEventListener("click", () => {
        saveMode = option;
        editing = false;
        render();
      });
      tabs.append(tab);
    }
    box.append(tabs);
  }

  const candidate = s.candidates.find((c) => c.id === chosenId) ?? null;
  const title = saveMode === "new" ? draftTitle : (candidate?.title ?? "");
  // A change-password form usually has no username: the login keeps its own.
  const shownUser = draftUser || (saveMode === "update" ? (candidate?.username ?? "") : "");
  const login: Login = { id: "", title, username: shownUser, url: s.url, vault: "", favorite: false };
  const edit = el("button", { type: "button", className: "link", textContent: editing ? t("done") : t("edit") });
  edit.addEventListener("click", () => {
    editing = !editing;
    render();
    app.querySelector<HTMLInputElement>(".edit input")?.focus();
  });
  const details = editing
    ? el(
        "div",
        { className: "edit" },
        ...(saveMode === "new" ? [input(draftTitle, t("titleLabel"), (value) => (draftTitle = value))] : []),
        input(draftUser, t("usernameLabel"), (value) => (draftUser = value)),
      )
    : el("span", { className: "text" }, el("span", { className: "title", textContent: title || s.host }), el("span", { className: "sub", textContent: shownUser || s.host }));
  box.append(el("div", { className: "save-item" }, avatar(login, s.url), details, edit));

  // Which login to update, when there are several for the site.
  if (saveMode === "update" && s.candidates.length > 1) {
    if (!chosenId) box.append(el("p", { className: "note small", textContent: t("chooseLoginToUpdate") }));
    const list = el("div", { className: "choices" });
    for (const c of s.candidates) {
      const choice = el("button", { type: "button", className: `choice${c.id === chosenId ? " active" : ""}` }, el("span", { className: "title", textContent: c.title }), el("span", { className: "sub", textContent: c.username || c.vault }));
      choice.addEventListener("click", () => {
        chosenId = c.id;
        render();
      });
      list.append(choice);
    }
    box.append(list);
  }
  if (s.generated) box.append(el("p", { className: "note small", textContent: t("generatedNote") }));

  const footer = el("div", { className: "save-foot" });
  if (saveMode === "new" && s.vaults.length > 1) {
    const select = el("select", { title: t("vaultLabel") });
    for (const vault of s.vaults) select.append(el("option", { value: vault.id, textContent: vault.name, selected: vault.id === vaultId }));
    select.addEventListener("change", () => (vaultId = select.value));
    footer.append(select);
  } else {
    footer.append(el("span", { className: "vault", textContent: saveMode === "new" ? (s.vaults[0]?.name ?? "") : (candidate?.vault ?? "") }));
  }
  const action = el("button", {
    type: "button",
    className: "primary",
    disabled: busy || (saveMode === "update" && !chosenId),
    textContent: s.locked ? t("unlockToSave") : saveMode === "update" ? t("update") : t("save"),
  });
  action.addEventListener("click", () => void doSave());
  footer.append(action);
  box.append(footer);
  const never = el("button", { type: "button", className: "link never", textContent: t("neverForSite", s.host) });
  never.addEventListener("click", async () => {
    await send({ type: "never_save" });
    toParent("close");
  });
  box.append(never);
  app.replaceChildren(box);
}

// ----- Passkey prompt -------------------------------------------------------------
//
// A site asked to save a passkey or to sign in with one (see background.ts):
// shown at the top of the page like the "Save login?" prompt, over the page
// dimmed, with the same guard against clicks the user did not mean. The
// background knows the request (the one waiting in this tab); this page
// only shows it and passes on what the user chose. Closing it hands the
// request to the browser, like closing the Keyless window.

interface PasskeyView {
  kind: "create" | "get";
  host: string;
  rpId: string;
  locked: boolean;
  rpName?: string;
  userName?: string;
  logins?: Login[];
  passkeys?: PasskeyEntry[];
  /** The site already has a passkey of this account in Keyless. */
  exists?: boolean;
  /** Asked from a frame of another site inside the page. */
  topHost?: string;
}

let passkey: PasskeyView | null = null;
/** Where a new passkey goes: a new login, or a login's id. */
let passkeyTarget = "";
let passkeyError: string | null = null;

async function loadPasskey() {
  const reply = await send<PasskeyView>({ type: "passkey_view" });
  if (!reply.ok || !reply.data) return toParent("close");
  passkey = reply.data;
  render();
}

async function passkeyAction(type: string, extra: Record<string, unknown> = {}) {
  if (busy) return;
  busy = true;
  render();
  const reply = await send<PasskeyView>({ type, ...extra });
  busy = false;
  if (type === "passkey_unlock" && reply.ok && reply.data) {
    passkey = reply.data;
    return render();
  }
  // Done (the background also closes this), or gone meanwhile.
  if (reply.ok || reply.error === "expired") return toParent("close");
  passkeyError = reply.error === "exists" ? t("pkExists") : t("pkFailed");
  await loadPasskey();
}

/** The close button and Escape: the browser takes the request, unless the
 * account already has a passkey here (the site is told so). */
function closePasskey() {
  if (passkey?.kind === "create" && passkey.exists) void passkeyAction("passkey_cancel", { exists: true });
  else void passkeyAction("passkey_fallback");
}

// ----- SSH public keys --------------------------------------------------------------
//
// Under a developer site's box for an SSH public key: the vault's SSH keys
// (public keys only); the chosen one goes in the box.

let sshKeys: { id: string; title: string; fingerprint: string }[] | null = null;

async function loadSsh() {
  const reply = await send<{ id: string; title: string; fingerprint: string }[]>({ type: "ssh_keys" });
  sshKeys = reply.ok ? (reply.data ?? []) : [];
  render();
}

function renderSsh() {
  const box = el("div", { className: "box menu" }, el("div", { className: "head" }, svg(LOGO), el("span", { textContent: t("sshKeys") })));
  if (!sshKeys?.length) box.append(el("p", { className: "note", textContent: t("noSshKeys") }));
  for (const key of sshKeys ?? []) {
    const row = el(
      "button",
      { className: "row", type: "button" },
      el("span", { className: "glyph" }, svg(ICON_KEY)),
      el("span", { className: "text" }, el("span", { className: "title", textContent: key.title }), el("span", { className: "sub", textContent: key.fingerprint })),
    );
    row.addEventListener("click", async () => {
      const reply = await send({ type: "fill_ssh_key", id: key.id });
      if (reply.ok) toParent("close");
      else showError(t("fillFailed"));
    });
    box.append(row);
  }
  app.replaceChildren(box);
}

// ----- Breach warning ------------------------------------------------------------
//
// Sentinel found this website's login breached: its password in breaches,
// or the website breached after the password was set. Shown at the top of
// the page like the "Save login?" prompt; the button opens the website's
// page to change the password in a new tab.

let siteAlert: AlertView | null = null;

async function loadAlert() {
  const reply = await send<AlertView>({ type: "site_alert" });
  if (!reply.ok || !reply.data) return toParent("close");
  siteAlert = reply.data;
  render();
}

async function alertAction(type: "site_alert_change" | "site_alert_dismiss" | "site_alert_clear" | "site_alert_trust", extra: Record<string, unknown> = {}) {
  if (busy) return;
  busy = true;
  render();
  await send({ type, ...extra });
  busy = false;
  toParent("close");
}

function renderAlert() {
  const v = siteAlert!;
  if (v.kind === "paste") return renderPasteAlert(v);
  if (v.kind === "secret_key") return renderSecretKeyAlert(v);
  const close = closeButton(() => void alertAction("site_alert_dismiss"));
  const box = el("div", { className: "box save alert" }, el("div", { className: "save-head" }, svg(LOGO), el("strong", { textContent: t("breachTitle") }), close));
  const compromised = v.alerts.find((a) => a.kind === "compromised");
  const date = compromised?.date
    ? new Intl.DateTimeFormat(chrome.i18n.getUILanguage(), { dateStyle: "medium", timeZone: "UTC" }).format(new Date(`${compromised.date}T00:00:00Z`))
    : "";
  box.append(el("p", { className: "note", textContent: compromised ? t("breachSite", v.host, date) : t("breachPassword") }));
  const list = el("div", { className: "choices" });
  for (const a of v.alerts) {
    const login: Login = { id: a.itemId, title: a.title, username: a.username, url: v.url, vault: "", favorite: false };
    list.append(el("div", { className: "save-item" }, avatar(login, v.url), el("span", { className: "text" }, el("span", { className: "title", textContent: a.title }), el("span", { className: "sub", textContent: a.username || v.host }))));
  }
  box.append(list);
  const later = el("button", { type: "button", className: "link", textContent: t("breachLater"), disabled: busy });
  later.addEventListener("click", () => void alertAction("site_alert_dismiss", { snooze: true }));
  box.append(el("div", { className: "save-foot" }, later, primaryButton(t("breachChange"), () => void alertAction("site_alert_change"))));
  app.replaceChildren(box);
}

/** A password of another site's login was pasted here: maybe a page
 * pretending to be that site. */
function renderPasteAlert(v: Extract<AlertView, { kind: "paste" }>) {
  const close = closeButton(() => void alertAction("site_alert_dismiss"));
  const box = el("div", { className: "box save alert" }, el("div", { className: "save-head" }, svg(LOGO), el("strong", { textContent: t("pasteTitle") }), close));
  const sites = [...new Set(v.logins.map((l) => l.site).filter(Boolean))].join(", ");
  box.append(el("p", { className: "note", textContent: t("pasteBody", sites || "?", v.host) }));
  const list = el("div", { className: "choices" });
  for (const l of v.logins) {
    const login: Login = { id: l.itemId, title: l.title, username: l.site, url: l.site ? `https://${l.site}` : v.url, vault: "", favorite: false };
    list.append(el("div", { className: "save-item" }, avatar(login, login.url), el("span", { className: "text" }, el("span", { className: "title", textContent: l.title }), el("span", { className: "sub", textContent: l.site }))));
  }
  box.append(list);
  const foot = el("div", { className: "save-foot" });
  if (v.logins.length === 1) {
    const trust = el("button", { type: "button", className: "link", textContent: t("pasteTrust"), disabled: busy });
    trust.addEventListener("click", () => void alertAction("site_alert_trust"));
    foot.append(trust);
  } else {
    foot.append(el("span"));
  }
  foot.append(primaryButton(t("pasteClear"), () => void alertAction("site_alert_clear")));
  box.append(foot);
  app.replaceChildren(box);
}

/** The Secret Key was pasted into a website: Keyless never asks for it on
 * one. */
function renderSecretKeyAlert(v: Extract<AlertView, { kind: "secret_key" }>) {
  const close = closeButton(() => void alertAction("site_alert_dismiss"));
  const box = el("div", { className: "box save alert" }, el("div", { className: "save-head" }, svg(LOGO), el("strong", { textContent: t("secretKeyTitle") }), close));
  box.append(el("p", { className: "note", textContent: t("secretKeyBody", v.host) }));
  box.append(el("div", { className: "save-foot" }, el("span"), primaryButton(t("pasteClear"), () => void alertAction("site_alert_clear"))));
  app.replaceChildren(box);
}

function primaryButton(label: string, run: () => void): HTMLButtonElement {
  const button = el("button", { type: "button", className: "primary", textContent: label, disabled: busy });
  button.addEventListener("click", run);
  return button;
}

function renderPasskey() {
  const v = passkey!;
  const close = closeButton(closePasskey);
  close.title = t("pkCloseHint");
  const title = v.locked ? t("pkLocked") : v.kind === "create" ? t("pkSaveShort") : t("pkSignInShort");
  const box = el("div", { className: "box save passkey" }, el("div", { className: "save-head" }, svg(LOGO), el("strong", { textContent: title }), close));
  if (v.topHost) box.append(el("p", { className: "note small top", textContent: t("pkInFrame", v.topHost) }));
  if (passkeyError) box.append(el("p", { className: "error", textContent: passkeyError }));
  const site = `https://${v.host}`;
  const other = el("button", { type: "button", className: "link", textContent: t("pkOtherDevice"), disabled: busy });
  other.addEventListener("click", () => void passkeyAction("passkey_fallback"));

  if (v.locked) {
    box.append(el("p", { className: "note", textContent: t("pkLockedHint", v.rpId) }));
    box.append(el("div", { className: "save-foot" }, other, primaryButton(t("unlockApp"), () => void passkeyAction("passkey_unlock"))));
  } else if (v.kind === "create") {
    const login: Login = { id: "", title: v.rpName || v.rpId, username: v.userName ?? "", url: site, vault: "", favorite: false };
    box.append(
      el(
        "div",
        { className: "save-item" },
        avatar(login, site),
        el("span", { className: "text" }, el("span", { className: "title", textContent: v.rpId }), el("span", { className: "sub", textContent: v.userName || v.rpName || "" })),
        svg(ICON_PASSKEY),
      ),
    );
    if (v.exists) {
      box.append(el("p", { className: "note small", textContent: t("pkExists") }));
      box.append(el("div", { className: "save-foot" }, el("span"), primaryButton(t("ok"), closePasskey)));
    } else {
      const foot = el("div", { className: "save-foot" });
      if ((v.logins ?? []).length > 0) {
        // A login already saved for the site can take it.
        const select = el("select", { title: t("pkSaveIn") });
        select.append(el("option", { value: "", textContent: t("pkNewLogin"), selected: passkeyTarget === "" }));
        for (const l of v.logins ?? []) select.append(el("option", { value: l.id, textContent: l.username ? `${l.title} · ${l.username}` : l.title, selected: l.id === passkeyTarget }));
        select.addEventListener("change", () => (passkeyTarget = select.value));
        foot.append(select);
      } else {
        foot.append(el("span", { className: "vault", textContent: t("pkNewLogin") }));
      }
      foot.append(primaryButton(t("save"), () => void passkeyAction("passkey_choose", { itemId: passkeyTarget })));
      box.append(foot);
      box.append(el("div", { className: "passkey-other" }, other));
    }
  } else {
    const keys = v.passkeys ?? [];
    if (keys.length === 0) {
      box.append(el("p", { className: "note", textContent: t("pkNone") }));
      box.append(el("div", { className: "save-foot" }, el("span", { className: "vault", textContent: t("pkNoneHint") }), primaryButton(t("pkOtherDevice"), () => void passkeyAction("passkey_fallback"))));
    } else {
      const list = el("div", { className: "list" });
      for (const key of keys) {
        const login: Login = { id: key.itemId, title: key.title, username: key.userName, url: site, vault: "", favorite: false };
        const row = el("button", { className: "row", type: "button", disabled: busy }, avatar(login, site), texts(login), svg(ICON_PASSKEY));
        row.addEventListener("click", () => void passkeyAction("passkey_choose", { credentialId: key.credentialId }));
        list.append(row);
      }
      box.append(list, el("div", { className: "passkey-other" }, other));
    }
  }
  app.replaceChildren(box);
}

function render() {
  if (mode === "menu") renderMenu();
  else if (mode === "card") renderCard();
  else if (mode === "passkey") {
    if (passkey) renderPasskey();
  } else if (mode === "alert") {
    if (siteAlert) renderAlert();
  } else if (mode === "ssh") {
    if (sshKeys) renderSsh();
  } else if (saving) renderSave();
  report();
}

let lastRendered = "";
async function refresh(force = false) {
  if (mode === "save") return loadSave();
  if (mode === "passkey") return loadPasskey();
  if (mode === "alert") return loadAlert();
  if (mode === "ssh") return loadSsh();
  const reply = await send<InlineState>({ type: "state" });
  state = reply.ok && reply.data ? reply.data : { state: "error", url: null, host: null, logins: [] };
  if (mode === "menu" && field.newPassword && state.state === "ready" && suggestion === null) await newSuggestion();
  if (mode === "menu" && field.form && state.state === "ready") await loadFormItems();
  // Avoid redrawing (and losing the keyboard focus) when nothing changed.
  const key = JSON.stringify(state);
  if (!force && key === lastRendered && app.childElementCount > 0) return;
  lastRendered = key;
  render();
}

window.addEventListener("message", async (event) => {
  const data = event.data;
  if (event.source !== window.parent || typeof data?.keyless !== "string") return;
  if (data.type === "init") {
    if (token) return;
    settle();
    // Until the content script has checked the menu on screen.
    pageSafe = false;
    // Adopted only once the background confirms it: the page can post here
    // too, but cannot know the token.
    const reply = await chrome.runtime.sendMessage({ type: "hello", token: data.keyless }).catch(() => null);
    if (reply?.ok && !token) {
      token = data.keyless;
      if (data.field) field = data.field;
      await refresh(true);
      watchUnseen();
      if (data.activate) void activate(true);
    }
    return;
  }
  if (!token || data.keyless !== token) return;
  switch (data.type) {
    case "safety":
      // Visible again after being hidden or covered: wait a moment again.
      if (data.safe === true && !pageSafe) settle();
      pageSafe = data.safe === true;
      break;
    case "moved":
      settle();
      break;
    case "recheck":
      settle();
      watchVisibility();
      break;
    case "show":
      settle();
      pageSafe = false;
      expanded = false;
      // A new passkey request.
      passkeyError = null;
      passkeyTarget = "";
      if (data.field) {
        if (data.field.newPassword !== field.newPassword || data.field.maxLength !== field.maxLength || data.field.rules !== field.rules) suggestion = null;
        field = data.field;
      }
      await refresh(true);
      watchUnseen();
      if (data.activate) void activate(true);
      break;
    case "activate":
      void activate(false);
      break;
    case "refresh":
      void refresh();
      break;
    case "focus":
      focusRow(0);
      break;
  }
});

// Locked or unlocked meanwhile (by the app, the popup or another menu), or
// a login saved.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "session" || !token) return;
  if (changes.lockState || (changes.itemsChangedAt && mode !== "save")) void refresh();
});

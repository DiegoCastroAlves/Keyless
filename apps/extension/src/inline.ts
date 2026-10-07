// The Keyless menus shown inside web pages, in an iframe the content script
// creates: the list below a login field (#menu) and the sign-in card at the
// top of the page (#card).
//
// This is an extension page, isolated from the web page: the page can
// neither read it nor script it. It only works with the token its content
// script registered with the background, which it receives by postMessage
// (addressed to the extension origin, so the page never sees it).

import type { InlineState, Login } from "./types";

const t = (key: string, ...subs: string[]) => chrome.i18n.getMessage(key, subs) || key;
const mode: "menu" | "card" = location.hash === "#card" ? "card" : "menu";
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

function svg(markup: string): HTMLElement {
  const span = el("span", { className: "svg" });
  span.innerHTML = markup;
  return span;
}

const LOGO = `<svg viewBox="0 0 1024 1024" width="20" height="20" aria-hidden="true"><circle cx="512" cy="512" r="452" fill="#14B8A6"/><circle cx="512" cy="512" r="318" fill="#073b37"/><circle cx="512" cy="438" r="94" fill="#fff"/><path d="M470 486H554L586 676Q590 702 564 702H460Q434 702 438 676Z" fill="#fff"/></svg>`;
const ICON_CLOSE = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>`;
const ICON_CHEVRON = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>`;
const ICON_KEY = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M17 6l3 3M15 8l2 2"/></svg>`;

function hostOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

function avatar(login: Login): HTMLElement {
  return el("span", { className: "avatar", textContent: (login.title.match(/[\p{L}\p{N}]/u)?.[0] ?? "?").toUpperCase() });
}

function texts(login: Login): HTMLElement {
  return el(
    "span",
    { className: "text" },
    el("span", { className: "title", textContent: login.title }),
    el("span", { className: "sub", textContent: login.username || login.vault }),
  );
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
    case "rate_limited":
      return t("rateLimited");
    default:
      return t("unlockFailed");
  }
}

// ----- Actions ------------------------------------------------------------------

async function fillLogin(login: Login, submit: boolean, anySite = false) {
  const reply = await send({ type: "fill", id: login.id, submit, anySite });
  if (reply.ok) return; // The content script closes the menu.
  if (reply.error === "locked") await refresh();
  else showError(t("fillFailed"));
}

/** A login saved for another site: fill only after the user confirms. */
function confirmOtherSite(login: Login, row: HTMLElement) {
  const fillButton = el("button", { className: "primary small", type: "button", textContent: t("fillAnyway") });
  const cancel = el("button", { className: "secondary small", type: "button", textContent: t("cancel") });
  const warning = el(
    "div",
    { className: "warn" },
    el("p", { textContent: t("otherSiteWarning", login.title, hostOf(login.url), state?.host ?? "") }),
    el("div", { className: "actions" }, cancel, fillButton),
  );
  fillButton.addEventListener("click", () => void fillLogin(login, false, true));
  cancel.addEventListener("click", () => {
    warning.replaceWith(row);
    row.focus();
    report();
  });
  row.replaceWith(warning);
  fillButton.focus();
  report();
}

function loginRow(login: Login, options: { submit: boolean; matches?: boolean }): HTMLButtonElement {
  const row = el("button", { className: "row", type: "button" }, avatar(login), texts(login));
  if (mode === "card") row.append(svg(ICON_KEY));
  if (options.matches === false) row.title = t("savedFor", hostOf(login.url));
  row.addEventListener("click", () => {
    if (options.matches === false) confirmOtherSite(login, row);
    else void fillLogin(login, options.submit);
  });
  return row;
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
    if (mode === "menu") toParent("close", { refocus: true });
    else if (expanded) {
      expanded = false;
      render();
    } else toParent("close");
  }
});

// ----- Views --------------------------------------------------------------------

function lockedView(): HTMLElement {
  const text = el("p", { className: "note", textContent: t("lockedNote") });
  const systemUnlock = state?.systemUnlock ?? false;
  const button = el("button", { className: "primary", type: "button", textContent: systemUnlock ? t("unlockWithSystem") : t("unlockApp") });
  button.addEventListener("click", async () => {
    if (systemUnlock) {
      // The computer password prompt: Keyless itself stays in the
      // background.
      button.disabled = true;
      text.textContent = t("waitingSystem");
      report();
      const reply = await send({ type: "unlock_system" });
      if (reply.ok) {
        toParent("unlocked");
        await refresh();
        return;
      }
      button.disabled = false;
      text.textContent = reply.error === "cancelled" ? t("lockedNote") : unlockError(reply.error);
      report();
    } else {
      // The master password is typed in the popup, never in the page.
      try {
        await chrome.action.openPopup();
        text.textContent = t("unlockInPopup");
      } catch {
        text.textContent = t("unlockToolbarHint");
      }
      report();
    }
  });
  return el("div", { className: "locked" }, text, button);
}

function noteFor(current: InlineState["state"]): string {
  return current === "app_not_running" ? t("notRunningBody") : t("notConnectedNote");
}

function renderMenu() {
  const box = el("div", { className: "box menu" }, el("div", { className: "head" }, svg(LOGO), el("span", { textContent: "Keyless" })));
  if (!state || state.state === "ready") {
    const logins = state?.logins ?? [];
    if (logins.length === 0) box.append(el("p", { className: "note", textContent: t("noMatches") }));
    logins.forEach((login) => box.append(loginRow(login, { submit: false })));
  } else if (state.state === "locked") {
    box.append(lockedView());
  } else {
    box.append(el("p", { className: "note", textContent: noteFor(state.state) }));
  }
  app.replaceChildren(box);
}

function renderCard() {
  if (state?.state !== "ready" || state.logins.length === 0) {
    // Locked meanwhile, or nothing left to offer.
    app.replaceChildren();
    toParent("hide");
    return;
  }
  if (expanded) return renderSearch(state);
  const best = state.logins[0];
  const signIn = el("button", { className: "signin", type: "button", textContent: t("signIn") });
  signIn.addEventListener("click", () => void fillLogin(best, true));
  const others = el("button", { className: "others", type: "button" }, el("span", { textContent: t("otherLogins") }), svg(ICON_CHEVRON));
  others.addEventListener("click", () => {
    expanded = true;
    render();
  });
  app.replaceChildren(
    el("div", { className: "box card" }, avatar(best), texts(best), signIn, closeButton(() => toParent("close"))),
    others,
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

  const matching = new Set(current.logins.map((login) => login.id));
  const show = (logins: Login[]) => {
    list.replaceChildren(...logins.map((login) => loginRow(login, { submit: matching.has(login.id), matches: matching.has(login.id) })));
    if (logins.length === 0) list.append(el("p", { className: "note", textContent: t("noResults") }));
    report();
  };
  show(current.logins);

  let timer: ReturnType<typeof setTimeout> | undefined;
  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const query = input.value.trim();
      if (!query) return show(current.logins);
      const reply = await send<Login[]>({ type: "search", query });
      if (input.value.trim() === query) show((reply.data ?? []).slice(0, MAX_SEARCH_RESULTS));
    }, 120);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      focusRow(0);
    }
  });
  input.focus();
}

function render() {
  if (mode === "menu") renderMenu();
  else renderCard();
  report();
}

let lastRendered = "";
async function refresh(force = false) {
  const reply = await send<InlineState>({ type: "state" });
  state = reply.ok && reply.data ? reply.data : { state: "error", host: null, logins: [], systemUnlock: false };
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
    // Adopted only once the background confirms it: the page can post here
    // too, but cannot know the token.
    const reply = await chrome.runtime.sendMessage({ type: "hello", token: data.keyless }).catch(() => null);
    if (reply?.ok && !token) {
      token = data.keyless;
      void refresh(true);
    }
    return;
  }
  if (!token || data.keyless !== token) return;
  switch (data.type) {
    case "show":
      expanded = false;
      void refresh(true);
      break;
    case "refresh":
      void refresh();
      break;
    case "focus":
      focusRow(0);
      break;
  }
});

// Unlocked from the popup or another menu.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.unlockedAt && token) void refresh();
});

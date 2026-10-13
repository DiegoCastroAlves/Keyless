// The window that opens from the Keyless button in the browser's toolbar.
//
// Two panes, like the app: the logins on the left (suggestions for the page
// first) and the chosen one on the right, with what can be copied and the
// button that fills it. The keyboard works as in the app: typing searches,
// the arrows move, Enter fills, Escape clears the search and then closes.

import { avatar, hostOf } from "./avatar";
import { providerName } from "./providers";
import type { Settings } from "./settings";
import type { BrowserManager, Login, Status } from "./types";

const t = (key: string, ...subs: string[]) => chrome.i18n.getMessage(key, subs) || key;
const app = document.getElementById("app")!;

type Reply<T> = { ok: boolean; data?: T; error?: string };
const send = <T>(message: unknown): Promise<Reply<T>> => chrome.runtime.sendMessage(message);

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: (Node | string | null)[]): HTMLElementTagNameMap[K] {
  const node = Object.assign(document.createElement(tag), props) as HTMLElementTagNameMap[K];
  node.append(...children.filter((c): c is Node | string => c !== null));
  return node;
}

function svg(markup: string): SVGElement {
  const box = document.createElement("span");
  box.innerHTML = markup;
  return box.firstElementChild as SVGElement;
}

const icon = (paths: string, size = 16) =>
  `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;

const ICONS = {
  search: icon('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>', 15),
  key: icon('<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M17 6l3 3M15 8l2 2"/>'),
  qr: icon('<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3"/>'),
  plus: icon('<path d="M12 5v14M5 12h14"/>'),
  more: icon('<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>'),
  chevron: icon('<path d="m7 15 5 5 5-5M7 9l5-5 5 5"/>', 14),
  back: icon('<path d="m15 18-6-6 6-6"/>'),
  close: icon('<path d="M18 6 6 18M6 6l12 12"/>'),
  copy: icon('<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>', 15),
  eye: icon('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>', 15),
  eyeOff: icon('<path d="M10.6 5.1A10.8 10.8 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-2.2 3.2M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.9 9.9 0 0 0 5.4-1.6M3 3l18 18M9.9 9.9a3 3 0 0 0 4.2 4.2"/>', 15),
  external: icon('<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>', 15),
  app: icon('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/>', 15),
  lock: icon('<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>', 15),
  gear: icon('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>', 15),
  refresh: icon('<path d="M21 12a9 9 0 1 1-2.6-6.4L21 8M21 3v5h-5"/>', 15),
  remove: icon('<path d="M6 6l12 12M18 6 6 18"/>', 14),
  sparkle: icon('<path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6"/>', 15),
  star: icon('<path d="m12 2.5 2.9 6 6.6.9-4.8 4.6 1.2 6.5L12 17.4l-5.9 3.1 1.2-6.5L2.5 9.4l6.6-.9z"/>', 15),
  clock: icon('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>', 15),
  list: icon('<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>', 15),
  login: icon('<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>', 15),
  note: icon('<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>', 15),
  card: icon('<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/>', 15),
  id: icon('<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="M15 9h3M15 13h3M6 16a3 3 0 0 1 6 0"/>', 15),
  password: icon('<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 12h.01M12 12h.01M17 12h.01"/>', 15),
};

function iconButton(markup: string, title: string, run: (e: MouseEvent) => void, className = "tool"): HTMLButtonElement {
  const button = el("button", { className, type: "button", title });
  button.setAttribute("aria-label", title);
  button.append(svg(markup));
  button.addEventListener("click", run);
  return button;
}

let toastTimer: ReturnType<typeof setTimeout> | undefined;
function toast(text: string) {
  document.querySelector(".toast")?.remove();
  clearTimeout(toastTimer);
  const node = el("div", { className: "toast", role: "status", textContent: text });
  document.body.append(node);
  toastTimer = setTimeout(() => node.remove(), 2400);
}

function copiedToast(reply: Reply<{ clearAfterSeconds: number }>) {
  toast(reply.ok ? t("copied", String(reply.data?.clearAfterSeconds ?? "")) : t("copyFailed"));
}

/** An item's website as an address to open: "https://" when it has no
 * scheme, and the scheme in lower case (the background only fills http(s)). */
function siteUrl(href: string): string {
  const scheme = /^(https?):/i.exec(href.trim());
  return scheme ? scheme[1].toLowerCase() + href.trim().slice(scheme[1].length) : `https://${href.trim()}`;
}

/** Passwords shown with digits and symbols in their own colours, as in the app. */
function coloredSecret(text: string): HTMLElement {
  const box = el("span", { className: "secret" });
  for (const ch of text) {
    const span = el("span", { textContent: ch });
    if (/[0-9]/.test(ch)) span.className = "digit";
    else if (!/[\p{L}]/u.test(ch)) span.className = "symbol";
    box.append(span);
  }
  return box;
}

// ----- Menus ---------------------------------------------------------------------

interface MenuEntry {
  label: string;
  icon?: string;
  hint?: string;
  danger?: boolean;
  run: () => void;
}

let openMenu: HTMLElement | null = null;

function closeMenu() {
  openMenu?.remove();
  openMenu = null;
}

/** A small menu under `anchor`, closed by a click elsewhere or Escape. */
function showMenu(anchor: HTMLElement, entries: (MenuEntry | "divider" | { header: string })[], align: "left" | "right" = "right") {
  // A second click on the same button closes its menu.
  const reopening = openMenu !== null && openMenu.dataset.anchor === anchor.dataset.menuId;
  closeMenu();
  if (reopening) return;
  anchor.dataset.menuId ||= crypto.randomUUID();
  const menu = el("div", { className: "menu", role: "menu" });
  menu.dataset.anchor = anchor.dataset.menuId;
  for (const entry of entries) {
    if (entry === "divider") {
      menu.append(el("div", { className: "menu-divider" }));
    } else if ("header" in entry) {
      menu.append(el("div", { className: "menu-header", textContent: entry.header }));
    } else {
      const item = el("button", { className: `menu-item${entry.danger ? " danger" : ""}`, type: "button", role: "menuitem" });
      if (entry.icon) item.append(svg(entry.icon));
      item.append(el("span", { className: "grow", textContent: entry.label }));
      if (entry.hint) item.append(el("kbd", { textContent: entry.hint }));
      item.addEventListener("click", () => {
        closeMenu();
        entry.run();
      });
      menu.append(item);
    }
  }
  document.body.append(menu);
  const box = anchor.getBoundingClientRect();
  menu.style.top = `${Math.round(box.bottom + 6)}px`;
  if (align === "right") menu.style.right = `${Math.round(window.innerWidth - box.right)}px`;
  else menu.style.left = `${Math.round(box.left)}px`;
  openMenu = menu;
  (menu.querySelector(".menu-item") as HTMLElement | null)?.focus();
}

document.addEventListener("mousedown", (e) => {
  if (openMenu && !openMenu.contains(e.target as Node) && !(e.target as HTMLElement).closest?.("[data-menu-id]")) closeMenu();
});

// ----- States before the vault ------------------------------------------------------

/** A full-window message, laid out like the app's lock screen. */
function message(title: string, body: string, action?: { label: string; run: () => Promise<void> }, extra: Node[] = []) {
  const parts: Node[] = [
    el("div", { className: "state-logo" }, el("img", { src: "icons/icon-128.png", width: 56, height: 56, alt: "" })),
    el("h2", { textContent: title }),
    el("p", { textContent: body }),
    ...extra,
  ];
  if (action) {
    const button = el("button", { className: "primary", type: "button", textContent: action.label });
    button.addEventListener("click", async () => {
      button.disabled = true;
      await action.run();
      button.disabled = false;
    });
    parts.push(button);
  }
  app.replaceChildren(el("section", { className: "state" }, ...parts));
  (app.querySelector("button.primary") as HTMLElement | null)?.focus();
}

let status: Status | null = null;

async function render() {
  const reply = await send<Status>({ type: "status" });
  status = reply.data ?? { state: "error" };
  switch (status.state) {
    case "host_missing":
      return message(t("hostMissingTitle"), t("hostMissingBody"));
    case "app_not_running":
      return message(t("notRunningTitle"), t("notRunningBody"), {
        label: t("openApp"),
        run: async () => {
          await send({ type: "launch" });
          setTimeout(render, 2500);
        },
      });
    case "not_paired":
      return renderPairing(status.code ?? "");
    case "untrusted_browser":
      return message(t("untrustedBrowserTitle"), t("untrustedBrowserBody"));
    case "untrusted_host":
      return message(t("untrustedHostTitle"), t("untrustedHostBody"));
    case "locked":
      return renderLocked();
    case "ready":
      return renderVault();
    default:
      return message(t("errorTitle"), t("errorBody"), { label: t("retry"), run: render });
  }
}

function renderPairing(code: string) {
  const hint = el("p", { className: "hint", textContent: t("pairHint") });
  message(t("pairTitle"), t("pairBody"), {
    label: t("connect"),
    run: async () => {
      hint.textContent = t("pairWaiting");
      const reply = await send<boolean>({ type: "pair" });
      if (reply.ok && reply.data) void render();
      else hint.textContent = t("pairFailed");
    },
  }, [el("div", { className: "code", textContent: code })]);
  app.querySelector(".state")?.append(hint);
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

/** Unlocks Keyless without opening it. Keyless asks for the password itself:
 * the computer password prompt when that is on, otherwise a small Keyless
 * window. The master password is never typed in the browser. */
function renderLocked() {
  message(t("lockedTitle"), t("lockedNote"), { label: t("unlockApp"), run: () => run(false) });
  const button = app.querySelector("button.primary") as HTMLButtonElement;
  const hint = app.querySelector(".state p") as HTMLElement;
  async function run(auto: boolean) {
    button.disabled = true;
    hint.textContent = t("waitingUnlock");
    const reply = await send({ type: "unlock", auto });
    if (reply.ok) return void render();
    button.disabled = false;
    hint.textContent = reply.error === "cancelled" || reply.error === "skipped" ? t("lockedNote") : unlockError(reply.error);
  }
  // Opening the popup is the request: Keyless asks right away.
  void run(true);
}

// ----- The vault --------------------------------------------------------------------

type ListKind = "suggestions" | "favorites" | "recent" | "all";

interface Details {
  id: string;
  title: string;
  username: string;
  urls: { href: string; label: string }[];
  vault: string;
  favorite: boolean;
  hasPassword: boolean;
  totp: { code: string; period: number; expiresIn: number } | null;
  updatedAt: number;
  password?: string;
}

const LIST_KINDS: { kind: ListKind; label: string; icon: string }[] = [
  { kind: "suggestions", label: "listSuggestions", icon: ICONS.sparkle },
  { kind: "favorites", label: "listFavorites", icon: ICONS.star },
  { kind: "recent", label: "listRecent", icon: ICONS.clock },
  { kind: "all", label: "listAll", icon: ICONS.list },
];

const view = {
  /** The page in the active tab, if it is a web page. */
  pageUrl: null as string | null,
  pageHost: null as string | null,
  /** Logins for the page (fillable as they are). */
  suggestions: [] as Login[],
  kind: "suggestions" as ListKind,
  query: "",
  items: [] as Login[],
  selected: 0,
  details: null as Details | null,
  revealed: false,
  generatorOpen: false,
};

const fillable = (login: Login) => view.suggestions.some((s) => s.id === login.id);

let listBox: HTMLElement;
let listPicker: HTMLButtonElement;
let detailPane: HTMLElement;
let searchInput: HTMLInputElement;
let totpTimer: ReturnType<typeof setInterval> | undefined;

async function renderVault() {
  searchInput = el("input", { type: "search", placeholder: t("searchPlaceholder"), spellcheck: false });
  searchInput.setAttribute("aria-label", t("searchPlaceholder"));
  const generatorButton = iconButton(ICONS.key, `${t("generator")} (Ctrl G)`, () => toggleGenerator());
  const newButton = iconButton(ICONS.plus, t("newItem"), () => showNewItemMenu(newButton), "new");
  const moreButton = iconButton(ICONS.more, t("moreActions"), () => showMainMenu(moreButton));
  const brand = el("button", { className: "brand", type: "button", title: t("openApp") }, el("img", { src: "icons/icon-32.png", width: 24, height: 24, alt: "" }));
  brand.addEventListener("click", () => void send({ type: "open_app" }).then(() => window.close()));

  listPicker = el("button", { className: "list-picker", type: "button" });
  listPicker.addEventListener("click", () => showListMenu());
  listBox = el("div", { className: "items", role: "listbox", tabIndex: -1 });
  listBox.setAttribute("aria-label", t("listAll"));
  detailPane = el("section", { className: "detail" });

  app.replaceChildren(
    el(
      "div",
      { className: "frame vault" },
      el(
        "header",
        { className: "top" },
        brand,
        el("label", { className: "searchbox" }, svg(ICONS.search), searchInput),
        generatorButton,
        newButton,
        moreButton,
      ),
      el("div", { className: "panes" }, el("aside", { className: "list-pane" }, listPicker, listBox), detailPane),
    ),
  );
  searchInput.focus();

  let timer: ReturnType<typeof setTimeout> | undefined;
  searchInput.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      view.query = searchInput.value.trim();
      void loadList();
    }, 120);
  });

  const matches = await send<{ url: string | null; logins: Login[] }>({ type: "tab_matches" });
  view.pageUrl = matches.data?.url ?? null;
  view.pageHost = view.pageUrl ? hostOf(view.pageUrl) : null;
  view.suggestions = matches.data?.logins ?? [];
  // Suggestions first; with none for this page, the most recent logins.
  view.kind = view.suggestions.length > 0 ? "suggestions" : "recent";
  await loadList();
}

async function loadList() {
  let items: Login[];
  if (view.query) {
    items = (await send<Login[]>({ type: "search", query: view.query, limit: 200 })).data ?? [];
  } else if (view.kind === "suggestions") {
    items = view.suggestions;
  } else if (view.kind === "favorites") {
    items = (await send<Login[]>({ type: "search", query: "", favorites: true, limit: 500 })).data ?? [];
  } else if (view.kind === "recent") {
    items = (await send<Login[]>({ type: "search", query: "", limit: 30 })).data ?? [];
  } else {
    items = (await send<Login[]>({ type: "search", query: "", limit: 1000 })).data ?? [];
    items.sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: "base" }));
  }
  view.items = items;
  view.selected = 0;
  renderPicker();
  renderList();
  void showSelected();
}

function renderPicker() {
  const current = LIST_KINDS.find((k) => k.kind === view.kind)!;
  if (view.query) {
    listPicker.replaceChildren(el("span", { className: "grow", textContent: t("searchResults") }), el("span", { className: "count", textContent: String(view.items.length) }));
    listPicker.disabled = true;
  } else {
    listPicker.replaceChildren(
      svg(current.icon),
      el("span", { className: "grow", textContent: t(current.label) }),
      el("span", { className: "count", textContent: String(view.items.length) }),
      svg(ICONS.chevron),
    );
    listPicker.disabled = false;
  }
}

function showListMenu() {
  showMenu(
    listPicker,
    LIST_KINDS.map((k) => ({
      label: t(k.label),
      icon: k.icon,
      run: () => {
        view.kind = k.kind;
        void loadList().then(() => searchInput.focus());
      },
    })),
    "left",
  );
}

function emptyText(): string {
  if (view.query) return t("noResults");
  switch (view.kind) {
    case "suggestions":
      return view.pageHost ? t("noSuggestionsFor", view.pageHost) : t("noSuggestions");
    case "favorites":
      return t("noFavorites");
    default:
      return t("noLogins");
  }
}

function renderList() {
  listBox.replaceChildren();
  if (view.items.length === 0) {
    listBox.append(el("p", { className: "empty", textContent: emptyText() }));
    return;
  }
  view.items.forEach((login, index) => listBox.append(listRow(login, index)));
  markSelected();
}

function listRow(login: Login, index: number): HTMLElement {
  const canFill = fillable(login);
  const through = login.signInWith ? (login.providerAccount ? t("signInWithAccount", providerName(login.signInWith), login.providerAccount) : t("signInWith", providerName(login.signInWith))) : "";
  const sub = login.frame ? [login.username, t("inFrame", login.frame)].filter(Boolean).join(" · ") : through || login.username || login.vault;
  const node = el(
    "div",
    { className: "item", role: "option", id: `item-${index}` },
    avatar(login, canFill ? (view.pageUrl ?? undefined) : undefined),
    el("span", { className: "text" }, el("span", { className: "title", textContent: login.title }), el("span", { className: "sub", textContent: sub })),
  );
  if (canFill) {
    const chip = el("button", { className: "chip", type: "button", textContent: t("fillShort"), tabIndex: -1 });
    chip.addEventListener("click", (e) => {
      e.stopPropagation();
      void fill(login);
    });
    node.append(chip);
  }
  node.addEventListener("click", () => select(index));
  node.addEventListener("dblclick", () => void defaultAction());
  return node;
}

function markSelected() {
  listBox.querySelectorAll(".item").forEach((node, index) => {
    const on = index === view.selected;
    node.classList.toggle("selected", on);
    node.setAttribute("aria-selected", String(on));
    if (on) (node as HTMLElement).scrollIntoView({ block: "nearest" });
  });
  searchInput?.setAttribute("aria-activedescendant", `item-${view.selected}`);
}

function select(index: number) {
  if (index < 0 || index >= view.items.length || index === view.selected) return;
  view.selected = index;
  markSelected();
  void showSelected();
}

const selectedLogin = (): Login | undefined => view.items[view.selected];

// ----- Details -------------------------------------------------------------------

let detailsRequest = 0;

async function showSelected() {
  clearInterval(totpTimer);
  view.revealed = false;
  if (view.generatorOpen) return;
  const login = selectedLogin();
  if (!login) {
    view.details = null;
    detailPane.replaceChildren(el("div", { className: "detail-empty" }, el("img", { src: "icons/icon-128.png", width: 44, height: 44, alt: "" }), el("p", { textContent: emptyText() })));
    return;
  }
  const request = ++detailsRequest;
  const reply = await send<Details>({ type: "details", id: login.id });
  if (request !== detailsRequest) return;
  if (!reply.ok || !reply.data) {
    view.details = null;
    detailPane.replaceChildren(el("div", { className: "detail-empty" }, el("p", { textContent: t("errorBody") })));
    return;
  }
  view.details = reply.data;
  renderDetails(login, reply.data);
}

function field(label: string, value: Node, actions: HTMLElement[], copy?: () => void): HTMLElement {
  const row = el("div", { className: `field${copy ? " copyable" : ""}` }, el("span", { className: "label", textContent: label }), el("div", { className: "value" }, value), el("div", { className: "field-actions" }, ...actions));
  if (copy) {
    row.title = t("copy");
    row.addEventListener("click", (e) => {
      if ((e.target as HTMLElement).closest("button")) return;
      copy();
    });
  }
  return row;
}

function copyField(login: Login, which: "username" | "password" | "totp") {
  void send<{ clearAfterSeconds: number }>({ type: "copy", id: login.id, field: which }).then(copiedToast);
}

function totpRing(expiresIn: number, period: number): HTMLElement {
  const fraction = Math.max(0, Math.min(1, expiresIn / period));
  const circumference = 2 * Math.PI * 8;
  const ring = svg(
    `<svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-opacity="0.2" stroke-width="2.4"/><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" transform="rotate(-90 10 10)" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${(circumference * (1 - fraction)).toFixed(2)}"/></svg>`,
  );
  return el("span", { className: `ring${expiresIn <= 5 ? " ending" : ""}` }, ring, el("span", { textContent: String(expiresIn) }));
}

function renderDetails(login: Login, details: Details) {
  const canFill = fillable(login);
  const site = details.urls[0]?.href;
  const primary = el("button", { className: canFill ? "primary" : "outline", type: "button", textContent: canFill ? t("fillShort") : t("openFill") });
  primary.disabled = !canFill && !site;
  primary.addEventListener("click", () => void defaultAction());
  const more = iconButton(ICONS.more, t("moreActions"), () => showItemMenu(more, login, details));

  const fields = el("div", { className: "card" });
  if (details.username) {
    fields.append(field(t("fieldUsername"), document.createTextNode(details.username), [iconButton(ICONS.copy, t("copyUsername"), () => copyField(login, "username"), "tool small")], () => copyField(login, "username")));
  }
  if (details.hasPassword) {
    const value = el("span", { className: "dots", textContent: "••••••••••••" });
    const eye = iconButton(ICONS.eye, t("reveal"), () => void toggleReveal(login, value, eye), "tool small");
    fields.append(field(t("fieldPassword"), value, [eye, iconButton(ICONS.copy, t("copyPassword"), () => copyField(login, "password"), "tool small")], () => copyField(login, "password")));
  }
  if (details.totp) {
    let { code, period, expiresIn } = details.totp;
    const value = el("span", { className: "code-value" });
    const showCode = () => {
      value.replaceChildren(el("span", { className: "mono", textContent: code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code }), totpRing(expiresIn, period));
    };
    showCode();
    fields.append(field(t("fieldCode"), value, [iconButton(ICONS.copy, t("copyCode"), () => copyField(login, "totp"), "tool small")], () => copyField(login, "totp")));
    totpTimer = setInterval(async () => {
      expiresIn -= 1;
      if (expiresIn <= 0) {
        const fresh = await send<Details>({ type: "details", id: login.id });
        if (!fresh.data?.totp || view.details?.id !== login.id) return;
        ({ code, period, expiresIn } = fresh.data.totp);
      }
      showCode();
    }, 1000);
  }

  const websites = el("div", { className: "card" });
  for (const url of details.urls) {
    const link = el("a", { className: "link", href: url.href, textContent: hostOf(url.href) || url.href, title: url.href });
    link.addEventListener("click", (e) => {
      e.preventDefault();
      void chrome.tabs.create({ url: siteUrl(url.href) }).then(() => window.close());
    });
    websites.append(field(url.label || t("fieldWebsite"), link, []));
  }

  const subtitle = [t("categoryLogin"), details.vault ? t("inVault", details.vault) : ""].filter(Boolean).join(" · ");
  const parts: (Node | null)[] = [
    el(
      "div",
      { className: "detail-head" },
      avatar({ ...login, favorite: details.favorite }, canFill ? (view.pageUrl ?? undefined) : undefined),
      el("div", { className: "head-text" }, el("h1", { textContent: details.title }), el("p", { textContent: subtitle })),
    ),
    el("div", { className: "detail-actions" }, primary, more),
    fields.childElementCount > 0 ? fields : null,
    websites.childElementCount > 0 ? websites : null,
  ];
  if (details.updatedAt > 0) {
    const date = new Intl.DateTimeFormat(chrome.i18n.getUILanguage(), { dateStyle: "medium", timeStyle: "short" }).format(new Date(details.updatedAt * 1000));
    parts.push(el("p", { className: "meta", textContent: t("modifiedOn", date) }));
  }
  detailPane.replaceChildren(el("div", { className: "detail-scroll" }, ...parts));
}

async function toggleReveal(login: Login, value: HTMLElement, eye: HTMLButtonElement) {
  view.revealed = !view.revealed;
  eye.replaceChildren(svg(view.revealed ? ICONS.eyeOff : ICONS.eye));
  eye.title = view.revealed ? t("conceal") : t("reveal");
  if (!view.revealed) {
    value.replaceChildren("••••••••••••");
    value.className = "dots";
    return;
  }
  const reply = await send<Details>({ type: "details", id: login.id, reveal: true });
  if (!view.revealed || view.details?.id !== login.id) return;
  value.className = "revealed";
  value.replaceChildren(coloredSecret(reply.data?.password ?? ""));
}

/** Fills the login, or opens its website and fills it there. */
async function defaultAction() {
  const login = selectedLogin();
  if (!login) return;
  if (fillable(login)) return fill(login);
  const site = view.details?.id === login.id ? view.details.urls[0]?.href : login.url;
  if (!site) return;
  const reply = await send({ type: "open_fill", id: login.id, url: siteUrl(site) });
  if (reply.ok) window.close();
  else toast(t("fillFailed"));
}

async function fill(login: Login, extra: Record<string, unknown> = {}) {
  if (login.signInWith && !extra.anySite) {
    // Through the page's button for the provider (see background.ts).
    const reply = await send({ type: "sign_in_with", id: login.id });
    if (reply.ok) window.close();
    else toast(t("signInWithMissing", providerName(login.signInWith)));
    return;
  }
  const request = { type: "fill", id: login.id, ...extra };
  const reply = await send(request);
  if (reply.ok) window.close();
  else if (reply.error === "cross_site_frame") confirmFill(t("frameWarning", login.frame ?? "", view.pageHost ?? ""), { ...request, frameConfirmed: true });
  else if (reply.error === "insecure_confirm") confirmFill(t("insecureFillWarning", view.pageHost ?? ""), { ...request, insecureConfirmed: true });
  else toast(t("fillFailed"));
}

/** A dialog over the details: fill only after the user confirms. `also`:
 * a second way to go on (fill and add this website to the login). */
function confirmFill(text: string, request: Record<string, unknown>, also?: { label: string; request: Record<string, unknown> }) {
  const fillButton = el("button", { className: "primary", type: "button", textContent: t("fillAnyway") });
  const cancel = el("button", { className: "secondary", type: "button", textContent: t("cancel") });
  const actions = el("div", { className: "dialog-actions" }, cancel);
  const dialog = el("div", { className: "dialog-backdrop" }, el("div", { className: "dialog", role: "alertdialog" }, el("p", { textContent: text }), actions));
  const run = async (next: Record<string, unknown>) => {
    const reply = await send(next);
    if (reply.ok) window.close();
    else if (reply.error === "insecure_confirm") {
      dialog.remove();
      confirmFill(t("insecureFillWarning", view.pageHost ?? ""), { ...next, insecureConfirmed: true });
    } else {
      dialog.remove();
      toast(t("fillFailed"));
    }
  };
  if (also) {
    const alsoButton = el("button", { className: "secondary", type: "button", textContent: also.label });
    alsoButton.addEventListener("click", () => void run(also.request));
    actions.append(alsoButton);
  }
  actions.append(fillButton);
  fillButton.addEventListener("click", () => void run(request));
  cancel.addEventListener("click", () => {
    dialog.remove();
    searchInput.focus();
  });
  document.body.append(dialog);
  fillButton.focus();
}

function showItemMenu(anchor: HTMLElement, login: Login, details: Details) {
  const entries: (MenuEntry | "divider")[] = [
    { label: t("openInKeyless"), icon: ICONS.app, run: () => void send({ type: "open_app", id: login.id }).then(() => window.close()) },
  ];
  if (details.urls[0]) {
    const href = details.urls[0].href;
    entries.push({ label: t("openWebsite"), icon: ICONS.external, run: () => void chrome.tabs.create({ url: siteUrl(href) }).then(() => window.close()) });
  }
  if (!fillable(login) && view.pageHost) {
    // Saved for another site: only with a clear warning.
    entries.push({
      label: t("fill"),
      icon: ICONS.login,
      run: () =>
        confirmFill(
          t("otherSiteWarning", login.title, hostOf(details.urls[0]?.href ?? login.url), view.pageHost ?? ""),
          { type: "fill", id: login.id, anySite: true },
          { label: t("fillAndAddSite"), request: { type: "fill", id: login.id, anySite: true, addSite: true } },
        ),
    });
  }
  entries.push("divider");
  if (details.username) entries.push({ label: t("copyUsername"), icon: ICONS.copy, hint: "Ctrl C", run: () => copyField(login, "username") });
  if (details.hasPassword) entries.push({ label: t("copyPassword"), icon: ICONS.copy, hint: "Ctrl Shift C", run: () => copyField(login, "password") });
  if (details.totp) entries.push({ label: t("copyCode"), icon: ICONS.copy, hint: "Ctrl Alt C", run: () => copyField(login, "totp") });
  showMenu(anchor, entries);
}

function showNewItemMenu(anchor: HTMLElement) {
  const create = (category: string) => () => void send({ type: "new_item", category }).then(() => window.close());
  const entries: (MenuEntry | "divider" | { header: string })[] = [{ header: t("newItemHint") }];
  if (view.pageHost) entries.push({ label: t("newLoginFor", view.pageHost), icon: ICONS.sparkle, run: create("login") }, "divider");
  entries.push(
    { label: t("categoryLogin"), icon: ICONS.login, run: create("login") },
    { label: t("categoryPassword"), icon: ICONS.password, run: create("password") },
    { label: t("categorySecureNote"), icon: ICONS.note, run: create("secure_note") },
    { label: t("categoryCreditCard"), icon: ICONS.card, run: create("credit_card") },
    { label: t("categoryIdentity"), icon: ICONS.id, run: create("identity") },
  );
  showMenu(anchor, entries);
}

function showMainMenu(anchor: HTMLElement) {
  const entries: (MenuEntry | "divider" | { header: string })[] = [];
  if (status?.email) entries.push({ header: status.email });
  entries.push(
    { label: t("openApp"), icon: ICONS.app, run: () => void send({ type: "open_app" }).then(() => window.close()) },
    { label: t("generator"), icon: ICONS.key, hint: "Ctrl G", run: () => toggleGenerator(true) },
    ...(view.pageHost ? [{ label: t("scanPageQr"), icon: ICONS.qr, run: () => void scanPageQr() }] : []),
    { label: t("extensionSettings"), icon: ICONS.gear, run: () => void renderSettings() },
    "divider",
    { label: t("lockKeyless"), icon: ICONS.lock, hint: "Ctrl Shift L", run: () => void lock() },
  );
  showMenu(anchor, entries);
}

/** Reads the page's one-time password QR code (a site's two-factor setup)
 * and keeps it in one of the page's logins. */
async function scanPageQr() {
  const reply = await send<{ uri: string; issuer: string | null; account: string | null; logins: Login[] }>({ type: "scan_page_qr" });
  if (!reply.ok || !reply.data) return toast(t("qrNotFound"));
  const { uri, issuer, account, logins } = reply.data;
  const label = [issuer, account].filter(Boolean).join(" · ");
  const list = el("div", { className: "dialog-list" });
  const dialog = el(
    "div",
    { className: "dialog-backdrop" },
    el("div", { className: "dialog", role: "dialog" }, el("p", { textContent: logins.length ? t("qrFoundChoose", label) : t("qrFoundNoLogin", label) }), list),
  );
  const close = () => dialog.remove();
  for (const login of logins) {
    const row = el("button", { className: "secondary", type: "button", textContent: login.username ? `${login.title} · ${login.username}` : login.title });
    row.addEventListener("click", async () => {
      const saved = await send({ type: "save_totp", id: login.id, uri });
      close();
      toast(saved.ok ? t("codeSaved", login.title) : t("errorTitle"));
    });
    list.append(row);
  }
  const cancel = el("button", { className: "secondary", type: "button", textContent: t("cancel") });
  cancel.addEventListener("click", close);
  list.append(cancel);
  document.body.append(dialog);
}

async function lock() {
  await send({ type: "lock" });
  void render();
}

// ----- Password generator ----------------------------------------------------------

type GeneratorKind = "random" | "memorable" | "pin";

const generator = {
  kind: "random" as GeneratorKind,
  length: 20,
  words: 4,
  pinLength: 6,
  digits: true,
  symbols: true,
  capitalize: true,
  includeNumber: true,
  password: "",
};

/** Same words as the app's strength meter, from the generator's entropy. */
function strengthLabel(bits: number): { level: number; text: string } {
  const thresholds = [10, 20, 26.6, 33.2, 39.9, 53.2];
  const level = thresholds.findIndex((limit) => bits < limit);
  const final = level === -1 ? 6 : level;
  return { level: final, text: t(`strength${final}`) };
}

function generatorOptions(): Record<string, unknown> {
  switch (generator.kind) {
    case "memorable":
      return { kind: "memorable", words: generator.words, separator: "-", capitalize: generator.capitalize, include_number: generator.includeNumber };
    case "pin":
      return { kind: "pin", length: generator.pinLength };
    default:
      return { kind: "random", length: generator.length, uppercase: true, lowercase: true, digits: generator.digits, symbols: generator.symbols, avoid_ambiguous: true };
  }
}

function toggleGenerator(open = !view.generatorOpen) {
  view.generatorOpen = open;
  clearInterval(totpTimer);
  if (open) void renderGenerator();
  else void showSelected();
}

async function renderGenerator() {
  const output = el("div", { className: "generated" });
  const meter = el("div", { className: "meter" });
  const meterText = el("span", { className: "meter-text" });

  const generate = async () => {
    const reply = await send<{ password: string; entropyBits: number }>({ type: "generate", options: generatorOptions() });
    if (!reply.ok || !reply.data) return toast(t("errorTitle"));
    generator.password = reply.data.password;
    output.replaceChildren(coloredSecret(generator.password));
    const strength = strengthLabel(reply.data.entropyBits);
    meter.replaceChildren(...Array.from({ length: 7 }, (_, i) => el("span", { className: i <= strength.level ? `on level-${strength.level}` : "" })));
    meterText.textContent = strength.text;
    meterText.className = `meter-text level-${strength.level}`;
  };

  const kinds = el("div", { className: "segmented", role: "radiogroup" });
  for (const kind of ["random", "memorable", "pin"] as GeneratorKind[]) {
    const button = el("button", { type: "button", className: kind === generator.kind ? "on" : "", textContent: t(`gen_${kind}`) });
    button.setAttribute("role", "radio");
    button.setAttribute("aria-checked", String(kind === generator.kind));
    button.addEventListener("click", () => {
      generator.kind = kind;
      void renderGenerator();
    });
    kinds.append(button);
  }

  const slider = (label: string, value: number, min: number, max: number, change: (n: number) => void) => {
    const shown = el("span", { className: "slider-value", textContent: String(value) });
    const input = el("input", { type: "range", min: String(min), max: String(max), value: String(value) });
    input.setAttribute("aria-label", label);
    input.addEventListener("input", () => {
      shown.textContent = input.value;
      change(Number(input.value));
      void generate();
    });
    return el("div", { className: "option" }, el("div", { className: "option-head" }, el("span", { textContent: label }), shown), input);
  };
  const toggle = (label: string, checked: boolean, change: (on: boolean) => void) => {
    const box = el("input", { type: "checkbox", checked, className: "switch" });
    box.addEventListener("change", () => {
      change(box.checked);
      void generate();
    });
    return el("label", { className: "option toggle" }, el("span", { textContent: label }), box);
  };

  const options = el("div", { className: "options" });
  if (generator.kind === "random") {
    options.append(
      slider(t("genLength"), generator.length, 8, 64, (n) => (generator.length = n)),
      toggle(t("genDigits"), generator.digits, (on) => (generator.digits = on)),
      toggle(t("symbols"), generator.symbols, (on) => (generator.symbols = on)),
    );
  } else if (generator.kind === "memorable") {
    options.append(
      slider(t("genWords"), generator.words, 3, 10, (n) => (generator.words = n)),
      toggle(t("genCapitalize"), generator.capitalize, (on) => (generator.capitalize = on)),
      toggle(t("genIncludeNumber"), generator.includeNumber, (on) => (generator.includeNumber = on)),
    );
  } else {
    options.append(slider(t("genLength"), generator.pinLength, 4, 12, (n) => (generator.pinLength = n)));
  }

  const copy = el("button", { className: "primary", type: "button", textContent: t("copy") });
  copy.addEventListener("click", async () => {
    if (generator.password) copiedToast(await send<{ clearAfterSeconds: number }>({ type: "copy_generated", password: generator.password }));
  });
  const again = iconButton(ICONS.refresh, t("genAgain"), () => void generate(), "secondary icon-text");
  again.append(el("span", { textContent: t("genAgain") }));

  detailPane.replaceChildren(
    el(
      "div",
      { className: "detail-scroll generator" },
      el("div", { className: "sheet-head" }, el("h1", { textContent: t("generator") }), iconButton(ICONS.close, t("close"), () => toggleGenerator(false))),
      output,
      el("div", { className: "meter-row" }, meter, meterText),
      kinds,
      options,
      el("div", { className: "sheet-actions" }, again, copy),
      el("p", { className: "meta", textContent: t("genHistoryNote") }),
    ),
  );
  await generate();
}

// ----- Keyboard -------------------------------------------------------------------

document.addEventListener("keydown", (e) => {
  // Only in the vault view (not the settings or a message).
  if (!document.querySelector(".frame.vault")) return;
  if (document.querySelector(".dialog-backdrop")) {
    if (e.key === "Escape") {
      e.preventDefault();
      document.querySelector(".dialog-backdrop")?.remove();
      searchInput.focus();
    }
    return;
  }
  if (openMenu) {
    const entries = [...openMenu.querySelectorAll<HTMLElement>(".menu-item")];
    const at = entries.indexOf(document.activeElement as HTMLElement);
    if (e.key === "Escape") {
      e.preventDefault();
      closeMenu();
      searchInput.focus();
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      entries[(at + (e.key === "ArrowDown" ? 1 : entries.length - 1)) % entries.length]?.focus();
    }
    return;
  }
  const ctrl = e.ctrlKey || e.metaKey;
  const key = e.key.toLowerCase();
  const login = selectedLogin();
  const inSearch = document.activeElement === searchInput;
  const textSelected = inSearch && searchInput.selectionStart !== searchInput.selectionEnd;

  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    if (view.generatorOpen && !inSearch) return;
    e.preventDefault();
    select(Math.max(0, Math.min(view.items.length - 1, view.selected + (e.key === "ArrowDown" ? 1 : -1))));
  } else if (e.key === "Enter" && (inSearch || document.activeElement === document.body) && !view.generatorOpen) {
    e.preventDefault();
    void defaultAction();
  } else if (e.key === "Escape") {
    e.preventDefault();
    if (view.generatorOpen) toggleGenerator(false);
    else if (searchInput.value) {
      searchInput.value = "";
      view.query = "";
      void loadList();
    } else window.close();
  } else if (ctrl && key === "f") {
    e.preventDefault();
    searchInput.focus();
    searchInput.select();
  } else if (ctrl && key === "g") {
    e.preventDefault();
    toggleGenerator();
  } else if (ctrl && e.shiftKey && key === "l") {
    e.preventDefault();
    void lock();
  } else if (ctrl && key === "c" && login && !textSelected && !view.generatorOpen) {
    const which = e.altKey ? "totp" : e.shiftKey ? "password" : "username";
    if (which === "totp" && !view.details?.totp) return;
    e.preventDefault();
    copyField(login, which);
  }
});

// ----- Extension settings ---------------------------------------------------------------

async function renderSettings() {
  const reply = await send<{ settings: Settings; site: string | null; vaults: { id: string; name: string }[] }>({ type: "settings" });
  if (!reply.ok || !reply.data) return toast(t("errorTitle"));
  let { settings } = reply.data;
  const { site, vaults } = reply.data;
  const save = async (patch: Partial<Settings>) => {
    const saved = await send<Settings>({ type: "set_settings", settings: patch });
    if (saved.ok && saved.data) settings = saved.data;
    else toast(t("errorTitle"));
  };

  const toggle = (label: string, checked: boolean, change: (value: boolean) => Promise<void>) => {
    const box = el("input", { type: "checkbox", checked, className: "switch" });
    box.addEventListener("change", async () => {
      box.disabled = true;
      await change(box.checked);
      box.disabled = false;
    });
    return el("label", { className: "setting" }, el("span", { textContent: label }), box);
  };
  const group = (title: string, ...rows: Node[]) => el("div", { className: "settings-group" }, el("div", { className: "section", textContent: title }), el("div", { className: "card" }, ...rows));

  const body = el("div", { className: "settings" });
  if (site) {
    body.append(
      group(
        t("onSite", site),
        toggle(t("siteShow"), !settings.hidden.includes(site), async (show) => {
          await save({ hidden: show ? settings.hidden.filter((s) => s !== site) : [...settings.hidden, site] });
          void renderSettings();
        }),
        toggle(t("siteSave"), !settings.neverSave.includes(site), async (offer) => {
          await save({ neverSave: offer ? settings.neverSave.filter((s) => s !== site) : [...settings.neverSave, site] });
          void renderSettings();
        }),
      ),
    );
  }

  body.append(
    group(
      t("inPages"),
      toggle(t("setOfferSave"), settings.offerSave, (value) => save({ offerSave: value })),
      toggle(t("setSignInCard"), settings.signInCard, (value) => save({ signInCard: value })),
      toggle(t("setAutoOpen"), settings.autoOpen, (value) => save({ autoOpen: value })),
      toggle(t("setAutoSubmit"), settings.autoSubmit, (value) => save({ autoSubmit: value })),
      toggle(t("setCopyTotp"), settings.copyTotp, (value) => save({ copyTotp: value })),
      toggle(t("setPasskeys"), settings.passkeys, (value) => save({ passkeys: value })),
      toggle(t("setBreachWarnings"), settings.breachWarnings, (value) => save({ breachWarnings: value })),
      toggle(t("setConfirmFormFill"), settings.confirmFormFill, (value) => save({ confirmFormFill: value })),
      toggle(t("setPasteWarnings"), settings.pasteWarnings, (value) => save({ pasteWarnings: value })),
    ),
  );

  // Which vaults this browser fills from (a work browser, say, only the
  // work vault). None ticked would be all: the last one stays ticked.
  if (vaults.length > 1) {
    const chosen = () => (settings.vaults.length ? settings.vaults.filter((id) => vaults.some((v) => v.id === id)) : vaults.map((v) => v.id));
    body.append(
      group(
        t("vaultsInBrowser"),
        ...vaults.map((vault) =>
          toggle(vault.name, chosen().includes(vault.id), async (on) => {
            const next = on ? [...chosen(), vault.id] : chosen().filter((id) => id !== vault.id);
            if (next.length === 0) return void renderSettings();
            await save({ vaults: next.length === vaults.length ? [] : next });
          }),
        ),
      ),
    );
  }

  // The browser's own password manager. Changed by the background script:
  // the browser's permission prompt closes the popup.
  const managerText = el("p", { className: "muted small" });
  const managerButton = el("button", { className: "secondary small", type: "button" });
  let manager: BrowserManager = "on";
  const showManager = async () => {
    manager = (await send<BrowserManager>({ type: "browser_manager" })).data ?? "on";
    const off = manager === "off" || manager === "off_browser";
    managerText.textContent = off ? t("browserManagerOff") : manager === "other" ? t("browserManagerOther") : t("browserManagerOn");
    managerButton.textContent = off ? t("turnOn") : t("turnOff");
    managerButton.hidden = manager === "other" || manager === "off_browser";
  };
  managerButton.addEventListener("click", () => {
    // Both started from the click itself, so the browser can ask for the
    // permission; the background script applies the change once granted.
    const done = send({ type: "set_browser_manager", enabled: manager === "off" });
    const granted = chrome.permissions.request({ permissions: ["privacy"] });
    void Promise.all([done, granted]).then(() => setTimeout(() => void showManager(), 300));
  });
  await showManager();
  body.append(group(t("browserSection"), el("div", { className: "setting column" }, el("strong", { textContent: t("browserManager") }), managerText, managerButton)));

  // Sites set aside, each removable.
  const siteList = (title: string, key: "hidden" | "neverSave") => {
    const rows: Node[] = [];
    if (settings[key].length === 0) rows.push(el("p", { className: "muted small setting", textContent: t("noSites") }));
    for (const entry of settings[key]) {
      rows.push(
        el(
          "div",
          { className: "setting site" },
          el("span", { textContent: entry }),
          iconButton(ICONS.remove, t("remove"), async () => {
            await save({ [key]: settings[key].filter((s) => s !== entry) });
            void renderSettings();
          }),
        ),
      );
    }
    return group(title, ...rows);
  };
  body.append(siteList(t("hiddenSites"), "hidden"), siteList(t("neverSaveSites"), "neverSave"));

  app.replaceChildren(
    el(
      "div",
      { className: "frame settings-frame" },
      el("header", { className: "top" }, iconButton(ICONS.back, t("back"), () => void render()), el("h1", { textContent: t("extensionSettings") })),
      body,
    ),
  );
}

void render();

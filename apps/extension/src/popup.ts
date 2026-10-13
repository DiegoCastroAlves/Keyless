// The window that opens from the Keyless button in the browser's toolbar.
//
// Two panes, like the app: the logins on the left (suggestions for the page
// first) and the chosen one on the right, with what can be copied and the
// button that fills it. The keyboard works as in the app: typing searches,
// the arrows move, Enter fills, Escape clears the search and then closes.

import { avatar, hostOf } from "./avatar";
import { renderMarkdown } from "./markdown";
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
  edit: icon('<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>', 15),
  archive: icon('<rect x="2" y="4" width="20" height="5" rx="1"/><path d="M4 9v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9M10 13h4"/>', 15),
  trash: icon('<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>', 15),
  download: icon('<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>', 15),
  map: icon('<path d="M9 4 3 6v14l6-2 6 2 6-2V4l-6 2z"/><path d="M9 4v14M15 6v14"/>', 15),
  large: icon('<path d="M4 18 8.5 6 13 18M5.6 14h5.8M15 18v-5.5a2.5 2.5 0 0 1 5 0V18M15 15.5h5"/>', 15),
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

/** A field as the app shows it here (see bridge/items_view.rs): secret
 * values only when the user asks for them. */
interface FieldView {
  id: string;
  label: string;
  kind: string;
  purpose: "username" | "password" | "other" | null;
  secret: boolean;
  empty: boolean;
  value?: string;
  totp?: { code: string; period: number; expiresIn: number };
  address?: Partial<Record<"street" | "line2" | "city" | "state" | "zip" | "country", string>>;
  geo?: string;
  link?: { id: string; title: string; subtitle: string };
}

/** Any item, as the details pane shows it. */
interface ItemView {
  id: string;
  title: string;
  subtitle: string;
  category: string;
  vault: string;
  favorite: boolean;
  archived: boolean;
  canEdit: boolean;
  tags: string[];
  urls: { href: string; label: string }[];
  sections: { title: string; fields: FieldView[] }[];
  notes: string;
  attachments: { id: string; name: string; size: number }[];
  history: { index: number; changedAt: number }[];
  passkeys: number;
  createdAt: number;
  updatedAt: number;
}

const LIST_KINDS: { kind: ListKind; label: string; icon: string }[] = [
  { kind: "suggestions", label: "listSuggestions", icon: ICONS.sparkle },
  { kind: "favorites", label: "listFavorites", icon: ICONS.star },
  { kind: "recent", label: "listRecent", icon: ICONS.clock },
  { kind: "all", label: "listAll", icon: ICONS.list },
];

/** The kinds of item and their icons, as in the app. */
const CATEGORY_ICONS: Record<string, string> = {
  login: ICONS.login,
  password: ICONS.password,
  secure_note: ICONS.note,
  credit_card: ICONS.card,
  identity: ICONS.id,
  bank_account: icon('<path d="M3 10h18M5 10v8M9 10v8M15 10v8M19 10v8M3 20h18M12 3 3 8h18z"/>', 15),
  api_credential: icon('<path d="M8 3H7a2 2 0 0 0-2 2v4a2 2 0 0 1-2 2 2 2 0 0 1 2 2v4a2 2 0 0 0 2 2h1M16 3h1a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2 2 2 0 0 0-2 2v4a2 2 0 0 1-2 2h-1"/>', 15),
  database: icon('<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>', 15),
  server: icon('<rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M7 7h.01M7 17h.01"/>', 15),
  ssh_key: icon('<path d="m4 17 6-6-6-6M12 19h8"/>', 15),
  software_license: icon('<circle cx="12" cy="9" r="6"/><path d="m8.5 14-1.5 8 5-3 5 3-1.5-8"/>', 15),
  wireless_router: icon('<path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a15 15 0 0 1 20 0M12 20h.01"/>', 15),
  email_account: icon('<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/>', 15),
  passport: icon('<rect x="4" y="2" width="16" height="20" rx="2"/><circle cx="12" cy="10" r="3"/><path d="M8 17h8"/>', 15),
  driver_license: icon('<rect x="2" y="5" width="20" height="14" rx="2"/><circle cx="8" cy="12" r="2"/><path d="M14 10h4M14 14h4"/>', 15),
  membership: icon('<path d="M3 9a2 2 0 0 0 0 6v3a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-3a2 2 0 0 0 0-6V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2zM13 4v16"/>', 15),
  crypto_wallet: icon('<path d="M20 7V5a2 2 0 0 0-2-2H5a2 2 0 0 0 0 4h15v14H5a2 2 0 0 1-2-2V5M16 14h.01"/>', 15),
  medical_record: icon('<path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1-1.1a5.5 5.5 0 0 0-7.8 7.8L12 21l8.8-8.6a5.5 5.5 0 0 0 0-7.8z"/>', 15),
  document: ICONS.note,
  other: icon('<circle cx="12" cy="12" r="9"/>', 15),
};

/** The kinds of item that fill sign-in forms (the app's `is_fillable`). */
const LOGIN_LIKE = new Set(["login", "password", "email_account", "server", "database", "api_credential"]);

const categoryName = (category: string) => chrome.i18n.getMessage(`cat_${category}`) || category;
const categoryIcon = (category: string) => CATEGORY_ICONS[category] ?? CATEGORY_ICONS.other;

/** A template's field label in the user's language, as the app shows it
 * (labels are kept as the English words). */
function fieldLabel(label: string): string {
  const key = `fl_${label.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").toLowerCase()}`;
  return (label && chrome.i18n.getMessage(key)) || label;
}

const view = {
  /** The page in the active tab, if it is a web page. */
  pageUrl: null as string | null,
  pageHost: null as string | null,
  /** Logins for the page (fillable as they are). */
  suggestions: [] as Login[],
  kind: "suggestions" as ListKind,
  /** In the list of all items: only this kind of item. */
  category: null as string | null,
  /** The kinds of item the vault has (for the list menu). */
  categories: [] as string[],
  query: "",
  items: [] as Login[],
  selected: 0,
  /** Items picked for an action on several (Ctrl or Shift and a click). */
  picked: new Set<string>(),
  details: null as ItemView | null,
  generatorOpen: false,
};

const fillable = (login: Login) => view.suggestions.some((s) => s.id === login.id);
const allFields = (item: ItemView) => item.sections.flatMap((s) => s.fields);
const byPurpose = (item: ItemView, purpose: "username" | "password") => allFields(item).find((f) => f.purpose === purpose && !f.empty);

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
  listPicker.addEventListener("click", () => void showListMenu());
  listBox = el("div", { className: "items", role: "listbox", tabIndex: -1 });
  listBox.setAttribute("aria-label", t("listAll"));
  listBox.setAttribute("aria-multiselectable", "true");
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
  // Suggestions first; with none for this page, the most recent items.
  view.kind = view.suggestions.length > 0 ? "suggestions" : "recent";
  await loadList();
}

/** Every item (not only logins), for the list of all items and its kinds. */
async function allItems(): Promise<Login[]> {
  const items = (await send<Login[]>({ type: "search", query: "", all: true, limit: 1000 })).data ?? [];
  const kinds = new Set(items.map((item) => item.category ?? "login"));
  view.categories = [...kinds].sort((a, b) => categoryName(a).localeCompare(categoryName(b)));
  return items;
}

async function loadList() {
  let items: Login[];
  if (view.query) {
    items = (await send<Login[]>({ type: "search", query: view.query, all: true, limit: 200 })).data ?? [];
  } else if (view.kind === "suggestions") {
    items = view.suggestions;
  } else if (view.kind === "favorites") {
    items = (await send<Login[]>({ type: "search", query: "", favorites: true, all: true, limit: 500 })).data ?? [];
  } else if (view.kind === "recent") {
    items = (await send<Login[]>({ type: "search", query: "", all: true, limit: 30 })).data ?? [];
  } else {
    items = (await allItems()).filter((item) => !view.category || (item.category ?? "login") === view.category);
    items.sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: "base" }));
  }
  view.items = items;
  view.selected = 0;
  view.picked.clear();
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
    const category = view.kind === "all" ? view.category : null;
    listPicker.replaceChildren(
      svg(category ? categoryIcon(category) : current.icon),
      el("span", { className: "grow", textContent: category ? categoryName(category) : t(current.label) }),
      el("span", { className: "count", textContent: String(view.items.length) }),
      svg(ICONS.chevron),
    );
    listPicker.disabled = false;
  }
}

async function showListMenu() {
  if (view.categories.length === 0) await allItems();
  const choose = (kind: ListKind, category: string | null) => () => {
    view.kind = kind;
    view.category = category;
    void loadList().then(() => searchInput.focus());
  };
  const entries: (MenuEntry | "divider" | { header: string })[] = LIST_KINDS.map((k) => ({ label: t(k.label), icon: k.icon, run: choose(k.kind, null) }));
  if (view.categories.length > 1) {
    entries.push({ header: t("listCategories") }, ...view.categories.map((category) => ({ label: categoryName(category), icon: categoryIcon(category), run: choose("all", category) })));
  }
  showMenu(listPicker, entries, "left");
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

const STAR_BADGE = `<svg viewBox="0 0 24 24" width="10" height="10"><path fill="currentColor" d="m12 2.5 2.9 6 6.6.9-4.8 4.6 1.2 6.5L12 17.4l-5.9 3.1 1.2-6.5L2.5 9.4l6.6-.9z"/></svg>`;

/** An item without a website: its kind's icon. */
function categoryAvatar(category: string, favorite: boolean): HTMLElement {
  const box = el("span", { className: "avatar glyph" }, svg(categoryIcon(category)));
  if (favorite) box.append(el("span", { className: "star" }, svg(STAR_BADGE)));
  return box;
}

function listAvatar(login: Login, pageUrl?: string): HTMLElement {
  const category = login.category ?? "login";
  return category === "login" || login.url ? avatar(login, pageUrl) : categoryAvatar(category, login.favorite);
}

function listRow(login: Login, index: number): HTMLElement {
  const canFill = fillable(login);
  const category = login.category ?? "login";
  const through = login.signInWith ? (login.providerAccount ? t("signInWithAccount", providerName(login.signInWith), login.providerAccount) : t("signInWith", providerName(login.signInWith))) : "";
  const sub = login.frame
    ? [login.username, t("inFrame", login.frame)].filter(Boolean).join(" · ")
    : through || login.username || (category === "login" ? login.vault : categoryName(category));
  const node = el(
    "div",
    { className: "item", role: "option", id: `item-${index}` },
    listAvatar(login, canFill ? (view.pageUrl ?? undefined) : undefined),
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
  node.addEventListener("click", (e) => {
    if (e.ctrlKey || e.metaKey) return pick(index, "toggle");
    if (e.shiftKey) return pick(index, "range");
    if (view.picked.size > 0) {
      view.picked.clear();
      markSelected();
      if (index === view.selected) return void showSelected();
    }
    select(index);
  });
  node.addEventListener("dblclick", () => void defaultAction());
  return node;
}

function markSelected() {
  listBox.querySelectorAll(".item").forEach((node, index) => {
    const on = index === view.selected;
    const picked = view.picked.has(view.items[index]?.id ?? "");
    node.classList.toggle("selected", on && view.picked.size === 0);
    node.classList.toggle("picked", picked);
    node.setAttribute("aria-selected", String(view.picked.size > 0 ? picked : on));
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

/** Ctrl and a click picks or leaves an item; Shift and a click, the items
 * from the selected one to it. Two or more: the actions for all of them. */
function pick(index: number, how: "toggle" | "range") {
  const ids = view.items.map((item) => item.id);
  if (view.picked.size === 0 && ids[view.selected]) view.picked.add(ids[view.selected]);
  if (how === "toggle") {
    if (view.picked.has(ids[index])) view.picked.delete(ids[index]);
    else view.picked.add(ids[index]);
  } else {
    view.picked = new Set(ids.slice(Math.min(view.selected, index), Math.max(view.selected, index) + 1));
  }
  if (view.picked.size >= 2) {
    markSelected();
    renderBulk();
    return;
  }
  // One left: it is the selected item again.
  const at = ids.indexOf([...view.picked][0] ?? "");
  view.picked.clear();
  if (at >= 0) view.selected = at;
  markSelected();
  void showSelected();
}

const selectedLogin = (): Login | undefined => view.items[view.selected];

// ----- Several items ------------------------------------------------------------------

function renderBulk() {
  clearInterval(totpTimer);
  view.details = null;
  const ids = [...view.picked];
  const picked = view.items.filter((item) => view.picked.has(item.id));
  const allFavorite = picked.every((item) => item.favorite);
  const action = (label: string, markup: string, run: () => void, danger = false) => {
    const button = el("button", { className: `secondary${danger ? " danger" : ""}`, type: "button" }, svg(markup), el("span", { textContent: label }));
    button.addEventListener("click", run);
    return button;
  };
  detailPane.replaceChildren(
    el(
      "div",
      { className: "detail-scroll bulk" },
      el("div", { className: "bulk-head" }, el("h1", { textContent: t("selectedCount", String(ids.length)) }), el("p", { className: "muted small", textContent: t("selectionHint") })),
      el(
        "div",
        { className: "bulk-actions" },
        action(allFavorite ? t("favoriteRemove") : t("favoriteAdd"), ICONS.star, () => void changeItems(ids, "favorite", !allFavorite)),
        action(t("archive"), ICONS.archive, () => void changeItems(ids, "archive", true)),
        action(t("moveToTrash"), ICONS.trash, () => confirmTrash(ids, t("trashConfirmMany", String(ids.length))), true),
        action(t("clearSelection"), ICONS.close, () => {
          view.picked.clear();
          markSelected();
          void showSelected();
        }),
      ),
    ),
  );
}

/** Favorite, archive or move to the trash, then the list again (staying on
 * the same item when it is still there). */
async function changeItems(ids: string[], action: "favorite" | "archive" | "trash", on = true) {
  const reply = await send<{ changed: number }>({ type: "change_items", ids, action, on });
  if (!reply.ok) return toast(reply.error === "read_only" ? t("readOnlyVault") : t("errorTitle"));
  toast(t("doneShort"));
  // The page's suggestions too: archived and trashed items leave them.
  if (action === "favorite") view.suggestions.forEach((s) => ids.includes(s.id) && (s.favorite = on));
  else view.suggestions = view.suggestions.filter((s) => !ids.includes(s.id));
  const keep = view.items[view.selected]?.id;
  await loadList();
  const at = view.items.findIndex((item) => item.id === keep);
  if (at > 0) select(at);
}

function confirmTrash(ids: string[], text: string) {
  const go = el("button", { className: "primary danger", type: "button", textContent: t("moveToTrash") });
  const cancel = el("button", { className: "secondary", type: "button", textContent: t("cancel") });
  const dialog = el("div", { className: "dialog-backdrop" }, el("div", { className: "dialog", role: "alertdialog" }, el("p", { textContent: text }), el("div", { className: "dialog-actions" }, cancel, go)));
  cancel.addEventListener("click", () => {
    dialog.remove();
    searchInput.focus();
  });
  go.addEventListener("click", () => {
    dialog.remove();
    void changeItems(ids, "trash");
  });
  document.body.append(dialog);
  cancel.focus();
}

// ----- Details -------------------------------------------------------------------

let detailsRequest = 0;

async function showSelected() {
  clearInterval(totpTimer);
  if (view.generatorOpen) return;
  if (view.picked.size >= 2) return renderBulk();
  const login = selectedLogin();
  if (!login) {
    view.details = null;
    detailPane.replaceChildren(el("div", { className: "detail-empty" }, el("img", { src: "icons/icon-128.png", width: 44, height: 44, alt: "" }), el("p", { textContent: emptyText() })));
    return;
  }
  await showItem(login.id, login);
}

/** Shows an item: the list's, or one a field links to. */
async function showItem(id: string, login: Login | null = null) {
  clearInterval(totpTimer);
  const request = ++detailsRequest;
  const reply = await send<ItemView>({ type: "item_view", id });
  if (request !== detailsRequest) return;
  if (!reply.ok || !reply.data) {
    view.details = null;
    detailPane.replaceChildren(el("div", { className: "detail-empty" }, el("p", { textContent: t("errorBody") })));
    return;
  }
  view.details = reply.data;
  renderDetails(reply.data, login);
}

function field(label: string, value: Node, actions: HTMLElement[], copy?: () => void): HTMLElement {
  const row = el("div", { className: `field${copy ? " copyable" : ""}` }, el("span", { className: "label", textContent: label }), el("div", { className: "value" }, value), el("div", { className: "field-actions" }, ...actions));
  if (copy) {
    row.title = t("copy");
    row.addEventListener("click", (e) => {
      if ((e.target as HTMLElement).closest("button, a")) return;
      copy();
    });
  }
  return row;
}

/** Copied by the app (cleared after a while, kept out of history). */
function copyFrom(itemId: string, what: { field?: "username" | "password" | "totp"; fieldId?: string; history?: number }) {
  void send<{ clearAfterSeconds: number }>({ type: "copy", id: itemId, ...what }).then(copiedToast);
}

async function revealed(itemId: string, what: { fieldId?: string; history?: number }): Promise<string | null> {
  const reply = await send<{ value: string }>({ type: "reveal", id: itemId, ...what });
  return reply.ok && reply.data ? reply.data.value : null;
}

function totpRing(expiresIn: number, period: number): HTMLElement {
  const fraction = Math.max(0, Math.min(1, expiresIn / period));
  const circumference = 2 * Math.PI * 8;
  const ring = svg(
    `<svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-opacity="0.2" stroke-width="2.4"/><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" transform="rotate(-90 10 10)" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${(circumference * (1 - fraction)).toFixed(2)}"/></svg>`,
  );
  return el("span", { className: `ring${expiresIn <= 5 ? " ending" : ""}` }, ring, el("span", { textContent: String(expiresIn) }));
}

/** A secret shown as dots, with buttons to see it, see it large and copy
 * it; the app sends it only when asked. */
function secretRow(label: string, itemId: string, what: { fieldId?: string; history?: number }): HTMLElement {
  const value = el("span", { className: "dots", textContent: "••••••••••••" });
  let shown = false;
  const eye = iconButton(
    ICONS.eye,
    t("reveal"),
    async () => {
      if (shown) {
        shown = false;
        value.className = "dots";
        value.replaceChildren("••••••••••••");
      } else {
        const text = await revealed(itemId, what);
        if (text === null) return toast(t("errorTitle"));
        shown = true;
        value.className = "revealed";
        value.replaceChildren(coloredSecret(text));
      }
      eye.replaceChildren(svg(shown ? ICONS.eyeOff : ICONS.eye));
      eye.title = shown ? t("conceal") : t("reveal");
    },
    "tool small",
  );
  const large = iconButton(ICONS.large, t("largeType"), () => void largeType(label, () => revealed(itemId, what)), "tool small");
  const copy = () => copyFrom(itemId, what);
  return field(label, value, [eye, large, iconButton(ICONS.copy, t("copy"), copy, "tool small")], copy);
}

/** A field that is shown as it is. */
function plainRow(label: string, itemId: string, f: FieldView, shown: Node, extra: HTMLElement[] = []): HTMLElement {
  const copy = () => copyFrom(itemId, { fieldId: f.id });
  const text = f.value ?? "";
  const large = text ? [iconButton(ICONS.large, t("largeType"), () => void largeType(label, async () => text), "tool small")] : [];
  return field(label, shown, [...extra, ...large, iconButton(ICONS.copy, t("copy"), copy, "tool small")], copy);
}

function formatDate(value: string): string {
  const day = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value.trim());
  if (!day) return value;
  const date = new Date(Number(day[1]), Number(day[2]) - 1, Number(day[3]));
  return new Intl.DateTimeFormat(chrome.i18n.getUILanguage(), { dateStyle: "medium" }).format(date);
}

/** A map of the place: by its coordinates when known, otherwise by text
 * (OpenStreetMap, as the app does by default). */
function openMap(query: string, geo: string) {
  const point = geo.match(/^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$/);
  const url = point
    ? `https://www.openstreetmap.org/?mlat=${point[1]}&mlon=${point[2]}#map=17/${point[1]}/${point[2]}`
    : `https://www.openstreetmap.org/search?query=${encodeURIComponent(query)}`;
  void chrome.tabs.create({ url }).then(() => window.close());
}

function addressLines(f: FieldView): string[] {
  const a = f.address;
  if (!a) return (f.value ?? "").split("\n").filter(Boolean);
  const town = [a.zip, a.city].filter(Boolean).join(" ");
  return [a.street, a.line2, town, a.state, a.country].filter((line): line is string => Boolean(line));
}

function fieldRow(item: ItemView, f: FieldView): HTMLElement {
  const label = fieldLabel(f.label) || categoryName(item.category);
  if (f.totp) {
    let { code, period, expiresIn } = f.totp;
    const value = el("span", { className: "code-value" });
    const showCode = () => {
      value.replaceChildren(el("span", { className: "mono", textContent: code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code }), totpRing(expiresIn, period));
    };
    showCode();
    totpTimer = setInterval(async () => {
      expiresIn -= 1;
      if (expiresIn <= 0) {
        const fresh = await send<ItemView>({ type: "item_view", id: item.id });
        const next = fresh.data && allFields(fresh.data).find((other) => other.id === f.id)?.totp;
        if (!next || view.details?.id !== item.id) return;
        ({ code, period, expiresIn } = next);
      }
      showCode();
    }, 1000);
    const copy = () => copyFrom(item.id, { fieldId: f.id });
    return field(label, value, [iconButton(ICONS.copy, t("copy"), copy, "tool small")], copy);
  }
  if (f.secret) return secretRow(label, item.id, { fieldId: f.id });
  const text = f.value ?? "";
  switch (f.kind) {
    case "url": {
      const link = el("a", { className: "link", href: siteUrl(text), textContent: text, title: text });
      link.addEventListener("click", (e) => {
        e.preventDefault();
        void chrome.tabs.create({ url: siteUrl(text) }).then(() => window.close());
      });
      return plainRow(label, item.id, f, link);
    }
    case "address":
    case "location": {
      const lines = addressLines(f);
      const shown = el("span", { className: "multiline", textContent: lines.join("\n") || f.geo || "" });
      const map = iconButton(ICONS.map, t("openMap"), () => openMap(lines.join(", "), f.geo ?? ""), "tool small");
      return plainRow(label, item.id, { ...f, value: lines.join("\n") }, shown, [map]);
    }
    case "sign_in_with": {
      const shown = el("span", { textContent: [providerName(text), f.link?.subtitle].filter(Boolean).join(" · ") });
      const show = f.link ? [iconButton(ICONS.external, t("showItem"), () => void showItem(f.link!.id), "tool small")] : [];
      return field(label, shown, show);
    }
    case "reference": {
      if (!f.link) return field(label, document.createTextNode("—"), []);
      const link = el("a", { className: "link", href: "#", textContent: f.link.title });
      link.addEventListener("click", (e) => {
        e.preventDefault();
        void showItem(f.link!.id);
      });
      return field(label, link, []);
    }
    case "date":
      return plainRow(label, item.id, f, document.createTextNode(formatDate(text)));
    case "multiline":
      return plainRow(label, item.id, f, el("span", { className: "multiline", textContent: text }));
    default:
      return plainRow(label, item.id, f, document.createTextNode(text));
  }
}

/** A value in large letters, each with its position: to read it out or
 * type it on another device. */
async function largeType(label: string, value: () => Promise<string | null>) {
  const text = await value();
  if (text === null) return toast(t("errorTitle"));
  const cells = el("div", { className: "large-cells" });
  [...text].forEach((ch, index) => {
    const kind = /[0-9]/.test(ch) ? " digit" : /[\p{L}]/u.test(ch) ? "" : " symbol";
    const shown = ch === " " ? "␣" : ch === "\n" ? "↵" : ch;
    cells.append(el("span", { className: `large-cell${kind}` }, el("span", { className: "large-char", textContent: shown }), el("span", { className: "large-index", textContent: String(index + 1) })));
  });
  const close = el("button", { className: "secondary", type: "button", textContent: t("close") });
  const dialog = el(
    "div",
    { className: "dialog-backdrop" },
    el("div", { className: "dialog large-type", role: "dialog" }, el("p", { className: "muted small", textContent: label }), cells, el("div", { className: "dialog-actions" }, close)),
  );
  close.addEventListener("click", () => {
    dialog.remove();
    searchInput.focus();
  });
  dialog.addEventListener("click", (e) => e.target === dialog && close.click());
  document.body.append(dialog);
  close.focus();
}

function formatSize(bytes: number): string {
  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  return `${new Intl.NumberFormat(chrome.i18n.getUILanguage(), { maximumFractionDigits: unit === 0 ? 0 : 1 }).format(size)} ${units[unit]}`;
}

function formatTime(seconds: number): string {
  return new Intl.DateTimeFormat(chrome.i18n.getUILanguage(), { dateStyle: "medium", timeStyle: "short" }).format(new Date(seconds * 1000));
}

/** Links in notes: web pages in a new tab, other items here. */
function openLink(href: string) {
  const item = /^keyless:\/\/item\/([A-Za-z0-9-]{1,64})\/?$/i.exec(href);
  if (item) return void showItem(item[1]);
  void chrome.tabs.create({ url: href }).then(() => window.close());
}

function renderDetails(item: ItemView, login: Login | null) {
  const canFill = login !== null && fillable(login);
  const site = item.urls[0]?.href;
  const primary = el("button", { className: canFill ? "primary" : "outline", type: "button", textContent: primaryLabel(item, canFill) });
  primary.addEventListener("click", () => void primaryAction(item, login));
  const star = iconButton(ICONS.star, item.favorite ? t("favoriteRemove") : t("favoriteAdd"), () => void changeItems([item.id], "favorite", !item.favorite), `tool${item.favorite ? " on" : ""}`);
  star.hidden = !item.canEdit;
  const more = iconButton(ICONS.more, t("moreActions"), () => showItemMenu(more, item, login));

  const asLogin: Login = login ?? { id: item.id, title: item.title, username: item.subtitle, url: site ?? "", vault: item.vault, favorite: item.favorite };
  const head = item.category === "login" || site ? avatar({ ...asLogin, favorite: item.favorite }, canFill ? (view.pageUrl ?? undefined) : undefined) : categoryAvatar(item.category, item.favorite);
  const subtitle = [categoryName(item.category), item.vault ? t("inVault", item.vault) : "", item.archived ? t("archivedNote") : ""].filter(Boolean).join(" · ");
  const parts: (Node | null)[] = [
    el("div", { className: "detail-head" }, head, el("div", { className: "head-text" }, el("h1", { textContent: item.title }), el("p", { textContent: subtitle }))),
    el("div", { className: "detail-actions" }, primary, star, more),
  ];

  for (const section of item.sections) {
    const rows = section.fields.filter((f) => !f.empty || f.address || f.geo || f.totp).map((f) => fieldRow(item, f));
    if (rows.length === 0) continue;
    if (section.title) parts.push(el("div", { className: "section", textContent: section.title }));
    parts.push(el("div", { className: "card" }, ...rows));
  }
  if (item.passkeys > 0) parts.push(el("div", { className: "card" }, field(t("passkeyLabel"), document.createTextNode(t("passkeySaved")), [])));

  if (item.urls.length > 0) {
    const websites = el("div", { className: "card" });
    for (const url of item.urls) {
      const link = el("a", { className: "link", href: siteUrl(url.href), textContent: hostOf(url.href) || url.href, title: url.href });
      link.addEventListener("click", (e) => {
        e.preventDefault();
        void chrome.tabs.create({ url: siteUrl(url.href) }).then(() => window.close());
      });
      websites.append(field(url.label || t("fieldWebsite"), link, []));
    }
    parts.push(websites);
  }

  if (item.notes.trim()) parts.push(el("div", { className: "section", textContent: t("notesTitle") }), el("div", { className: "card notes" }, renderMarkdown(item.notes, openLink)));

  if (item.attachments.length > 0) {
    const files = el("div", { className: "card" });
    for (const file of item.attachments) {
      const save = iconButton(
        ICONS.download,
        `${t("saveFile")} · ${t("saveFileHint")}`,
        () => void send({ type: "save_attachment", id: item.id, attachmentId: file.id, title: t("saveFileTitle") }).then((reply) => !reply.ok && toast(t("errorTitle"))),
        "tool small",
      );
      files.append(field(formatSize(file.size), el("span", { textContent: file.name, title: file.name }), [save]));
    }
    parts.push(el("div", { className: "section", textContent: t("attachmentsTitle") }), files);
  }

  if (item.history.length > 0) {
    const list = el("div", { className: "card" });
    list.hidden = true;
    for (const entry of [...item.history].sort((a, b) => b.changedAt - a.changedAt)) {
      list.append(secretRow(formatTime(entry.changedAt), item.id, { history: entry.index }));
    }
    const toggle = el("button", { className: "section toggle", type: "button" }, el("span", { textContent: `${t("passwordHistory")} (${item.history.length})` }), svg(ICONS.chevron));
    toggle.addEventListener("click", () => (list.hidden = !list.hidden));
    parts.push(toggle, list);
  }

  if (item.tags.length > 0) parts.push(el("div", { className: "tags", title: t("tagsTitle") }, ...item.tags.map((tag) => el("span", { className: "tag", textContent: tag }))));

  const dates = [item.updatedAt > 0 ? t("modifiedOn", formatTime(item.updatedAt)) : "", item.createdAt > 0 ? t("createdOn", formatTime(item.createdAt)) : ""].filter(Boolean);
  for (const line of dates) parts.push(el("p", { className: "meta", textContent: line }));
  detailPane.replaceChildren(el("div", { className: "detail-scroll" }, ...parts));
}

function primaryLabel(item: ItemView, canFill: boolean): string {
  if (canFill) return t("fillShort");
  if (LOGIN_LIKE.has(item.category) && item.urls[0]) return t("openFill");
  return item.canEdit ? t("editInKeyless") : t("openInKeyless");
}

/** Fills the login, or opens its website and fills it there; other items
 * open in Keyless (in its editor when the vault allows). */
async function primaryAction(item: ItemView | null, login: Login | null) {
  if (login && fillable(login)) return fill(login);
  if (!item) return;
  const site = item.urls[0]?.href;
  if (LOGIN_LIKE.has(item.category) && site) {
    const reply = await send({ type: "open_fill", id: item.id, url: siteUrl(site) });
    if (reply.ok) window.close();
    else toast(t("fillFailed"));
  } else if (item.canEdit) {
    await editItem(item.id);
  } else {
    await send({ type: "open_app", id: item.id });
    window.close();
  }
}

async function editItem(id: string) {
  const reply = await send({ type: "edit_item", id });
  if (reply.ok) window.close();
  else toast(t("errorTitle"));
}

async function defaultAction() {
  if (view.picked.size >= 2) return;
  const login = selectedLogin() ?? null;
  const item = view.details && (!login || view.details.id === login.id) ? view.details : null;
  return primaryAction(item, login);
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

function showItemMenu(anchor: HTMLElement, item: ItemView, login: Login | null) {
  const entries: (MenuEntry | "divider")[] = [];
  if (item.canEdit) entries.push({ label: t("editInKeyless"), icon: ICONS.edit, run: () => void editItem(item.id) });
  entries.push({ label: t("openInKeyless"), icon: ICONS.app, run: () => void send({ type: "open_app", id: item.id }).then(() => window.close()) });
  if (item.urls[0]) {
    const href = item.urls[0].href;
    entries.push({ label: t("openWebsite"), icon: ICONS.external, run: () => void chrome.tabs.create({ url: siteUrl(href) }).then(() => window.close()) });
  }
  if (login && !fillable(login) && view.pageHost && LOGIN_LIKE.has(item.category)) {
    // Saved for another site: only with a clear warning.
    entries.push({
      label: t("fill"),
      icon: ICONS.login,
      run: () =>
        confirmFill(
          t("otherSiteWarning", item.title, hostOf(item.urls[0]?.href ?? login.url), view.pageHost ?? ""),
          { type: "fill", id: item.id, anySite: true },
          { label: t("fillAndAddSite"), request: { type: "fill", id: item.id, anySite: true, addSite: true } },
        ),
    });
  }
  const username = byPurpose(item, "username");
  const password = byPurpose(item, "password");
  const code = allFields(item).find((f) => f.totp);
  if (username || password || code) entries.push("divider");
  if (username) entries.push({ label: t("copyUsername"), icon: ICONS.copy, hint: "Ctrl C", run: () => copyFrom(item.id, { fieldId: username.id }) });
  if (password) entries.push({ label: t("copyPassword"), icon: ICONS.copy, hint: "Ctrl Shift C", run: () => copyFrom(item.id, { fieldId: password.id }) });
  if (code) entries.push({ label: t("copyCode"), icon: ICONS.copy, hint: "Ctrl Alt C", run: () => copyFrom(item.id, { fieldId: code.id }) });
  if (item.canEdit) {
    entries.push(
      "divider",
      { label: item.archived ? t("unarchive") : t("archive"), icon: ICONS.archive, run: () => void changeItems([item.id], "archive", !item.archived) },
      { label: t("moveToTrash"), icon: ICONS.trash, danger: true, run: () => confirmTrash([item.id], t("trashConfirmOne", item.title)) },
    );
  }
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
    else if (view.picked.size > 0) {
      view.picked.clear();
      markSelected();
      void showSelected();
    } else if (searchInput.value) {
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
  } else if (ctrl && key === "c" && view.details && !textSelected && !view.generatorOpen && view.picked.size === 0) {
    // The username, the password or the code of the item shown.
    const item = view.details;
    const chosen = e.altKey ? allFields(item).find((f) => f.totp) : byPurpose(item, e.shiftKey ? "password" : "username");
    if (!chosen) return;
    e.preventDefault();
    copyFrom(item.id, { fieldId: chosen.id });
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

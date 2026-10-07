import { avatar, hostOf } from "./avatar";
import type { Settings } from "./settings";
import type { BrowserManager, Login, Status } from "./types";

const t = (key: string, ...subs: string[]) => chrome.i18n.getMessage(key, subs) || key;
const app = document.getElementById("app")!;

type Reply<T> = { ok: boolean; data?: T; error?: string };
const send = <T>(message: unknown): Promise<Reply<T>> => chrome.runtime.sendMessage(message);

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
  const node = Object.assign(document.createElement(tag), props) as HTMLElementTagNameMap[K];
  node.append(...children);
  return node;
}

function toast(text: string) {
  const node = el("div", { className: "toast", textContent: text });
  document.body.append(node);
  setTimeout(() => node.remove(), 2200);
}

const ICON_GEAR = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>`;
const ICON_BACK = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg>`;
const ICON_REMOVE = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>`;

function iconButton(markup: string, title: string, run: () => void): HTMLButtonElement {
  const button = el("button", { className: "icon", type: "button", title });
  button.setAttribute("aria-label", title);
  button.innerHTML = markup;
  button.addEventListener("click", run);
  return button;
}

function shell(...content: (Node | string)[]) {
  app.replaceChildren(
    el(
      "header",
      {},
      el("img", { src: "icons/icon-32.png", width: 22, height: 22, alt: "" }),
      el("strong", { textContent: "Keyless" }),
      el("span", { className: "grow" }),
      iconButton(ICON_GEAR, t("settings"), () => void renderSettings()),
    ),
    ...content,
  );
}

function message(title: string, body: string, action?: { label: string; run: () => Promise<void> }) {
  const parts: Node[] = [el("h2", { textContent: title }), el("p", { textContent: body })];
  if (action) {
    const button = el("button", { className: "primary", textContent: action.label });
    button.addEventListener("click", async () => {
      button.disabled = true;
      await action.run();
      button.disabled = false;
    });
    parts.push(button);
  }
  shell(el("section", { className: "state" }, ...parts));
}

async function render() {
  const reply = await send<Status>({ type: "status" });
  const status = reply.data ?? { state: "error" };
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
    case "locked":
      return renderLocked();
    case "ready":
      return renderVault();
    default:
      return message(t("errorTitle"), t("errorBody"), { label: t("retry"), run: render });
  }
}

function renderPairing(code: string) {
  const button = el("button", { className: "primary", textContent: t("connect") });
  const hint = el("p", { className: "muted", textContent: t("pairHint") });
  button.addEventListener("click", async () => {
    button.disabled = true;
    hint.textContent = t("pairWaiting");
    const reply = await send<boolean>({ type: "pair" });
    if (reply.ok && reply.data) {
      void render();
    } else {
      hint.textContent = t("pairFailed");
      button.disabled = false;
    }
  });
  shell(
    el(
      "section",
      { className: "state" },
      el("h2", { textContent: t("pairTitle") }),
      el("p", { textContent: t("pairBody") }),
      el("div", { className: "code", textContent: code }),
      button,
      hint,
    ),
  );
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
  const hint = el("p", { textContent: t("lockedNote") });
  const button = el("button", { className: "primary", textContent: t("unlockApp") });
  const run = async (auto: boolean) => {
    button.disabled = true;
    hint.textContent = t("waitingUnlock");
    const reply = await send({ type: "unlock", auto });
    if (reply.ok) return render();
    button.disabled = false;
    hint.textContent = reply.error === "cancelled" || reply.error === "skipped" ? t("lockedNote") : unlockError(reply.error);
  };
  button.addEventListener("click", () => void run(false));
  shell(el("section", { className: "state" }, el("h2", { textContent: t("lockedTitle") }), hint, button));
  // Opening the popup is the request: Keyless asks right away.
  void run(true);
}

/** A login saved for another site: fill only after the user confirms. */
function confirmOtherSite(login: Login, node: HTMLElement, pageHost: string) {
  const fill = el("button", { className: "primary small", textContent: t("fillAnyway") });
  const cancel = el("button", { className: "secondary small", textContent: t("cancel") });
  const warning = el(
    "div",
    { className: "warn" },
    el("p", { textContent: t("otherSiteWarning", login.title, hostOf(login.url), pageHost) }),
    el("div", { className: "warn-actions" }, cancel, fill),
  );
  fill.addEventListener("click", async () => {
    const reply = await send({ type: "fill", id: login.id, anySite: true });
    if (reply.ok) window.close();
    else toast(t("fillFailed"));
  });
  cancel.addEventListener("click", () => {
    warning.replaceWith(node);
    node.focus();
  });
  node.replaceWith(warning);
  fill.focus();
}

/** The active tab, whose icon the matching logins show. */
let pageUrl: string | null = null;

function row(login: Login, canFill: boolean, pageHost: string | null = null): HTMLElement {
  const icon = avatar(login, canFill ? (pageUrl ?? undefined) : undefined);
  const text = el("span", { className: "text" }, el("span", { className: "title", textContent: login.title }), el("span", { className: "sub", textContent: login.username || login.vault }));
  const actions = el("span", { className: "actions" });
  const copy = (field: "username" | "password" | "totp", label: string, icon: string) => {
    const b = el("button", { className: "icon", title: label, innerHTML: icon });
    b.addEventListener("click", async (e) => {
      e.stopPropagation();
      const reply = await send<{ clearAfterSeconds: number }>({ type: "copy", id: login.id, field });
      toast(reply.ok ? t("copied", String(reply.data?.clearAfterSeconds ?? "")) : t("copyFailed"));
    });
    return b;
  };
  actions.append(
    copy("username", t("copyUsername"), ICON_USER),
    copy("password", t("copyPassword"), ICON_KEY),
    copy("totp", t("copyCode"), ICON_CLOCK),
  );
  const node = el("div", { className: `row${canFill ? " fillable" : ""}`, tabIndex: 0 }, icon, text, actions);
  if (canFill) {
    node.title = t("fill");
    const doFill = async () => {
      const reply = await send({ type: "fill", id: login.id });
      if (reply.ok) window.close();
      else toast(t("fillFailed"));
    };
    node.addEventListener("click", doFill);
    node.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void doFill();
    });
  } else if (pageHost) {
    node.classList.add("fillable");
    node.title = t("savedFor", hostOf(login.url));
    node.addEventListener("click", () => confirmOtherSite(login, node, pageHost));
    node.addEventListener("keydown", (e) => {
      if (e.key === "Enter") confirmOtherSite(login, node, pageHost);
    });
  }
  return node;
}

async function renderVault() {
  const search = el("input", { type: "search", placeholder: t("searchPlaceholder"), autofocus: true });
  const list = el("div", { className: "list" });
  shell(el("div", { className: "search" }, search), list);
  search.focus();

  const matches = await send<{ url: string | null; logins: Login[] }>({ type: "tab_matches" });
  pageUrl = matches.data?.url ?? null;
  const host = matches.data?.url ? new URL(matches.data.url).hostname.replace(/^www\./, "") : null;
  const suggestions = matches.data?.logins ?? [];

  const showSuggestions = () => {
    list.replaceChildren();
    if (host) list.append(el("div", { className: "section", textContent: t("suggestionsFor", host) }));
    if (suggestions.length === 0) list.append(el("p", { className: "muted pad", textContent: host ? t("noMatches") : t("searchHint") }));
    suggestions.forEach((login) => list.append(row(login, true)));
  };
  showSuggestions();

  let timer: ReturnType<typeof setTimeout> | undefined;
  search.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const query = search.value.trim();
      if (!query) return showSuggestions();
      const reply = await send<Login[]>({ type: "search", query });
      list.replaceChildren();
      const results = reply.data ?? [];
      if (results.length === 0) list.append(el("p", { className: "muted pad", textContent: t("noResults") }));
      const fillable = new Set(suggestions.map((s) => s.id));
      results.forEach((login) => list.append(row(login, fillable.has(login.id), host)));
    }, 150);
  });
}

// ----- Settings -------------------------------------------------------------------

async function renderSettings() {
  const reply = await send<{ settings: Settings; site: string | null }>({ type: "settings" });
  if (!reply.ok || !reply.data) return toast(t("errorTitle"));
  let { settings } = reply.data;
  const { site } = reply.data;
  const save = async (patch: Partial<Settings>) => {
    const saved = await send<Settings>({ type: "set_settings", settings: patch });
    if (saved.ok && saved.data) settings = saved.data;
    else toast(t("errorTitle"));
  };

  const toggle = (label: string, checked: boolean, change: (value: boolean) => Promise<void>) => {
    const box = el("input", { type: "checkbox", checked });
    box.addEventListener("change", async () => {
      box.disabled = true;
      await change(box.checked);
      box.disabled = false;
    });
    return el("label", { className: "setting" }, el("span", { textContent: label }), box);
  };

  const body = el("div", { className: "settings" });
  if (site) {
    body.append(
      el("div", { className: "section", textContent: t("onSite", site) }),
      toggle(t("siteShow"), !settings.hidden.includes(site), async (show) => {
        await save({ hidden: show ? settings.hidden.filter((s) => s !== site) : [...settings.hidden, site] });
        void renderSettings();
      }),
      toggle(t("siteSave"), !settings.neverSave.includes(site), async (offer) => {
        await save({ neverSave: offer ? settings.neverSave.filter((s) => s !== site) : [...settings.neverSave, site] });
        void renderSettings();
      }),
    );
  }

  body.append(
    el("div", { className: "section", textContent: t("inPages") }),
    toggle(t("setOfferSave"), settings.offerSave, (value) => save({ offerSave: value })),
    toggle(t("setSignInCard"), settings.signInCard, (value) => save({ signInCard: value })),
    toggle(t("setAutoOpen"), settings.autoOpen, (value) => save({ autoOpen: value })),
    toggle(t("setAutoSubmit"), settings.autoSubmit, (value) => save({ autoSubmit: value })),
    toggle(t("setCopyTotp"), settings.copyTotp, (value) => save({ copyTotp: value })),
  );

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
  body.append(
    el("div", { className: "section", textContent: t("browserSection") }),
    el("div", { className: "setting column" }, el("strong", { textContent: t("browserManager") }), managerText, managerButton),
  );

  // Sites set aside, each removable.
  const siteList = (title: string, key: "hidden" | "neverSave") => {
    const list = el("div", { className: "sites" });
    if (settings[key].length === 0) list.append(el("p", { className: "muted small pad", textContent: t("noSites") }));
    for (const entry of settings[key]) {
        list.append(
          el(
            "div",
            { className: "site" },
            el("span", { textContent: entry }),
            iconButton(ICON_REMOVE, t("remove"), async () => {
              await save({ [key]: settings[key].filter((s) => s !== entry) });
              void renderSettings();
            }),
          ),
        );
    }
    return [el("div", { className: "section", textContent: title }), list];
  };
  body.append(...siteList(t("hiddenSites"), "hidden"), ...siteList(t("neverSaveSites"), "neverSave"));

  app.replaceChildren(
    el("header", {}, iconButton(ICON_BACK, t("back"), () => void render()), el("strong", { textContent: t("settings") })),
    body,
  );
}

const ICON_USER = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>`;
const ICON_KEY = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M17 6l3 3M15 8l2 2"/></svg>`;
const ICON_CLOCK = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`;

void render();

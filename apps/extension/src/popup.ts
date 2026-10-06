import type { Login, Status } from "./types";

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

function shell(...content: (Node | string)[]) {
  app.replaceChildren(
    el("header", {}, el("img", { src: "icons/icon-32.png", width: 22, height: 22, alt: "" }), el("strong", { textContent: "Keyless" })),
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
      return message(t("lockedTitle"), t("lockedNote"), {
        label: t("unlockApp"),
        run: async () => {
          await send({ type: "show_app" });
          window.close();
        },
      });
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

function row(login: Login, canFill: boolean): HTMLElement {
  const avatar = el("span", { className: "avatar", textContent: (login.title.match(/[\p{L}\p{N}]/u)?.[0] ?? "?").toUpperCase() });
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
  const node = el("div", { className: `row${canFill ? " fillable" : ""}`, tabIndex: 0 }, avatar, text, actions);
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
  }
  return node;
}

async function renderVault() {
  const search = el("input", { type: "search", placeholder: t("searchPlaceholder"), autofocus: true });
  const list = el("div", { className: "list" });
  shell(el("div", { className: "search" }, search), list);
  search.focus();

  const matches = await send<{ url: string | null; logins: Login[] }>({ type: "tab_matches" });
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
      results.forEach((login) => list.append(row(login, fillable.has(login.id))));
    }, 150);
  });
}

const ICON_USER = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>`;
const ICON_KEY = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M17 6l3 3M15 8l2 2"/></svg>`;
const ICON_CLOCK = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`;

void render();

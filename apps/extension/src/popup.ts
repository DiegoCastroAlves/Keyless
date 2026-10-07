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
      return renderLocked(status);
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
    case "wrong_password":
      return t("wrongPassword");
    case "rate_limited":
      return t("rateLimited");
    case "busy":
      return t("unlockBusy");
    case "no_account":
      return t("noAccount");
    default:
      return t("unlockFailed");
  }
}

/** Unlocks Keyless without opening it: with the computer password (the
 * system shows its prompt) or the master password typed here. */
function renderLocked(status: Status) {
  const input = el("input", { type: "password", placeholder: t("masterPassword"), autocomplete: "current-password", spellcheck: false });
  const eye = el("button", { className: "icon eye", type: "button", title: t("showPassword"), innerHTML: ICON_EYE });
  eye.addEventListener("click", () => {
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    eye.innerHTML = hidden ? ICON_EYE_OFF : ICON_EYE;
    eye.title = hidden ? t("hidePassword") : t("showPassword");
    input.focus();
  });
  const submit = el("button", { className: "primary wide", type: "submit", textContent: t("unlock") });
  const error = el("p", { className: "error" });
  const form = el("form", { className: "unlock" }, el("div", { className: "password" }, input, eye), submit, error);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!input.value) return input.focus();
    submit.disabled = true;
    error.textContent = "";
    const reply = await send({ type: "unlock", password: input.value });
    if (reply.ok) {
      input.value = "";
      return render();
    }
    submit.disabled = false;
    error.textContent = unlockError(reply.error);
    // Kept so a typo can be fixed.
    input.focus();
    input.select();
  });

  const parts: Node[] = [el("h2", { textContent: t("lockedTitle") })];
  const hint = el("p", { className: "muted", textContent: t("lockedNote") });
  parts.push(hint);
  if (status.systemUnlock) {
    const system = el("button", { className: "secondary wide", type: "button", textContent: t("unlockWithSystem") });
    const runSystem = async (auto: boolean) => {
      system.disabled = true;
      hint.textContent = t("waitingSystem");
      const reply = await send({ type: "unlock_system", auto });
      system.disabled = false;
      if (reply.ok) return render();
      hint.textContent = reply.error === "cancelled" || reply.error === "skipped" ? t("lockedNote") : unlockError(reply.error);
      input.focus();
    };
    system.addEventListener("click", () => void runSystem(false));
    parts.push(system, el("div", { className: "or", textContent: t("or") }));
    // Like the app: the prompt comes up by itself.
    void runSystem(true);
  }
  parts.push(form);
  shell(el("section", { className: "state locked" }, ...parts));
  if (!status.systemUnlock) input.focus();
}

function hostOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
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

function row(login: Login, canFill: boolean, pageHost: string | null = null): HTMLElement {
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

const ICON_USER = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>`;
const ICON_KEY = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M17 6l3 3M15 8l2 2"/></svg>`;
const ICON_EYE = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>`;
const ICON_EYE_OFF = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.7 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-2.2 3.2M6.6 6.6C3.8 8.4 2 12 2 12s3.5 7 10 7c1.9 0 3.6-.6 5-1.5"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2M3 3l18 18"/></svg>`;
const ICON_CLOCK = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`;

void render();

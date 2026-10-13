// The Keyless window for a website's own sign-in dialog (HTTP Basic or
// Digest authentication; see background.ts): the user picks one of the
// site's logins, or leaves it to the browser's dialog. A separate window,
// so no page can cover it.

import { avatar } from "./avatar";
import type { Login } from "./types";

const t = (key: string, ...subs: string[]) => chrome.i18n.getMessage(key, subs) || key;
const app = document.getElementById("app")!;
const id = location.hash.slice(1);

type Reply<T> = { ok: boolean; data?: T; error?: string };
const send = <T>(message: Record<string, unknown>): Promise<Reply<T>> =>
  chrome.runtime.sendMessage({ ...message, id }).catch(() => ({ ok: false, error: "error" }));

interface View {
  host: string;
  realm: string;
  locked: boolean;
  logins: Login[];
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
  const node = Object.assign(document.createElement(tag), props) as HTMLElementTagNameMap[K];
  node.append(...children);
  return node;
}

function button(label: string, className: string, run: () => void): HTMLButtonElement {
  const b = el("button", { className, type: "button", textContent: label });
  b.addEventListener("click", run);
  return b;
}

async function act(type: string, extra: Record<string, unknown> = {}) {
  app.querySelectorAll("button").forEach((b) => (b.disabled = true));
  const reply = await send<View>({ type, ...extra });
  if (type === "auth_unlock" && reply.ok && reply.data) return render(reply.data);
  // Answered: the background script closes this window.
  if (!reply.ok) window.close();
}

function render(view: View) {
  const header = el("header", {}, el("img", { src: "icons/icon-32.png", width: 22, height: 22, alt: "" }), el("strong", { textContent: "Keyless" }));
  const browserDialog = button(t("authBrowser"), "link", () => void act("auth_browser"));
  const cancel = button(t("cancel"), "secondary", () => void act("auth_cancel"));
  const body = el("section", { className: "passkey-body" }, el("h2", { textContent: t("authTitle", view.host) }));
  if (view.realm) body.append(el("p", { className: "muted", textContent: t("authRealm", view.realm) }));
  let primary: HTMLButtonElement | null = null;
  if (view.locked) {
    body.append(el("p", { className: "muted", textContent: t("authLocked") }));
    primary = button(t("unlockApp"), "primary", () => void act("auth_unlock"));
  } else {
    const list = el("div", { className: "list" });
    for (const login of view.logins) {
      const row = el(
        "button",
        { className: "row fillable passkey-row", type: "button" },
        avatar(login, `https://${view.host}`),
        el("span", { className: "text" }, el("span", { className: "title", textContent: login.title }), el("span", { className: "sub", textContent: login.username || login.vault })),
      );
      row.addEventListener("click", () => void act("auth_choose", { itemId: login.id }));
      list.append(row);
    }
    body.append(el("p", { className: "muted", textContent: t("authHint") }), list);
  }
  const foot = el("div", { className: "passkey-foot" }, browserDialog, el("span", { className: "grow" }), cancel, ...(primary ? [primary] : []));
  app.replaceChildren(header, el("div", {}, body, foot));
}

async function load() {
  const reply = await send<View>({ type: "auth_view" });
  if (!reply.ok || !reply.data) return window.close();
  render(reply.data);
}

void load();

// The Keyless window for a site's passkey request (see background.ts): a
// separate browser window, so the page can neither cover it nor click in it.
// The user saves a passkey for the site (in a new login or one already saved
// for it), signs in with one, or hands the request back to the browser
// ("another device": a security key or a phone).

import { avatar } from "./avatar";
import type { Login } from "./types";

const t = (key: string, ...subs: string[]) => chrome.i18n.getMessage(key, subs) || key;
const app = document.getElementById("app")!;
const id = location.hash.slice(1);

type Reply<T> = { ok: boolean; data?: T; error?: string };
const send = <T>(message: Record<string, unknown>): Promise<Reply<T>> =>
  chrome.runtime.sendMessage({ ...message, id }).catch(() => ({ ok: false, error: "error" }));

interface PasskeyEntry {
  itemId: string;
  credentialId: string;
  title: string;
  userName: string;
}

interface View {
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

let busy = false;
async function act(type: string, extra: Record<string, unknown> = {}) {
  if (busy) return;
  busy = true;
  render(null, true);
  const reply = await send<View>({ type, ...extra });
  busy = false;
  if (type === "passkey_unlock" && reply.ok && reply.data) return render(reply.data);
  if (reply.ok) return; // The background script closes this window.
  if (reply.error === "expired") return window.close();
  void load(reply.error === "exists" ? t("pkExists") : t("pkFailed"));
}

function shell(title: string, sub: string, ...content: Node[]) {
  app.replaceChildren(
    el(
      "header",
      {},
      el("img", { src: "icons/icon-32.png", width: 22, height: 22, alt: "" }),
      el("strong", { textContent: "Keyless" }),
    ),
    el("section", { className: "passkey-body" }, el("h2", { textContent: title }), el("p", { className: "muted", textContent: sub }), ...content),
  );
}

function footer(primary?: HTMLButtonElement, exists = false) {
  const other = primary?.dataset.other ? [] : [button(t("pkOtherDevice"), "link", () => void act("passkey_fallback"))];
  const cancel = button(t("cancel"), "secondary", () => void act("passkey_cancel", { exists }));
  return el("div", { className: "passkey-foot" }, ...other, el("span", { className: "grow" }), cancel, ...(primary ? [primary] : []));
}

let choice = "";
function render(view: View | null, waiting = false, error?: string) {
  if (!view) {
    if (waiting) app.querySelectorAll("button").forEach((b) => (b.disabled = true));
    return;
  }
  const errorNode = error ? [el("p", { className: "error", textContent: error })] : [];
  if (view.locked) {
    return shell(t("pkLocked"), t("pkLockedHint", view.rpId), ...errorNode, footer(button(t("unlockApp"), "primary", () => void act("passkey_unlock"))));
  }
  if (view.kind === "create" && view.exists) {
    return shell(t("pkCreateTitle", view.rpId), t("pkExists"), ...errorNode, footer(undefined, true));
  }
  if (view.kind === "create") {
    const list = el("div", { className: "choices" });
    const options: { value: string; title: string; sub: string; login?: Login }[] = [
      { value: "", title: t("pkNewLogin"), sub: view.rpName || view.rpId },
      ...(view.logins ?? []).map((login) => ({ value: login.id, title: login.title, sub: login.username || login.vault, login })),
    ];
    for (const option of options) {
      const row = el(
        "label",
        { className: "choice-row" },
        el("input", { type: "radio", name: "target", value: option.value, checked: option.value === choice }),
        el("span", { className: "text" }, el("span", { className: "title", textContent: option.title }), el("span", { className: "sub", textContent: option.sub })),
      );
      if (option.login) row.insertBefore(avatar(option.login, `https://${view.host}`), row.children[1]);
      row.querySelector("input")!.addEventListener("change", () => (choice = option.value));
      list.append(row);
    }
    return shell(
      t("pkCreateTitle", view.rpId),
      t("pkCreateHint", view.userName || "?"),
      ...errorNode,
      list,
      footer(button(t("pkSave"), "primary", () => void act("passkey_choose", { itemId: choice }))),
    );
  }
  const passkeys = view.passkeys ?? [];
  const list = el("div", { className: "list" });
  for (const key of passkeys) {
    const login: Login = { id: key.itemId, title: key.title, username: key.userName, url: `https://${view.host}`, vault: "", favorite: false };
    const row = el(
      "button",
      { className: "row fillable passkey-row", type: "button" },
      avatar(login, `https://${view.host}`),
      el("span", { className: "text" }, el("span", { className: "title", textContent: key.title }), el("span", { className: "sub", textContent: key.userName })),
    );
    row.addEventListener("click", () => void act("passkey_choose", { credentialId: key.credentialId }));
    list.append(row);
  }
  if (passkeys.length === 0) {
    // Nothing here: another device is the way forward.
    list.append(el("p", { className: "muted pad", textContent: t("pkNone") }));
    const other = button(t("pkOtherDevice"), "primary", () => void act("passkey_fallback"));
    other.dataset.other = "1";
    return shell(t("pkGetTitle", view.rpId), t("pkNoneHint"), ...errorNode, list, footer(other));
  }
  shell(t("pkGetTitle", view.rpId), t("pkGetHint"), ...errorNode, list, footer());
}

async function load(error?: string) {
  const reply = await send<View>({ type: "passkey_view" });
  if (!reply.ok || !reply.data) return window.close();
  render(reply.data, false, error);
}

void load();

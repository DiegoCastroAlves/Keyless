// Content script: shows the Keyless button in login fields and fills them.
//
// Runs only in the top frame. The button and menu live in a closed shadow
// root, so the page cannot read or restyle them, and only real user clicks
// (isTrusted) are honoured.

import type { Login } from "./types";

const t = (key: string, ...subs: string[]) => chrome.i18n.getMessage(key, subs) || key;

const USERNAME_HINT = /user|email|e-mail|login|account|identifier|usuario|correo|cpf/i;
const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|token|c[oó]digo|code/i;

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
  if (OTP_HINT.test(hints) && (input.maxLength > 0 && input.maxLength <= 10)) return "otp";
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

function fill(anchor: HTMLInputElement | null, credentials: { username: string; password: string; totp: string | null }) {
  const fields = loginFields(anchor);
  if (fields.username && credentials.username) setValue(fields.username, credentials.username);
  if (fields.password && credentials.password) setValue(fields.password, credentials.password);
  if (fields.otp && credentials.totp && !fields.password) setValue(fields.otp, credentials.totp);
}

// ----- UI ---------------------------------------------------------------------

const LOGO = `<svg viewBox="0 0 1024 1024" width="18" height="18" aria-hidden="true"><circle cx="512" cy="512" r="452" fill="#14B8A6"/><circle cx="512" cy="512" r="318" fill="#073b37"/><circle cx="512" cy="438" r="94" fill="#fff"/><path d="M470 486H554L586 676Q590 702 564 702H460Q434 702 438 676Z" fill="#fff"/></svg>`;

const STYLE = `
:host { all: initial; }
.btn { position: fixed; z-index: 2147483646; width: 24px; height: 24px; border: 0; padding: 3px; border-radius: 6px;
  background: transparent; cursor: pointer; display: flex; align-items: center; justify-content: center; }
.btn:hover { background: rgba(20,184,166,.15); }
.menu { position: fixed; z-index: 2147483647; min-width: 260px; max-width: 340px; max-height: 320px; overflow: auto;
  background: #161a20; color: #e7eaee; border: 1px solid #2a3039; border-radius: 12px; padding: 6px;
  box-shadow: 0 12px 32px rgba(0,0,0,.35); font: 13px/1.35 system-ui, -apple-system, "Segoe UI", sans-serif; }
.head { display: flex; align-items: center; gap: 8px; padding: 6px 8px 8px; font-weight: 600; font-size: 12px; color: #9aa3ae; }
.row { display: flex; align-items: center; gap: 10px; width: 100%; padding: 8px; border: 0; border-radius: 8px; background: transparent;
  color: inherit; text-align: left; cursor: pointer; font: inherit; }
.row:hover, .row:focus { background: #232932; outline: none; }
.avatar { flex: none; width: 28px; height: 28px; border-radius: 8px; background: #0d9488; color: #fff; display: flex;
  align-items: center; justify-content: center; font-weight: 600; }
.text { min-width: 0; }
.title { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sub { color: #9aa3ae; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.note { padding: 8px; color: #9aa3ae; }
.action { margin: 4px 8px 8px; padding: 6px 10px; border: 0; border-radius: 8px; background: #2dd4bf; color: #052e2b;
  font: 600 12px system-ui, sans-serif; cursor: pointer; }
`;

const host = document.createElement("keyless-autofill");
const root = host.attachShadow({ mode: "closed" });
root.innerHTML = `<style>${STYLE}</style>`;
const button = document.createElement("button");
button.className = "btn";
button.type = "button";
button.title = "Keyless";
button.innerHTML = LOGO;
const menu = document.createElement("div");
menu.className = "menu";
menu.style.display = "none";
root.append(button, menu);
let mounted = false;
let current: HTMLInputElement | null = null;

function mount() {
  if (!mounted && document.documentElement) {
    document.documentElement.appendChild(host);
    mounted = true;
  }
}

function place() {
  if (!current) return;
  const rect = current.getBoundingClientRect();
  button.style.top = `${rect.top + (rect.height - 24) / 2}px`;
  button.style.left = `${rect.right - 28}px`;
  menu.style.top = `${rect.bottom + 4}px`;
  menu.style.left = `${Math.max(8, Math.min(rect.left, window.innerWidth - 348))}px`;
}

function hide() {
  button.style.display = "none";
  menu.style.display = "none";
  current = null;
}

function send<T>(message: unknown): Promise<{ ok: boolean; data?: T; error?: string }> {
  return chrome.runtime.sendMessage(message);
}

function note(text: string, action?: { label: string; run: () => void }) {
  menu.replaceChildren();
  const head = document.createElement("div");
  head.className = "head";
  head.innerHTML = LOGO;
  head.append("Keyless");
  const p = document.createElement("div");
  p.className = "note";
  p.textContent = text;
  menu.append(head, p);
  if (action) {
    const b = document.createElement("button");
    b.className = "action";
    b.textContent = action.label;
    b.addEventListener("click", (e) => {
      if (e.isTrusted) action.run();
    });
    menu.append(b);
  }
}

async function openMenu() {
  if (!current) return;
  const anchor = current;
  menu.style.display = "block";
  place();
  note(t("loading"));
  const reply = await send<Login[]>({ type: "matches" });
  if (anchor !== current) return;
  if (!reply.ok) {
    if (reply.error === "locked") note(t("lockedNote"), { label: t("unlockApp"), run: () => void send({ type: "show_app" }) });
    else note(t("notConnectedNote"));
    return;
  }
  const logins = reply.data ?? [];
  if (logins.length === 0) {
    note(t("noMatches"));
    return;
  }
  menu.replaceChildren();
  const head = document.createElement("div");
  head.className = "head";
  head.innerHTML = LOGO;
  head.append(t("fillWith"));
  menu.append(head);
  for (const login of logins) {
    const row = document.createElement("button");
    row.className = "row";
    row.type = "button";
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = (login.title.match(/[\p{L}\p{N}]/u)?.[0] ?? "?").toUpperCase();
    const text = document.createElement("span");
    text.className = "text";
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = login.title;
    const sub = document.createElement("div");
    sub.className = "sub";
    sub.textContent = login.username || login.vault;
    text.append(title, sub);
    row.append(avatar, text);
    row.addEventListener("click", async (e) => {
      if (!e.isTrusted) return;
      const credentials = await send<{ username: string; password: string; totp: string | null }>({ type: "credentials", id: login.id });
      if (credentials.ok && credentials.data) fill(anchor, credentials.data);
      hide();
    });
    menu.append(row);
  }
}

button.addEventListener("click", (e) => {
  if (!e.isTrusted) return;
  e.preventDefault();
  if (menu.style.display === "block") menu.style.display = "none";
  else void openMenu();
});

document.addEventListener(
  "focusin",
  (e) => {
    const target = e.target;
    if (!(target instanceof HTMLInputElement) || !fieldKind(target) || !visible(target)) return;
    mount();
    current = target;
    button.style.display = "flex";
    menu.style.display = "none";
    place();
  },
  true,
);

document.addEventListener(
  "mousedown",
  (e) => {
    if (e.composedPath().includes(host)) return;
    if (current && e.target !== current) hide();
  },
  true,
);
window.addEventListener("scroll", place, true);
window.addEventListener("resize", place);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") menu.style.display = "none";
});

// Fill requested from the popup or the keyboard shortcut.
chrome.runtime.onMessage.addListener((message, sender) => {
  if (sender.id !== chrome.runtime.id || message?.type !== "keyless-fill") return;
  const focused = document.activeElement instanceof HTMLInputElement ? document.activeElement : null;
  fill(focused, message);
});

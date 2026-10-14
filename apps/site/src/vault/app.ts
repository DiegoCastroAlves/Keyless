// The web vault (keyless.diegoalves.dev/vault/): the account's items in the
// browser, read-only. Keys are derived, checked and used in WebAssembly
// (crates/keyless-wasm, the same client as the Android app); this page
// talks to the server and shows what the client decrypts. Nothing is kept
// in the browser: closing or locking the page forgets everything, and the
// page locks itself after 10 minutes without use. Everything shown is set as
// text, never as HTML.

import init, { call } from "../../vendor/keyless-wasm/keyless_wasm.js";
import { prefsControl, prefsMenu } from "../prefs";
import { categoryLabel, categoryPlural, errorText, fieldLabel, formatDate, lang, t, type TextKey } from "./i18n";
import { server, ServerError, type Session } from "./server";

// ----- the client (WebAssembly) ---------------------------------------------

class ClientError extends Error {
  constructor(
    public key: string,
    message: string,
  ) {
    super(message);
  }
}

function client<T = unknown>(method: string, args: unknown = {}): T {
  const answer = JSON.parse(call(method, typeof args === "string" ? args : JSON.stringify(args))) as { ok?: T; error?: { key: string; message: string } };
  if (answer.error) throw new ClientError(answer.error.key, answer.error.message);
  return answer.ok as T;
}

function describe(err: unknown): string {
  if (err instanceof ClientError || err instanceof ServerError) return errorText(err.key, err.message);
  return errorText("unknown", err instanceof Error ? err.message : String(err));
}

// ----- the items, as the client gives them ------------------------------------

interface ItemUrl {
  href: string;
  label?: string;
}
interface Overview {
  title: string;
  subtitle: string;
  category: string;
  urls: ItemUrl[];
  tags: string[];
  favorite: boolean;
  archived: boolean;
  trashed_at?: number;
  updated_at: number;
}
interface Field {
  id: string;
  label: string;
  kind: string;
  value: string;
  purpose?: string | null;
}
interface Details {
  fields: Field[];
  sections: { id: string; title: string; fields: Field[] }[];
  notes: string;
}
interface Summary {
  id: string;
  vaultId: string;
  overview: Overview;
}
interface Vault {
  id: string;
  name: string;
  icon: string;
}

const SECRET_KINDS = new Set(["concealed", "pin", "card_number", "security_question"]);
const PAGE = 500;
const AUTO_LOCK_MS = 10 * 60 * 1000;
const CLEAR_CLIPBOARD_MS = 90 * 1000;

// ----- state --------------------------------------------------------------------

let session: Session | null = null;
let vaults: Vault[] = [];
let items: Summary[] = [];
let view: { kind: "all" | "favorites" | "vault" | "category"; id?: string } = { kind: "all" };
let query = "";
let selected: string | null = null;
let syncTimer: number | undefined;
let lockTimer: number | undefined;
let totpTimer: number | undefined;
let notice: string | null = null;

const root = document.getElementById("root")!;
document.title = t("title");
document.documentElement.lang = lang;

// The theme menu: in the bar above the sign-in screens and in the vault's
// own bar.
const prefs = prefsControl();
prefsMenu(prefs, t);

// ----- DOM helpers -----------------------------------------------------------------

function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string | boolean | undefined> = {}, ...children: (Node | string | null | false | undefined)[]) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (key === "text") node.textContent = String(value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children) if (child !== null && child !== false && child !== undefined) node.append(child);
  return node;
}

function button(label: string, onClick: (event: MouseEvent) => void, className = "") {
  const node = h("button", { type: "button", class: className, text: label });
  node.addEventListener("click", onClick);
  return node;
}

const brand = () => h("strong", { class: "brand" }, h("img", { src: "/icon-32.png", width: "24", height: "24", alt: "" }), "keyless");

/** A screen of its own in the middle of the page, under the bar. */
function centered(...children: Node[]) {
  root.replaceChildren(h("header", { class: "bar" }, brand(), prefs), h("main", { class: "center" }, ...children));
}

function input(type: string, name: string, autocomplete: string) {
  const node = document.createElement("input");
  node.type = type;
  node.name = name;
  node.id = name;
  node.setAttribute("autocomplete", autocomplete);
  return node;
}

const b64url = (bytes: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const fromB64url = (text: string) => {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4)), (c) => c.charCodeAt(0));
};
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));

// ----- signing in ------------------------------------------------------------------

/** The email and Secret Key a setup link or another device gave. */
let received: { email: string; secretKey: string } | null = null;

function signInScreen(error?: string) {
  stopTimers();
  const email = input("email", "email", "username");
  email.value = received?.email ?? rememberedEmail();
  const secretKey = input("text", "secret-key", "off");
  secretKey.spellcheck = false;
  secretKey.placeholder = "K1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX";
  secretKey.className = "mono";
  const password = input("password", "master-password", "current-password");
  const submit = h("button", { type: "submit", class: "primary", text: t("signIn") });
  const errorLine = h("p", { class: "error", role: "alert" }, error ?? "");

  // A pasted setup link fills the email and Secret Key.
  secretKey.addEventListener("input", () => {
    if (!secretKey.value.trim().toLowerCase().startsWith("keyless://setup")) return;
    try {
      received = client<{ email: string; secretKey: string }>("parseSetupLink", { text: secretKey.value });
      signInScreen();
    } catch (err) {
      secretKey.value = "";
      errorLine.textContent = describe(err);
    }
  });

  const keyField = received
    ? h("div", { class: "received" }, h("span", { text: `✓ ${t("keyReceived")}` }), button(t("cancel"), () => ((received = null), signInScreen()), "link"))
    : h("div", { class: "field" }, h("label", { for: "secret-key", text: t("secretKey") }), secretKey, h("p", { class: "hint", text: t("secretKeyHint") }));

  const form = h(
    "form",
    { class: "card signin", novalidate: true },
    h("h1", { text: t("signInTitle") }),
    h("p", { class: "muted", text: t("signInIntro") }),
    notice ? h("p", { class: "notice", text: notice }) : null,
    h("div", { class: "field" }, h("label", { for: "email", text: t("email") }), email),
    keyField,
    h("div", { class: "field" }, h("label", { for: "master-password", text: t("masterPassword") }), password),
    errorLine,
    submit,
    h("div", { class: "divider" }, h("span", { text: t("or") })),
    button(t("withPasskey"), () => void signInWithPasskey(errorLine)),
    button(t("withDevice"), () => {
      if (!email.value.includes("@")) {
        errorLine.textContent = t("emailFirst");
        return;
      }
      deviceScreen(email.value.trim().toLowerCase());
    }),
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    notice = null;
    submit.disabled = true;
    submit.textContent = t("signingIn");
    errorLine.textContent = "";
    // Let the button repaint before the key derivation takes the thread.
    await new Promise((r) => setTimeout(r, 30));
    try {
      const key = received?.secretKey ?? secretKey.value;
      const derived = client<{ authSecret: string }>("derive", { email: email.value, masterPassword: password.value, secretKey: key });
      password.value = "";
      const signed = await server.signIn(email.value.trim().toLowerCase(), derived.authSecret);
      await opened(signed, email.value);
    } catch (err) {
      client("lock");
      submit.disabled = false;
      submit.textContent = t("signIn");
      errorLine.textContent = describe(err);
    }
  });
  centered(form);
  (received || email.value ? password : email).focus();
}

function rememberedEmail(): string {
  try {
    return localStorage.getItem("vault-email") ?? "";
  } catch {
    return "";
  }
}

/** The server accepted the sign-in: open the account and read it. */
async function opened(signed: Session, email: string) {
  const profile = await server.profile(signed.accessToken, signed.userId);
  client("signedIn", { userId: signed.userId, profile });
  session = signed;
  received = null;
  try {
    localStorage.setItem("vault-email", email.trim().toLowerCase());
  } catch {
    // Private window: nothing remembered.
  }
  centered(h("p", { class: "muted", text: t("syncing") }));
  await sync();
  mainScreen();
  syncTimer = window.setInterval(() => void sync().then(renderMain), 60_000);
  watchActivity();
}

async function token(): Promise<string> {
  if (!session) throw new ServerError("session_expired");
  if (session.expiresAt - 60 < Date.now() / 1000) session = await server.refresh(session.refreshToken);
  return session.accessToken;
}

async function sync() {
  const access = await token();
  client("applyMemberships", JSON.stringify(await server.memberships(access, session!.userId)));
  vaults = client<Vault[]>("vaults");
  for (const vault of vaults) {
    for (;;) {
      const cursor = client<number>("cursor", { vaultId: vault.id });
      const page = await server.itemsSince(access, vault.id, cursor, PAGE);
      client("applyItems", { vaultId: vault.id, items: page });
      if (page.length < PAGE) break;
    }
  }
  items = client<Summary[]>("items").filter((i) => !i.overview.trashed_at);
  items.sort((a, b) => a.overview.title.localeCompare(b.overview.title));
}

// ----- passkeys -----------------------------------------------------------------------

type PrfResults = { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } };

async function signInWithPasskey(errorLine: HTMLElement) {
  errorLine.textContent = "";
  let credential: PublicKeyCredential;
  const salt = fromB64url(client<string>("passkeySalt"));
  try {
    credential = (await navigator.credentials.get({
      publicKey: {
        challenge: random(32),
        rpId: location.hostname,
        userVerification: "required",
        extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch {
    errorLine.textContent = t("passkeyCancelled");
    return;
  }
  const output = (credential.getClientExtensionResults() as PrfResults).prf?.results?.first;
  if (!output) {
    errorLine.textContent = t("passkeyNoPrf");
    return;
  }
  const prfOutput = b64url(output);
  const credentialId = b64url(credential.rawId);
  try {
    const { proof } = client<{ proof: string }>("passkeyProof", { prfOutput, credentialId });
    const answer = await server.rpc<{ user_id?: string; enc_bundle?: string; error?: string }>("passkey_sign_in", { p_credential_id: credentialId, p_proof: proof });
    if (answer.error || !answer.user_id || !answer.enc_bundle) {
      errorLine.textContent = answer.error === "passkey_throttled" ? t("passkeyThrottled") : t("passkeyFailed");
      return;
    }
    const bundle = client<{ email: string; authSecret: string }>("passkeyOpen", { prfOutput, credentialId, userId: answer.user_id, encBundle: answer.enc_bundle });
    const signed = await server.signIn(bundle.email, bundle.authSecret);
    await opened(signed, bundle.email);
  } catch (err) {
    client("lock");
    errorLine.textContent = err instanceof ServerError && err.key === "missing_function" ? errorText("passkeys_unavailable") : describe(err);
  }
}

async function addPasskey(name: string): Promise<void> {
  if (!session) return;
  const salt = fromB64url(client<string>("passkeySalt"));
  const email = (client<{ email: string }>("status").email ?? "").toString();
  let credential: PublicKeyCredential;
  try {
    credential = (await navigator.credentials.create({
      publicKey: {
        rp: { id: location.hostname, name: "Keyless" },
        user: { id: new TextEncoder().encode(session.userId), name: email, displayName: email },
        challenge: random(32),
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch {
    throw new Error(t("passkeyCancelled"));
  }
  const results = (credential.getClientExtensionResults() as PrfResults).prf;
  if (!results?.enabled && !results?.results?.first) throw new Error(t("passkeyNoPrf"));
  let output = results.results?.first;
  if (!output) {
    // Most authenticators give the PRF output only when signing in.
    const again = (await navigator.credentials.get({
      publicKey: {
        challenge: random(32),
        rpId: location.hostname,
        allowCredentials: [{ type: "public-key", id: credential.rawId }],
        userVerification: "required",
        extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
    output = (again.getClientExtensionResults() as PrfResults).prf?.results?.first;
  }
  if (!output) throw new Error(t("passkeyNoPrf"));
  const credentialId = b64url(credential.rawId);
  const sealed = client<{ proof: string; encBundle: string; encName: string }>("passkeyRegister", { prfOutput: b64url(output), credentialId, name });
  await server.rpc("add_passkey", { p_id: crypto.randomUUID(), p_credential_id: credentialId, p_enc_name: sealed.encName, p_proof: sealed.proof, p_enc_bundle: sealed.encBundle }, await token());
}

// ----- signing in with another device ---------------------------------------------------

function deviceScreen(email: string) {
  stopTimers();
  const status = h("div", { class: "device-status" }, h("p", { class: "muted", text: t("deviceWaiting") }));
  let stopped = false;
  const id = crypto.randomUUID();
  const secret = b64url(random(32));
  const cancel = () => {
    stopped = true;
    void server.rpc("cancel_device_setup", { p_id: id, p_secret: secret }).catch(() => undefined);
    signInScreen();
  };
  centered(h("section", { class: "card signin" }, h("h1", { text: t("deviceTitle") }), h("p", { class: "muted", text: t("deviceBody", { email }) }), status, button(t("cancel"), cancel)));
  const fail = (text: string) => {
    stopped = true;
    status.replaceChildren(h("p", { class: "error", text }), button(t("retry"), () => deviceScreen(email)));
  };
  const started = client<{ publicKey: string; commitment: string }>("setupStart");
  server
    .rpc<{ ok?: boolean; error?: string }>("request_device_setup", { p_email: email, p_id: id, p_secret: secret, p_public_key: started.publicKey, p_commitment: started.commitment, p_platform: "web" })
    .then(async (answer) => {
      if (answer.error) return fail(errorText(answer.error === "device_setup_throttled" ? "device_setup_throttled" : "unknown", answer.error));
      let revealed = false;
      while (!stopped) {
        await new Promise((r) => setTimeout(r, 2000));
        if (stopped) return;
        const state = await server.rpc<{ status: string; approver_key?: string; approver_nonce?: string; payload?: string }>("device_setup_status", { p_id: id, p_secret: secret });
        if ((state.status === "answered" || state.status === "revealed") && state.approver_key && state.approver_nonce) {
          const shown = client<{ code: string; nonce: string }>("setupCode", { approverKey: state.approver_key, approverNonce: state.approver_nonce });
          if (!revealed) {
            await server.rpc("reveal_device_setup", { p_id: id, p_secret: secret, p_nonce: shown.nonce });
            revealed = true;
          }
          status.replaceChildren(h("p", { class: "muted", text: t("deviceCode") }), h("p", { class: "code", text: `${shown.code.slice(0, 3)} ${shown.code.slice(3)}` }));
        } else if (state.status === "approved" && state.approver_key && state.approver_nonce && state.payload) {
          received = client<{ email: string; secretKey: string }>("setupOpen", { requestId: id, approverKey: state.approver_key, approverNonce: state.approver_nonce, payload: state.payload });
          notice = t("deviceDone");
          stopped = true;
          signInScreen();
          return;
        } else if (state.status === "denied") {
          return fail(t("deviceDenied"));
        } else if (state.status === "expired" || state.status === "unknown") {
          return fail(t("deviceExpired"));
        }
      }
    })
    .catch((err) => fail(err instanceof ServerError && err.key === "missing_function" ? errorText("device_setup_unavailable") : describe(err)));
}

// ----- the vault ----------------------------------------------------------------------

function visible(): Summary[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return items.filter((item) => {
    const o = item.overview;
    if (view.kind === "favorites" && !o.favorite) return false;
    if (view.kind === "vault" && item.vaultId !== view.id) return false;
    if (view.kind === "category" && o.category !== view.id) return false;
    if (view.kind !== "category" && o.archived) return false;
    const text = [o.title, o.subtitle, ...o.urls.map((u) => u.href), ...o.tags].join(" ").toLowerCase();
    return words.every((w) => text.includes(w));
  });
}

function mainScreen() {
  root.replaceChildren(
    h(
      "div",
      { class: "app" },
      h(
        "header",
        { class: "top" },
        brand(),
        searchBox(),
        button(t("settings"), () => settingsDialog(), "ghost"),
        button(t("lock"), () => void lock(), "ghost"),
        prefs,
      ),
      h("nav", { class: "side", id: "side" }),
      h("section", { class: "list", id: "list" }),
      h("section", { class: "detail", id: "detail" }),
    ),
  );
  renderMain();
}

function searchBox() {
  const box = input("search", "search", "off");
  box.placeholder = t("search");
  box.value = query;
  box.addEventListener("input", () => {
    query = box.value;
    renderList();
  });
  return box;
}

function renderMain() {
  if (!document.getElementById("side")) return;
  renderSide();
  renderList();
  renderDetail();
}

function renderSide() {
  const side = document.getElementById("side")!;
  const entry = (label: string, next: typeof view, count: number) => {
    const active = view.kind === next.kind && view.id === next.id;
    const node = h("button", { type: "button", class: active ? "nav active" : "nav" }, h("span", { text: label }), h("span", { class: "count", text: String(count) }));
    node.addEventListener("click", () => {
      view = next;
      selected = null;
      renderMain();
    });
    return node;
  };
  const live = items.filter((i) => !i.overview.archived);
  const categories = [...new Set(items.map((i) => i.overview.category))].sort((a, b) => categoryPlural(a).localeCompare(categoryPlural(b)));
  side.replaceChildren(
    entry(t("allItems"), { kind: "all" }, live.length),
    entry(t("favorites"), { kind: "favorites" }, live.filter((i) => i.overview.favorite).length),
    h("h2", { text: t("vaults") }),
    ...vaults.map((v) => entry(v.name, { kind: "vault", id: v.id }, live.filter((i) => i.vaultId === v.id).length)),
    h("h2", { text: t("categories") }),
    ...categories.map((c) => entry(categoryPlural(c), { kind: "category", id: c }, items.filter((i) => i.overview.category === c).length)),
  );
}

function avatar(title: string) {
  return h("span", { class: "avatar", text: (title.trim()[0] ?? "?").toUpperCase(), "aria-hidden": "true" });
}

function renderList() {
  const list = document.getElementById("list");
  if (!list) return;
  const shown = visible();
  if (!shown.length) {
    list.replaceChildren(h("p", { class: "muted empty", text: t("noItems") }));
    return;
  }
  list.replaceChildren(
    ...shown.map((item) => {
      const row = h(
        "button",
        { type: "button", class: item.id === selected ? "row active" : "row" },
        avatar(item.overview.title),
        h("span", { class: "row-text" }, h("span", { class: "row-title", text: item.overview.title }), h("span", { class: "row-sub", text: item.overview.subtitle || categoryLabel(item.overview.category) })),
      );
      row.addEventListener("click", () => {
        selected = item.id;
        renderList();
        renderDetail();
        // One column (phones): the item is below the list.
        if (matchMedia("(max-width: 860px)").matches) document.getElementById("detail")?.scrollIntoView({ behavior: "smooth" });
      });
      return row;
    }),
  );
}

function copyButton(value: string) {
  const node = button(t("copy"), async () => {
    try {
      await navigator.clipboard.writeText(value);
      node.textContent = t("copied");
      setTimeout(() => (node.textContent = t("copy")), 1500);
      // Cleared later, as the app does (only possible while the page has focus).
      setTimeout(() => {
        if (document.hasFocus()) void navigator.clipboard.writeText("").catch(() => undefined);
      }, CLEAR_CLIPBOARD_MS);
    } catch {
      // Not allowed: the value can still be selected.
    }
  }, "small");
  return node;
}

function fieldRow(field: Field) {
  const value = h("div", { class: "value" });
  const actions = h("div", { class: "actions" });
  if (field.kind === "totp") {
    value.classList.add("mono");
    const show = () => {
      try {
        const code = client<{ code: string; remaining: number }>("totp", { uri: field.value, now: Math.floor(Date.now() / 1000) });
        value.textContent = `${code.code.slice(0, Math.ceil(code.code.length / 2))} ${code.code.slice(Math.ceil(code.code.length / 2))}  ·  ${code.remaining}s`;
        actions.replaceChildren(copyButton(code.code));
      } catch {
        value.textContent = "—";
      }
    };
    show();
    totpRefreshers.push(show);
  } else if (SECRET_KINDS.has(field.kind)) {
    value.classList.add("mono");
    let shown = false;
    value.textContent = "••••••••••••";
    const toggle = button(t("reveal"), () => {
      shown = !shown;
      value.textContent = shown ? field.value : "••••••••••••";
      toggle.textContent = shown ? t("hide") : t("reveal");
    }, "small");
    actions.append(toggle, copyButton(field.value));
  } else if (field.kind === "url" && /^https?:\/\//i.test(field.value)) {
    value.append(h("a", { href: field.value, target: "_blank", rel: "noopener noreferrer", text: field.value }));
    actions.append(copyButton(field.value));
  } else {
    value.textContent = field.value;
    if (field.kind === "multiline" || field.kind === "address") value.classList.add("pre");
    actions.append(copyButton(field.value));
  }
  return h("div", { class: "field-row" }, h("div", { class: "label", text: fieldLabel(field.label) }), h("div", { class: "line" }, value, actions));
}

let totpRefreshers: (() => void)[] = [];

function renderDetail() {
  const detail = document.getElementById("detail");
  if (!detail) return;
  totpRefreshers = [];
  window.clearInterval(totpTimer);
  if (!selected) {
    detail.replaceChildren(h("p", { class: "muted empty", text: t("select") }));
    return;
  }
  let item: { overview: Overview; details: Details };
  try {
    item = client("item", { id: selected });
  } catch (err) {
    detail.replaceChildren(h("p", { class: "error", text: describe(err) }));
    return;
  }
  const { overview, details } = item;
  const card = h("article", { class: "item" }, h("div", { class: "kind", text: categoryLabel(overview.category) }), h("h1", { text: overview.title }));
  const main = details.fields.filter((f) => f.value);
  if (main.length) card.append(h("div", { class: "group" }, ...main.map(fieldRow)));
  for (const section of details.sections ?? []) {
    const fields = section.fields.filter((f) => f.value);
    if (!fields.length) continue;
    if (section.title) card.append(h("h2", { text: section.title }));
    card.append(h("div", { class: "group" }, ...fields.map(fieldRow)));
  }
  const urls = overview.urls.filter((u) => u.href);
  if (urls.length) {
    card.append(h("h2", { text: t("websites") }));
    card.append(
      h(
        "div",
        { class: "group" },
        ...urls.map((u) => {
          const href = /^https?:\/\//i.test(u.href) ? u.href : `https://${u.href}`;
          const safe = /^https?:\/\/[^\s]+$/i.test(href);
          return h(
            "div",
            { class: "field-row" },
            h("div", { class: "line" }, h("div", { class: "value" }, safe ? h("a", { href, target: "_blank", rel: "noopener noreferrer", text: u.href }) : u.href), h("div", { class: "actions" }, copyButton(u.href))),
          );
        }),
      ),
    );
  }
  if (details.notes) card.append(h("h2", { text: t("notes") }), h("div", { class: "group" }, h("div", { class: "field-row" }, h("div", { class: "value pre", text: details.notes }))));
  if (overview.tags.length) card.append(h("h2", { text: t("tags") }), h("p", { class: "tags", text: overview.tags.join(" · ") }));
  card.append(h("p", { class: "muted small", text: t("modified", { date: formatDate(overview.updated_at) }) }), h("p", { class: "muted small", text: t("readOnly") }));
  detail.replaceChildren(card);
  if (totpRefreshers.length) totpTimer = window.setInterval(() => totpRefreshers.forEach((f) => f()), 1000);
}

// ----- settings: passkeys ------------------------------------------------------------------

function settingsDialog() {
  const dialog = h("dialog", { class: "dialog" });
  const list = h("div", { class: "group" });
  const errorLine = h("p", { class: "error", role: "alert" });
  const name = input("text", "passkey-name", "off");
  name.placeholder = t("passkeyName");
  const add = button(t("addPasskey"), async () => {
    errorLine.textContent = "";
    add.disabled = true;
    try {
      await addPasskey(name.value.trim() || "Passkey");
      name.value = "";
      await load();
    } catch (err) {
      errorLine.textContent =
        err instanceof ClientError && err.key === "passkey_needs_password"
          ? t("passkeyNeedsPassword")
          : err instanceof ServerError && err.key === "missing_function"
            ? errorText("passkeys_unavailable")
            : err instanceof Error && !(err instanceof ClientError) && !(err instanceof ServerError)
              ? err.message
              : describe(err);
    } finally {
      add.disabled = false;
    }
  }, "primary");
  const load = async () => {
    try {
      const rows = client<{ id: string; name: string; created_at: string; last_used_at: string | null }[]>("passkeyNames", JSON.stringify(await server.passkeys(await token())));
      list.replaceChildren(
        ...(rows.length
          ? rows.map((row) =>
              h(
                "div",
                { class: "field-row" },
                h(
                  "div",
                  { class: "line" },
                  h(
                    "div",
                    { class: "value" },
                    h("strong", { text: row.name || "Passkey" }),
                    h("span", {
                      class: "muted small",
                      text: ` · ${t("added", { date: formatDate(Date.parse(row.created_at) / 1000) })}${row.last_used_at ? ` · ${t("lastUsed", { date: formatDate(Date.parse(row.last_used_at) / 1000) })}` : ""}`,
                    }),
                  ),
                  h(
                    "div",
                    { class: "actions" },
                    button(t("remove"), async () => {
                      await server.rpc("remove_passkey", { p_id: row.id }, await token()).catch((err) => (errorLine.textContent = describe(err)));
                      await load();
                    }, "small"),
                  ),
                ),
              ),
            )
          : [h("p", { class: "muted pad", text: t("noPasskeys") })]),
      );
    } catch (err) {
      list.replaceChildren(h("p", { class: "error pad", text: err instanceof ServerError && err.key === "missing_function" ? errorText("passkeys_unavailable") : describe(err) }));
    }
  };
  dialog.append(
    h("h1", { text: t("passkeys") }),
    h("p", { class: "muted", text: t("passkeysBody") }),
    list,
    h("div", { class: "add" }, name, add),
    errorLine,
    h("p", { class: "muted small", text: t("passkeysChanged") }),
    button(t("close"), () => dialog.close()),
  );
  dialog.addEventListener("close", () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
  void load();
}

// ----- locking ---------------------------------------------------------------------------

function stopTimers() {
  window.clearInterval(syncTimer);
  window.clearInterval(totpTimer);
  window.clearTimeout(lockTimer);
}

async function lock(text?: TextKey) {
  stopTimers();
  client("forget");
  const ending = session;
  session = null;
  items = [];
  vaults = [];
  selected = null;
  query = "";
  view = { kind: "all" };
  notice = text ? t(text) : null;
  if (ending) await server.signOut(ending.accessToken);
  for (const dialog of document.querySelectorAll("dialog")) dialog.remove();
  signInScreen();
}

let watching = false;
function watchActivity() {
  const restart = () => {
    window.clearTimeout(lockTimer);
    if (session) lockTimer = window.setTimeout(() => void lock("lockedBody"), AUTO_LOCK_MS);
  };
  restart();
  if (watching) return;
  watching = true;
  for (const kind of ["keydown", "mousedown", "touchstart", "wheel"]) window.addEventListener(kind, restart, { passive: true });
}

// The keys go with the page.
window.addEventListener("pagehide", () => {
  try {
    client("forget");
  } catch {
    // Not loaded yet.
  }
});

await init({ module_or_path: new URL("/vault/keyless_wasm_bg.wasm", location.href) });
signInScreen();

// Opens a Keyless share link: https://keyless.diegoalves.dev/share/#<id>.<key>
//
// The fragment (after '#') never reaches any server. The page takes the id
// and key from it, removes them from the address bar and history, and only
// when the visitor asks fetches the encrypted copy (each fetch counts as a
// view, so link previews do not use up one-time links). The copy is
// decrypted here, in the browser, with the format the app uses
// (keyless-core crypto.rs and share.rs): an XChaCha20-Poly1305 envelope
// "k1.<base64url(nonce || ciphertext)>", padded, bound to the share id.
// Everything shown is set as text, never as HTML.

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import labels from "virtual:labels";

declare const __SUPABASE_URL__: string;
declare const __SUPABASE_KEY__: string;

interface SharedField {
  label: string;
  value: string;
  kind: string;
  secret: boolean;
  section?: string;
}

interface SharedItem {
  format: number;
  title: string;
  category: string;
  fields: SharedField[];
  urls: string[];
  notes: string;
  sharedAt: number;
}

interface Opened {
  payload: string;
  expiresAt: string;
  viewsLeft: number | null;
}

// ----- Texts ---------------------------------------------------------------

type Lang = "pt-BR" | "en" | "es";
const TEXT = {
  "pt-BR": {
    title: "Item compartilhado",
    intro: "Alguém compartilhou um item do Keyless com você. Ele é descriptografado aqui, no seu navegador.",
    show: "Ver item",
    loading: "Abrindo…",
    once: "Depois de aberto, este link pode deixar de funcionar.",
    broken: "Este link está incompleto. Peça a quem enviou para copiar o link inteiro.",
    gone: "Este link expirou, foi revogado ou já foi aberto.",
    damaged: "Não foi possível abrir este item: o link ou o conteúdo foi alterado.",
    offline: "Não foi possível falar com o servidor. Verifique sua conexão e tente de novo.",
    expires: "Este link funciona até {date}.",
    lastView: "Esta foi a última visualização: anote o que precisar antes de fechar a página.",
    viewsLeft: "Ainda pode ser aberto {n} vez(es).",
    reveal: "Mostrar",
    hide: "Ocultar",
    copy: "Copiar",
    copied: "Copiado",
    websites: "Sites",
    notes: "Notas",
    sharedOn: "Compartilhado em {date}.",
    footer: "Keyless: gerenciador de senhas com criptografia de ponta a ponta.",
  },
  en: {
    title: "Shared item",
    intro: "Someone shared a Keyless item with you. It is decrypted here, in your browser.",
    show: "View item",
    loading: "Opening…",
    once: "Once opened, this link may stop working.",
    broken: "This link is incomplete. Ask the sender to copy the whole link.",
    gone: "This link expired, was revoked or has already been opened.",
    damaged: "This item could not be opened: the link or its content was changed.",
    offline: "Could not reach the server. Check your connection and try again.",
    expires: "This link works until {date}.",
    lastView: "This was the last view: note what you need before closing the page.",
    viewsLeft: "It can be opened {n} more time(s).",
    reveal: "Show",
    hide: "Hide",
    copy: "Copy",
    copied: "Copied",
    websites: "Websites",
    notes: "Notes",
    sharedOn: "Shared on {date}.",
    footer: "Keyless: a password manager with end-to-end encryption.",
  },
  es: {
    title: "Elemento compartido",
    intro: "Alguien compartió contigo un elemento de Keyless. Se descifra aquí, en tu navegador.",
    show: "Ver elemento",
    loading: "Abriendo…",
    once: "Una vez abierto, este enlace puede dejar de funcionar.",
    broken: "Este enlace está incompleto. Pide a quien lo envió que copie el enlace entero.",
    gone: "Este enlace caducó, fue revocado o ya se abrió.",
    damaged: "No se pudo abrir este elemento: el enlace o su contenido fue alterado.",
    offline: "No se pudo contactar con el servidor. Revisa tu conexión e inténtalo de nuevo.",
    expires: "Este enlace funciona hasta el {date}.",
    lastView: "Esta fue la última visualización: anota lo que necesites antes de cerrar la página.",
    viewsLeft: "Todavía se puede abrir {n} vez/veces.",
    reveal: "Mostrar",
    hide: "Ocultar",
    copy: "Copiar",
    copied: "Copiado",
    websites: "Sitios",
    notes: "Notas",
    sharedOn: "Compartido el {date}.",
    footer: "Keyless: gestor de contraseñas con cifrado de extremo a extremo.",
  },
} satisfies Record<Lang, Record<string, string>>;

const lang: Lang = (() => {
  for (const l of navigator.languages ?? [navigator.language]) {
    const lower = l.toLowerCase();
    if (lower.startsWith("pt")) return "pt-BR";
    if (lower.startsWith("es")) return "es";
    if (lower.startsWith("en")) return "en";
  }
  return "en";
})();
const t = (key: keyof (typeof TEXT)["en"], vars: Record<string, string | number> = {}) =>
  TEXT[lang][key].replace(/\{(\w+)\}/g, (_, name) => String(vars[name] ?? ""));
const fieldLabel = (label: string) => labels[lang].fieldLabels[label] ?? label;
const categoryLabel = (category: string) => labels[lang].categories[category] ?? category;
const formatDate = (date: Date) => date.toLocaleString(lang, { dateStyle: "long", timeStyle: "short" });

// ----- Decryption (same format as keyless-core) -----------------------------

const encoder = new TextEncoder();

function fromBase64Url(text: string): Uint8Array {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

/** context("keyless/share", [id]) with the envelope's domain prefix. */
function aad(id: string): Uint8Array {
  const parts = [encoder.encode("keyless/k1/keyless/share"), new Uint8Array([0]), encoder.encode(id)];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function decrypt(envelope: string, id: string, key: Uint8Array): SharedItem {
  if (!envelope.startsWith("k1.")) throw new Error("format");
  const raw = fromBase64Url(envelope.slice(3));
  if (raw.length < 24 + 16) throw new Error("format");
  const padded = xchacha20poly1305(key, raw.subarray(0, 24), aad(id)).decrypt(raw.subarray(24));
  // ISO/IEC 7816-4 padding: the content, 0x80, then zeros.
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0) end--;
  if (end < 0 || padded[end] !== 0x80) throw new Error("padding");
  const item = JSON.parse(new TextDecoder().decode(padded.subarray(0, end))) as SharedItem;
  padded.fill(0);
  if (typeof item.title !== "string" || !Array.isArray(item.fields)) throw new Error("format");
  return item;
}

// ----- Page ----------------------------------------------------------------

const app = document.getElementById("app")!;
document.documentElement.lang = lang;
document.title = `${t("title")} · Keyless`;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...children: (Node | string)[]) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function message(text: string, tone: "info" | "error" = "info") {
  app.replaceChildren(el("section", { className: `card ${tone}` }, el("p", { textContent: text })));
}

// The link's secret half, read once and removed from the address bar (and
// from this page's history entry).
const fragment = location.hash.slice(1);
history.replaceState(null, "", location.pathname + location.search);
const match = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/.exec(fragment);

if (!match) {
  message(t("broken"), "error");
} else {
  const [, id, keyText] = match;
  const show = el("button", { className: "primary", textContent: t("show") });
  app.replaceChildren(el("section", { className: "card" }, el("h1", { textContent: t("title") }), el("p", { textContent: t("intro") }), el("p", { className: "muted", textContent: t("once") }), show));
  show.addEventListener("click", async () => {
    show.disabled = true;
    show.textContent = t("loading");
    let opened: Opened | null;
    try {
      const response = await fetch(`${__SUPABASE_URL__}/rest/v1/rpc/open_share`, {
        method: "POST",
        headers: { apikey: __SUPABASE_KEY__, "Content-Type": "application/json" },
        body: JSON.stringify({ p_id: id }),
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
      if (!response.ok) throw new Error(String(response.status));
      opened = (await response.json()) as Opened | null;
    } catch {
      show.disabled = false;
      show.textContent = t("show");
      app.append(el("p", { className: "error-text", textContent: t("offline") }));
      return;
    }
    if (!opened) return message(t("gone"), "error");
    let item: SharedItem;
    try {
      const key = fromBase64Url(keyText);
      item = decrypt(opened.payload, id, key);
      key.fill(0);
    } catch {
      return message(t("damaged"), "error");
    }
    render(item, opened);
  });
}

function copyButton(value: string) {
  const button = el("button", { className: "small", textContent: t("copy") });
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(value);
      button.textContent = t("copied");
      setTimeout(() => (button.textContent = t("copy")), 1500);
    } catch {
      // Clipboard not allowed here: the value can still be selected.
    }
  });
  return button;
}

function fieldRow(field: SharedField) {
  const value = el("div", { className: field.secret ? "value secret" : "value" });
  value.textContent = field.secret ? "••••••••••••" : field.value;
  const actions = el("div", { className: "actions" });
  if (field.secret) {
    let shown = false;
    const toggle = el("button", { className: "small", textContent: t("reveal") });
    toggle.addEventListener("click", () => {
      shown = !shown;
      value.textContent = shown ? field.value : "••••••••••••";
      toggle.textContent = shown ? t("hide") : t("reveal");
    });
    actions.append(toggle);
  }
  actions.append(copyButton(field.value));
  return el("div", { className: "field" }, el("div", { className: "label", textContent: fieldLabel(field.label) }), el("div", { className: "row" }, value, actions));
}

function render(item: SharedItem, opened: Opened) {
  const card = el("section", { className: "card item" });
  card.append(el("div", { className: "kind", textContent: categoryLabel(item.category) }), el("h1", { textContent: item.title }));

  let section: string | undefined;
  let group = el("div", { className: "group" });
  for (const field of item.fields) {
    if ((field.section ?? "") !== (section ?? "")) {
      if (group.childElementCount) card.append(group);
      group = el("div", { className: "group" });
      section = field.section;
      if (section) card.append(el("h2", { textContent: section }));
    }
    group.append(fieldRow(field));
  }
  if (group.childElementCount) card.append(group);

  // Only real web addresses become links.
  const urls = item.urls.filter((u) => /^https?:\/\//i.test(u));
  if (urls.length) {
    card.append(el("h2", { textContent: t("websites") }));
    const list = el("div", { className: "group" });
    for (const href of urls) {
      const link = el("a", { href, textContent: href, target: "_blank", rel: "noopener noreferrer" });
      list.append(el("div", { className: "field" }, el("div", { className: "row" }, el("div", { className: "value" }, link), el("div", { className: "actions" }, copyButton(href)))));
    }
    card.append(list);
  }
  if (item.notes) {
    card.append(el("h2", { textContent: t("notes") }), el("div", { className: "group" }, el("div", { className: "field" }, el("div", { className: "value notes", textContent: item.notes }))));
  }

  const info = [t("sharedOn", { date: formatDate(new Date(item.sharedAt * 1000)) }), t("expires", { date: formatDate(new Date(opened.expiresAt)) })];
  if (opened.viewsLeft === 0) info.push(t("lastView"));
  else if (opened.viewsLeft !== null) info.push(t("viewsLeft", { n: opened.viewsLeft }));
  card.append(el("p", { className: "muted", textContent: info.join(" ") }));
  app.replaceChildren(card);
}

document.getElementById("footer")!.textContent = t("footer");

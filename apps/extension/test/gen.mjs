// Generates the field-detection test pages (test/pages/NNN.html): sign-in,
// sign-up, change-password, one-time-code, card and address forms, plus
// fields that are not a login's (newsletter, search, coupon, captcha,
// contact) and "honeypot" fields hidden from the user, in many shapes: a
// form or not, open, closed, nested and slotted shadow roots, labels in
// every way pages write them, English, Portuguese and Spanish, with and
// without autocomplete. Each page says what it expects (see harness.ts).
//
// Deterministic: the same pages every time.

import { mkdirSync, rmSync, writeFileSync } from "node:fs";

const OUT = new URL("./pages/", import.meta.url);

// ----- A small seeded random ------------------------------------------------------

let seed = 20261008;
const rand = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const pick = (list) => list[Math.floor(rand() * list.length)];

// ----- Words ------------------------------------------------------------------------

const LANGS = ["en", "pt", "es"];
const WORDS = {
  en: {
    idNumber: ["Customer number", "Member ID", "Account number"],
    user: ["Email", "Email address", "Username", "Username or email", "Phone, username or email", "Login", "User ID", "Account email"],
    pass: ["Password", "Your password"],
    newPass: ["Create a password", "New password", "Choose a password"],
    confirm: ["Confirm password", "Repeat password", "Retype password"],
    current: ["Current password", "Old password"],
    otp: ["Verification code", "Enter the 6-digit code", "Authentication code", "One-time code", "Code from your authenticator app"],
    card: { number: "Card number", holder: "Name on card", exp: "Expiration date (MM/YY)", code: "CVC" },
    address: { name: "Full name", street: "Street address", city: "City", zip: "ZIP code", phone: "Phone" },
    newsletter: ["Subscribe to our newsletter", "Get our newsletter"],
    subscribe: "Subscribe",
    search: ["Search", "Search products"],
    coupon: ["Coupon code", "Promo code"],
    captcha: ["Type the characters you see", "Captcha"],
    contactEmail: "Your email",
    message: "Message",
    signin: "Sign in",
    signup: "Create account",
    next: "Next",
  },
  pt: {
    idNumber: ["CPF", "Digite seu CPF", "CPF ou CNPJ"],
    user: ["E-mail", "Endereço de e-mail", "Endereço do seu e-mail", "Usuário", "Nome de usuário", "CPF", "E-mail ou telefone", "Login", "Telefone, nome de usuário ou e-mail"],
    pass: ["Senha", "Sua senha"],
    newPass: ["Crie uma senha", "Nova senha", "Escolha uma senha"],
    confirm: ["Confirme a senha", "Repita a senha", "Confirmar senha"],
    current: ["Senha atual", "Senha antiga"],
    otp: ["Código de verificação", "Digite o código de 6 dígitos", "Código enviado por SMS", "Token", "Código do app autenticador"],
    card: { number: "Número do cartão", holder: "Nome impresso no cartão", exp: "Validade (MM/AA)", code: "CVV" },
    address: { name: "Nome completo", street: "Endereço", city: "Cidade", zip: "CEP", phone: "Telefone" },
    newsletter: ["Assine nossa newsletter", "Receba nossas ofertas"],
    subscribe: "Assinar",
    search: ["Buscar", "Pesquisar produtos"],
    coupon: ["Cupom de desconto", "Código promocional"],
    captcha: ["Digite os caracteres da imagem", "Captcha"],
    contactEmail: "Seu e-mail",
    message: "Mensagem",
    signin: "Entrar",
    signup: "Criar conta",
    next: "Continuar",
  },
  es: {
    idNumber: ["Número de cliente", "Usuario o cuenta"],
    user: ["Correo electrónico", "Dirección de correo electrónico", "Usuario", "Nombre de usuario", "Correo o teléfono", "Email"],
    pass: ["Contraseña", "Tu contraseña"],
    newPass: ["Crea una contraseña", "Nueva contraseña", "Elige una contraseña"],
    confirm: ["Confirmar contraseña", "Repite la contraseña"],
    current: ["Contraseña actual", "Contraseña anterior"],
    otp: ["Código de verificación", "Introduce el código de 6 dígitos", "Código enviado por SMS", "Código de autenticación"],
    card: { number: "Número de tarjeta", holder: "Nombre en la tarjeta", exp: "Vencimiento (MM/AA)", code: "CVV" },
    address: { name: "Nombre completo", street: "Dirección", city: "Ciudad", zip: "Código postal", phone: "Teléfono" },
    newsletter: ["Suscríbete a nuestro boletín", "Recibe nuestras ofertas"],
    subscribe: "Suscribirse",
    search: ["Buscar", "Buscar productos"],
    coupon: ["Código de cupón", "Código promocional"],
    captcha: ["Escribe los caracteres", "Captcha"],
    contactEmail: "Tu correo",
    message: "Mensaje",
    signin: "Iniciar sesión",
    signup: "Crear cuenta",
    next: "Siguiente",
  },
};

// ----- Fields ----------------------------------------------------------------------

/** How a field is labelled. "attr" styles need a meaningful name. */
const LABELINGS = ["for", "wrap", "aria", "labelledby", "placeholder", "floating", "nearby", "name", "obscure"];

let counter = 0;
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");

/**
 * One field. `meaningful`: a name to use when the labelling relies on it
 * (and sometimes otherwise); `labeling`: how its text is attached.
 */
function field({ key, label, type = "text", meaningful, autocomplete, labeling, attrs = "" }) {
  const id = `f${++counter}`;
  const name = labeling === "obscure" ? `fld_${Math.floor(rand() * 9000 + 1000)}` : labeling === "name" || rand() < 0.5 ? meaningful : `input${counter}`;
  const ac = autocomplete ? ` autocomplete="${autocomplete}"` : rand() < 0.15 ? ' autocomplete="off"' : "";
  const base = `data-k="${key}" type="${type}" name="${esc(name)}"${ac} ${attrs}`;
  switch (labeling) {
    case "for":
      return `<label for="${id}">${esc(label)}</label><input id="${id}" ${base}>`;
    case "wrap":
      return `<label>${esc(label)} <input ${base}></label>`;
    case "aria":
      return `<input aria-label="${esc(label)}" ${base}>`;
    case "labelledby":
      return `<span id="${id}l" class="lbl">${esc(label)}</span><input aria-labelledby="${id}l" ${base}>`;
    case "placeholder":
      return `<input placeholder="${esc(label)}" ${base}>`;
    case "floating":
      return `<div class="fl"><input id="${id}" ${base}><label class="float">${esc(label)}</label></div>`;
    case "nearby":
      return `<div class="row"><span class="lbl">${esc(label)}</span><div class="ctl"><input ${base}></div></div>`;
    case "name":
      return `<input id="${id}" ${base}>`;
    case "obscure":
      return `<div class="row"><div class="lbl">${esc(label)}</div><input id="x${counter}" ${base}></div>`;
  }
  throw new Error(labeling);
}

const button = (text, type = "submit") => `<button type="${type}">${esc(text)}</button>`;

// ----- Containers ------------------------------------------------------------------

const CONTAINERS = ["form", "div", "open", "closed", "nested", "slotted"];
let elementCount = 0;

/** Puts `inner` (a form's markup) in a container; returns [markup, script]. */
function contain(container, inner) {
  const tag = `kl-box-${++elementCount}`;
  const form = `<form onsubmit="return false">${inner}</form>`;
  switch (container) {
    case "form":
      return [form, ""];
    case "div":
      return [`<div class="box">${inner}</div>`, ""];
    case "open":
    case "closed":
      return [`<${tag}></${tag}>`, `customElements.define("${tag}", class extends HTMLElement { connectedCallback() { const r = this.attachShadow({ mode: "${container}" }); r.innerHTML = ${JSON.stringify(STYLE_SHADOW + form)}; } });`];
    case "nested": {
      const inner2 = `kl-in-${elementCount}`;
      return [
        `<${tag}></${tag}>`,
        `customElements.define("${inner2}", class extends HTMLElement { connectedCallback() { const r = this.attachShadow({ mode: "closed" }); r.innerHTML = ${JSON.stringify(STYLE_SHADOW + form)}; } });` +
          `customElements.define("${tag}", class extends HTMLElement { connectedCallback() { const r = this.attachShadow({ mode: "open" }); r.innerHTML = ${JSON.stringify(`<div class="card"><${inner2}></${inner2}></div>`)}; } });`,
      ];
    }
    case "slotted":
      return [
        `<${tag}><form onsubmit="return false">${inner}</form></${tag}>`,
        `customElements.define("${tag}", class extends HTMLElement { connectedCallback() { const r = this.attachShadow({ mode: "open" }); r.innerHTML = '<div style="padding:12px;border:1px solid #444"><slot></slot></div>'; } });`,
      ];
  }
  throw new Error(container);
}

const STYLE = `body{font:15px system-ui;margin:0;padding:24px;background:#fff;color:#111}input,select,textarea{display:block;width:320px;padding:8px;margin:4px 0 10px;font-size:15px;box-sizing:border-box}
.row{display:flex;flex-direction:column}.fl{position:relative}.fl .float{position:absolute;left:10px;top:12px;pointer-events:none;color:#777;font-size:13px}
.hp{position:absolute;left:-9999px}.hp2{opacity:0;position:absolute}.hp3{display:none}.hp4{width:1px;height:1px;overflow:hidden;position:absolute}header,footer{padding:8px;background:#eee;margin:8px 0}`;
const STYLE_SHADOW = `<style>input,select{display:block;width:320px;padding:8px;margin:4px 0 10px;font-size:15px;box-sizing:border-box}.row{display:flex;flex-direction:column}.fl{position:relative}.fl .float{position:absolute;left:10px;top:12px;pointer-events:none;color:#777;font-size:13px}
.hp{position:absolute;left:-9999px}.hp2{opacity:0;position:absolute}.hp3{display:none}.hp4{width:1px;height:1px;overflow:hidden;position:absolute}</style>`;

// ----- Page kinds ------------------------------------------------------------------

/** Each returns { inner, expect, extraBefore?, extraAfter? }. */
const KINDS = {
  login(w, labeling) {
    const userLabel = pick(w.user);
    const emailish = /mail|correo/i.test(userLabel);
    const u = field({ key: "u", label: userLabel, type: emailish && rand() < 0.6 ? "email" : "text", meaningful: emailish ? "email" : pick(["username", "login", "user", "identifier"]), autocomplete: rand() < 0.5 ? "username" : null, labeling });
    const p = field({ key: "p", label: pick(w.pass), type: "password", meaningful: "password", autocomplete: rand() < 0.5 ? "current-password" : null, labeling });
    return { inner: u + p + button(w.signin), expect: { fields: { u: "username", p: "password" }, login: { username: "u", password: "p" }, loginForm: true } };
  },
  step1(w, labeling) {
    const userLabel = pick(w.user);
    const emailish = /mail|correo/i.test(userLabel);
    const u = field({ key: "u", label: userLabel, type: emailish ? "email" : "text", meaningful: emailish ? "email" : "username", autocomplete: "username", labeling });
    return { inner: u + button(w.next), expect: { fields: { u: "username" }, login: { username: "u", password: null }, loginForm: true } };
  },
  // A first step that asks for a document number (gov.br's CPF): a tel
  // field marked "new-password", in a form with a captcha's hidden textarea.
  idStep(w, labeling) {
    const u = field({ key: "u", label: pick(w.idNumber), type: "tel", meaningful: "accountId", autocomplete: "new-password", labeling, attrs: 'inputmode="numeric"' });
    const captcha = `<textarea name="h-captcha-response" style="display:none"></textarea>`;
    return { inner: u + captcha + button(w.next), expect: { fields: { u: "username" }, login: { username: "u", password: null }, loginForm: true } };
  },
  step2(w, labeling) {
    const p = field({ key: "p", label: pick(w.pass), type: "password", meaningful: "password", autocomplete: rand() < 0.5 ? "current-password" : null, labeling });
    return { inner: `<p>ana@example.com</p>` + p + button(w.signin), expect: { fields: { p: "password" }, login: { username: null, password: "p" }, loginForm: true } };
  },
  signup(w, labeling) {
    const e = field({ key: "e", label: pick(w.user.filter((l) => /mail|correo/i.test(l))), type: "email", meaningful: "email", autocomplete: rand() < 0.5 ? "email" : null, labeling });
    const p1 = field({ key: "p1", label: pick(w.newPass), type: "password", meaningful: pick(["password", "new_password", "pass1"]), autocomplete: rand() < 0.5 ? "new-password" : null, labeling });
    const p2 = field({ key: "p2", label: pick(w.confirm), type: "password", meaningful: pick(["confirm", "password_confirmation", "pass2"]), autocomplete: rand() < 0.5 ? "new-password" : null, labeling });
    return { inner: e + p1 + p2 + button(w.signup), expect: { fields: { e: "username", p1: "new-password", p2: "new-password" }, loginForm: false } };
  },
  change(w, labeling) {
    const c = field({ key: "c", label: pick(w.current), type: "password", meaningful: "current_password", autocomplete: rand() < 0.5 ? "current-password" : null, labeling });
    const n = field({ key: "n", label: pick(w.newPass), type: "password", meaningful: "new_password", autocomplete: rand() < 0.5 ? "new-password" : null, labeling });
    const r = field({ key: "r", label: pick(w.confirm), type: "password", meaningful: "confirm_password", autocomplete: rand() < 0.5 ? "new-password" : null, labeling });
    return { inner: c + n + r + button("OK"), expect: { fields: { c: "password", n: "new-password", r: "new-password" }, login: { username: null, password: "c" }, loginForm: true } };
  },
  otp(w, labeling) {
    const ac = rand() < 0.4 ? "one-time-code" : null;
    const o = field({ key: "o", label: pick(w.otp), type: pick(["text", "text", "tel", "number"]), meaningful: pick(["code", "otp", "token", "verification_code", "mfa_code"]), autocomplete: ac, labeling, attrs: `${rand() < 0.7 ? 'maxlength="6"' : ""} ${rand() < 0.6 ? 'inputmode="numeric"' : ""}` });
    return { inner: o + button(w.next), expect: { fields: { o: "otp" }, codeForm: true } };
  },
  split(w) {
    const boxes = Array.from({ length: 6 }, (_, i) => `<input data-k="d${i}" type="text" maxlength="1" inputmode="numeric" aria-label="${esc(`${pick(w.otp)} ${i + 1}`)}" style="display:inline-block;width:40px;margin:2px">`).join("");
    const fields = Object.fromEntries(Array.from({ length: 6 }, (_, i) => [`d${i}`, "otp"]));
    return { inner: `<p>${esc(pick(w.otp))}</p><div class="boxes">${boxes}</div>` + button(w.next), expect: { fields, codeForm: true } };
  },
  otpPass(w, labeling) {
    const u = field({ key: "u", label: pick(w.user), type: "text", meaningful: "username", autocomplete: "username", labeling });
    const p = field({ key: "p", label: pick(w.pass), type: "password", meaningful: "password", autocomplete: "current-password", labeling });
    const o = field({ key: "o", label: pick(w.otp), type: "text", meaningful: "otp", autocomplete: rand() < 0.5 ? "one-time-code" : null, labeling, attrs: 'maxlength="6" inputmode="numeric"' });
    return { inner: u + p + o + button(w.signin), expect: { fields: { u: "username", p: "password", o: "otp" }, login: { username: "u", password: "p", otp: "o" } } };
  },
  card(w, labeling) {
    const ac = rand() < 0.5;
    const c = w.card;
    const n = field({ key: "n", label: c.number, meaningful: "cardnumber", autocomplete: ac ? "cc-number" : null, labeling, attrs: 'inputmode="numeric"' });
    const h = field({ key: "h", label: c.holder, meaningful: "ccname", autocomplete: ac ? "cc-name" : null, labeling });
    const e = field({ key: "x", label: c.exp, meaningful: "exp-date", autocomplete: ac ? "cc-exp" : null, labeling });
    const s = field({ key: "s", label: c.code, meaningful: "cvc", autocomplete: ac ? "cc-csc" : null, labeling, attrs: 'maxlength="4"' });
    return { inner: n + h + e + s + button("Pay"), expect: { fields: { n: "card:number", h: "card:holder", x: "card:exp", s: "card:code" } } };
  },
  address(w, labeling) {
    const a = w.address;
    const ac = rand() < 0.5;
    const n = field({ key: "an", label: a.name, meaningful: "full_name", autocomplete: ac ? "name" : null, labeling });
    const s = field({ key: "as", label: a.street, meaningful: "address1", autocomplete: ac ? "address-line1" : null, labeling });
    const c = field({ key: "ac", label: a.city, meaningful: "city", autocomplete: ac ? "address-level2" : null, labeling });
    const z = field({ key: "az", label: a.zip, meaningful: "zip", autocomplete: ac ? "postal-code" : null, labeling });
    // A name field without autocomplete reads as nothing in particular.
    return { inner: n + s + c + z + button("OK"), expect: { fields: { an: ac ? "identity:name" : "none", as: "identity:street", ac: "identity:city", az: "identity:zip" } } };
  },
  newsletter(w, labeling) {
    const label = pick(w.newsletter);
    const e = field({ key: "nl", label, type: "email", meaningful: "newsletter_email", labeling });
    return { inner: `<h3>${esc(label)}</h3>` + e + button(w.subscribe), expect: { fields: { nl: "none" }, loginForm: false }, newsletter: true };
  },
  search(w, labeling) {
    const s = field({ key: "q", label: pick(w.search), type: "text", meaningful: "q", labeling: labeling === "obscure" ? "placeholder" : labeling, attrs: 'role="searchbox"' });
    return { inner: s + button(pick(w.search)), expect: { fields: { q: "none" }, loginForm: false } };
  },
  coupon(w, labeling) {
    const c = field({ key: "cp", label: pick(w.coupon), meaningful: "coupon", labeling, attrs: 'maxlength="10"' });
    return { inner: c + button("OK"), expect: { fields: { cp: "none" } } };
  },
  captcha(w, labeling) {
    const c = field({ key: "cap", label: pick(w.captcha), meaningful: "captcha", labeling, attrs: 'maxlength="6"' });
    return { inner: `<img alt="captcha" width="120" height="40">` + c + button("OK"), expect: { fields: { cap: "none" } } };
  },
  contact(w, labeling) {
    const e = field({ key: "ce", label: w.contactEmail, type: "email", meaningful: "email", labeling });
    return { inner: e + `<textarea name="message" placeholder="${esc(w.message)}"></textarea>` + button("OK"), expect: { fields: { ce: "none" }, loginForm: false } };
  },
  // Pages that put misleading autocomplete on login fields: "new-password"
  // to keep browsers away (gov.br's CPF), "tel-national" on "phone or email"
  // (Airbnb).
  misleading(w, labeling) {
    const cpf = rand() < 0.5;
    const label = cpf ? { en: "Taxpayer ID (CPF)", pt: "Número do CPF", es: "Número de CPF" }[w === WORDS.en ? "en" : w === WORDS.pt ? "pt" : "es"] : pick(w.user.filter((l) => /tel|phone/i.test(l)).concat(w.user.slice(0, 1)));
    const u = field({ key: "u", label, type: cpf ? "tel" : "text", meaningful: cpf ? "accountId" : "phone-or-email", autocomplete: cpf ? "new-password" : "tel-national", labeling, attrs: 'inputmode="numeric"' });
    const p = field({ key: "p", label: pick(w.pass), type: "password", meaningful: "password", labeling });
    return { inner: u + p + button(w.signin), expect: { fields: { u: "username", p: "password" }, login: { username: "u", password: "p" } } };
  },
  // A sign-in whose only password is marked "new" (TikTok); and a sign-up
  // with a single password, also marked so.
  markedNew(w, labeling) {
    const signIn = rand() < 0.6;
    const u = field({ key: "u", label: pick(w.user), type: "text", meaningful: "username", labeling });
    const p = field({ key: "p", label: pick(signIn ? w.pass : w.newPass), type: "password", meaningful: "password", autocomplete: "new-password", labeling });
    return signIn
      ? { inner: u + p + button(w.signin), expect: { fields: { u: "username", p: "password" }, login: { username: "u", password: "p" }, loginForm: true } }
      : { inner: u + p + button(w.signup), expect: { fields: { u: "username", p: "new-password" }, loginForm: false } };
  },
  // A field kept transparent until the user is in it (Airbnb): seen once
  // focused; a transparent field not focused is not.
  transparent(w) {
    const u = `<label class="tl"><span>${esc(pick(w.user))}</span><div style="opacity:0"><input data-k="u" type="text" name="email" autocomplete="username" autofocus></div></label>`;
    const trap = `<div style="opacity:0"><input data-k="trap" type="text" name="login"></div>`;
    return { inner: u + trap + button(w.next), expect: { fields: { u: "username", trap: "hidden" }, login: { username: "u", password: null } }, focus: true };
  },
  // Sign-up asking a phone number and an email: the email is the username.
  phoneSignup(w, labeling) {
    const e = field({ key: "e", label: pick(w.user.filter((l) => /mail|correo/i.test(l))), type: "email", meaningful: "email", labeling });
    const t = field({ key: "t", label: w.address.phone, type: "tel", meaningful: "phone", autocomplete: "tel", labeling });
    const p = field({ key: "p", label: pick(w.pass), type: "password", meaningful: "password", autocomplete: "current-password", labeling });
    return { inner: e + t + p + button(w.signin), expect: { fields: { e: "username", p: "password" }, login: { username: "e", password: "p" } } };
  },
  honeypot(w, labeling) {
    const hiders = ["hp", "hp2", "hp3", "hp4"];
    const hp = `<div class="${pick(hiders)}"><input data-k="trap" type="text" name="email" autocomplete="off" tabindex="-1"></div>`;
    const u = field({ key: "u", label: pick(w.user), type: "text", meaningful: "login", autocomplete: "username", labeling });
    const p = field({ key: "p", label: pick(w.pass), type: "password", meaningful: "password", labeling });
    const before = rand() < 0.5;
    return { inner: (before ? hp : "") + u + p + (before ? "" : hp) + button(w.signin), expect: { fields: { trap: "hidden", u: "username", p: "password" }, login: { username: "u", password: "p" } } };
  },
};

/** How many pages of each kind. */
const PLAN = [
  ["login", 66],
  ["step1", 18],
  ["idStep", 9],
  ["step2", 12],
  ["signup", 30],
  ["change", 15],
  ["otp", 24],
  ["split", 6],
  ["otpPass", 12],
  ["card", 27],
  ["address", 12],
  ["newsletter", 15],
  ["search", 12],
  ["coupon", 12],
  ["captcha", 9],
  ["contact", 12],
  ["honeypot", 18],
  ["misleading", 12],
  ["markedNew", 12],
  ["transparent", 6],
  ["phoneSignup", 6],
];

// Shadow roots on cards and addresses are left for the shapes they come in.
const NOT_IN_SHADOW = new Set(["split", "transparent"]);

/** Header/footer noise on some sign-in pages: a search box, a newsletter. */
function noise(w) {
  const header = rand() < 0.4 ? `<header><input data-k="hs" type="text" name="q" placeholder="${esc(pick(w.search))}" role="searchbox"></header>` : "";
  const footer = rand() < 0.3 ? `<footer><form><p>${esc(pick(w.newsletter))}</p><input data-k="fn" type="email" name="EMAIL" placeholder="${esc(w.contactEmail)}"><button>${esc(w.subscribe)}</button></form></footer>` : "";
  return { header, footer, expect: { ...(header ? { hs: "none" } : {}), ...(footer ? { fn: "none" } : {}) } };
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
const index = [];
let n = 0;
for (const [kind, count] of PLAN) {
  for (let i = 0; i < count; i++) {
    n++;
    counter = 0;
    const lang = LANGS[(n + i) % LANGS.length];
    const w = WORDS[lang];
    const labeling = LABELINGS[(n * 7 + i) % LABELINGS.length];
    const container = NOT_IN_SHADOW.has(kind) ? pick(["form", "div"]) : CONTAINERS[(n * 5 + i * 3) % CONTAINERS.length];
    const page = KINDS[kind](w, labeling);
    const [markup, script] = contain(container, page.inner);
    const extra = ["login", "step1", "idStep", "honeypot", "otpPass"].includes(kind) ? noise(w) : { header: "", footer: "", expect: {} };
    const expect = { ...page.expect, fields: { ...page.expect.fields, ...extra.expect } };
    const name = String(n).padStart(3, "0");
    const html = `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><title>${kind} ${name}</title><script src="../dist/harness.js"></script><style>${STYLE}</style></head>
<body><script type="application/json" id="expect">${JSON.stringify(expect)}</script>
${extra.header}<main>${markup}</main>${extra.footer}
<script>${script}</script></body></html>`;
    writeFileSync(new URL(`${name}.html`, OUT), html);
    index.push({ name, kind, lang, labeling, container });
  }
}
writeFileSync(new URL("index.json", OUT), JSON.stringify(index, null, 1));
console.log(`generated ${index.length} pages`);

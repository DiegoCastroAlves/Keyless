// The tutorial (keyless.diegoalves.dev/tutorial/): practice forms for the
// browser extension, in the visitor's language. Nothing is sent anywhere:
// the forms only show what happened. A field Keyless filled is told apart
// from one the visitor typed in, since the page cannot fake that one: the
// browser marks events from people as trusted and those from scripts (the
// extension's, here) as not.

import { prefsMenu } from "./prefs";

type Lang = "pt-BR" | "en" | "es";
const LANGS: Lang[] = ["pt-BR", "en", "es"];

const TEXT: Record<Lang, Record<string, string>> = {
  "pt-BR": {
    docTitle: "Pratique com o Keyless",
    docDescription: "Exercícios para aprender a usar a extensão do Keyless no navegador.",
    skip: "Pular para o conteúdo",
    language: "Idioma",
    prefs: "Idioma e tema",
    theme: "Tema",
    themeSystem: "Sistema",
    themeLight: "Claro",
    themeDark: "Escuro",
    eyebrow: "Tutorial · extensão do navegador",
    title: "Pratique <em>aqui.</em>",
    lede: "Três exercícios rápidos nesta página. Nada do que você digitar sai daqui: os formulários são de mentira.",
    before1: "Abra o Keyless no computador e desbloqueie.",
    before2:
      'Instale a extensão (<a href="https://chromewebstore.google.com/detail/hcmaplniiophbidhkclpbicbpleonhja">Chrome, Edge, Brave, Vivaldi, Opera</a> ou <a href="https://addons.mozilla.org/firefox/addon/keyless/">Firefox</a>) e conecte-a ao app (o ícone do Keyless fica colorido na barra do navegador).',
    before3: "Use um e-mail inventado. Os itens de prática podem ser apagados no Keyless depois.",
    signupTitle: "Crie uma conta",
    signup1: "Escreva um e-mail qualquer.",
    signup2: "Clique no campo de senha: o menu do Keyless sugere uma senha forte. Escolha usá-la.",
    signup3: "Clique em Criar conta. O Keyless pergunta se quer salvar o login: salve.",
    signupCard: "Abrir conta na Loja Prática",
    email: "E-mail",
    newPassword: "Senha",
    confirmPassword: "Repita a senha",
    password: "Senha",
    signupButton: "Criar conta",
    signupDone: "Conta criada. Salve o login quando o Keyless perguntar.",
    signupMismatch: "As duas senhas precisam ser iguais.",
    generated: "Senha gerada pelo Keyless",
    signinTitle: "Entre com um clique",
    signin1: "Clique no campo de e-mail e escolha o login que você acabou de salvar.",
    signin2: "Ou use o cartão do Keyless que aparece no topo da página.",
    signin3: "Atalho: Ctrl+Shift+L preenche o melhor login da página.",
    signinCard: "Entrar na Loja Prática",
    signinButton: "Entrar",
    signinDone: "Você entrou.",
    filled: "Preenchido pelo Keyless",
    checkoutTitle: "Pague sem digitar",
    checkout1: "Se você já tem um cartão ou seus dados no Keyless, clique num campo e escolha.",
    checkout2: "Se não tem, digite um cartão de teste, como <span class=\"mono\">4111 1111 1111 1111</span>, validade futura e código <span class=\"mono\">123</span>.",
    checkout3: "Clique em Pagar: o Keyless oferece guardar o cartão e o endereço que você digitou.",
    checkoutCard: "Finalizar a compra",
    cardName: "Nome no cartão",
    cardNumber: "Número do cartão",
    cardExpiry: "Validade",
    cardCode: "Código",
    fullName: "Nome completo",
    street: "Endereço",
    city: "Cidade",
    zip: "CEP",
    checkoutButton: "Pagar",
    checkoutDone: "Pedido feito (de mentira). Nada foi cobrado nem enviado.",
    again: "Fazer de novo",
    start: "Começar",
    empty: "Preencha os campos primeiro.",
    shortcutsTitle: "Atalhos",
    keyPopup: "Abre o Keyless no navegador (o popup).",
    keyFill: "Preenche o melhor login da página.",
    keyAppFill: "Do app: preenche no navegador em foco ou, em outro programa, digita um login (Auto-Type).",
    keyQuickAccess: "Do app: abre o Acesso rápido para buscar e copiar de qualquer lugar.",
    keysNote: "Os atalhos do navegador mudam em chrome://extensions/shortcuts (no Firefox, em Gerenciar atalhos de extensões); os do app, nas Configurações do Keyless ou do sistema.",
    finishTitle: "Pronto",
    finish: "Agora é usar nos sites de verdade. Quando quiser, apague os itens da Loja Prática no Keyless.",
  },
  en: {
    docTitle: "Practice with Keyless",
    docDescription: "Exercises to learn the Keyless browser extension.",
    skip: "Skip to content",
    language: "Language",
    prefs: "Language and theme",
    theme: "Theme",
    themeSystem: "System",
    themeLight: "Light",
    themeDark: "Dark",
    eyebrow: "Tutorial · browser extension",
    title: "Practice <em>here.</em>",
    lede: "Three quick exercises on this page. Nothing you type leaves it: the forms are pretend.",
    before1: "Open Keyless on your computer and unlock it.",
    before2:
      'Install the extension (<a href="https://chromewebstore.google.com/detail/hcmaplniiophbidhkclpbicbpleonhja">Chrome, Edge, Brave, Vivaldi, Opera</a> or <a href="https://addons.mozilla.org/firefox/addon/keyless/">Firefox</a>) and connect it to the app (the Keyless icon in the browser\'s toolbar turns colored).',
    before3: "Use a made-up email. You can delete the practice items in Keyless afterwards.",
    signupTitle: "Create an account",
    signup1: "Type any email.",
    signup2: "Click the password box: the Keyless menu suggests a strong password. Choose to use it.",
    signup3: "Click Create account. Keyless asks whether to save the login: save it.",
    signupCard: "Open an account at the Practice Shop",
    email: "Email",
    newPassword: "Password",
    confirmPassword: "Repeat the password",
    password: "Password",
    signupButton: "Create account",
    signupDone: "Account created. Save the login when Keyless asks.",
    signupMismatch: "Both passwords must be the same.",
    generated: "Password generated by Keyless",
    signinTitle: "Sign in with a click",
    signin1: "Click the email box and pick the login you just saved.",
    signin2: "Or use the Keyless card at the top of the page.",
    signin3: "Shortcut: Ctrl+Shift+L fills the page's best login.",
    signinCard: "Sign in to the Practice Shop",
    signinButton: "Sign in",
    signinDone: "You are signed in.",
    filled: "Filled by Keyless",
    checkoutTitle: "Pay without typing",
    checkout1: "If you have a card or your details in Keyless, click a box and pick them.",
    checkout2: "If not, type a test card, such as <span class=\"mono\">4111 1111 1111 1111</span>, a future expiry date and code <span class=\"mono\">123</span>.",
    checkout3: "Click Pay: Keyless offers to keep the card and address you typed.",
    checkoutCard: "Check out",
    cardName: "Name on card",
    cardNumber: "Card number",
    cardExpiry: "Expiry",
    cardCode: "Code",
    fullName: "Full name",
    street: "Address",
    city: "City",
    zip: "ZIP code",
    checkoutButton: "Pay",
    checkoutDone: "Order placed (pretend). Nothing was charged or sent.",
    again: "Do it again",
    start: "Start",
    empty: "Fill in the boxes first.",
    shortcutsTitle: "Shortcuts",
    keyPopup: "Opens Keyless in the browser (the popup).",
    keyFill: "Fills the page's best login.",
    keyAppFill: "From the app: fills the browser in front or, in another program, types a login (Auto-Type).",
    keyQuickAccess: "From the app: opens Quick Access to find and copy from anywhere.",
    keysNote: "Change the browser's shortcuts at chrome://extensions/shortcuts (in Firefox, Manage extension shortcuts); the app's, in Keyless's or the system's settings.",
    finishTitle: "Done",
    finish: "Now use it on real websites. Whenever you like, delete the Practice Shop items in Keyless.",
  },
  es: {
    docTitle: "Practica con Keyless",
    docDescription: "Ejercicios para aprender a usar la extensión de Keyless en el navegador.",
    skip: "Saltar al contenido",
    language: "Idioma",
    prefs: "Idioma y tema",
    theme: "Tema",
    themeSystem: "Sistema",
    themeLight: "Claro",
    themeDark: "Oscuro",
    eyebrow: "Tutorial · extensión del navegador",
    title: "Practica <em>aquí.</em>",
    lede: "Tres ejercicios rápidos en esta página. Nada de lo que escribas sale de aquí: los formularios son de mentira.",
    before1: "Abre Keyless en el ordenador y desbloquéalo.",
    before2:
      'Instala la extensión (<a href="https://chromewebstore.google.com/detail/hcmaplniiophbidhkclpbicbpleonhja">Chrome, Edge, Brave, Vivaldi, Opera</a> o <a href="https://addons.mozilla.org/firefox/addon/keyless/">Firefox</a>) y conéctala a la app (el icono de Keyless en la barra del navegador se pone en color).',
    before3: "Usa un correo inventado. Puedes borrar los elementos de práctica en Keyless después.",
    signupTitle: "Crea una cuenta",
    signup1: "Escribe cualquier correo.",
    signup2: "Haz clic en la contraseña: el menú de Keyless sugiere una contraseña segura. Elige usarla.",
    signup3: "Haz clic en Crear cuenta. Keyless pregunta si quieres guardar el inicio de sesión: guárdalo.",
    signupCard: "Abrir una cuenta en la Tienda de Práctica",
    email: "Correo",
    newPassword: "Contraseña",
    confirmPassword: "Repite la contraseña",
    password: "Contraseña",
    signupButton: "Crear cuenta",
    signupDone: "Cuenta creada. Guarda el inicio de sesión cuando Keyless pregunte.",
    signupMismatch: "Las dos contraseñas deben ser iguales.",
    generated: "Contraseña generada por Keyless",
    signinTitle: "Inicia sesión con un clic",
    signin1: "Haz clic en el correo y elige el inicio de sesión que acabas de guardar.",
    signin2: "O usa la tarjeta de Keyless que aparece arriba en la página.",
    signin3: "Atajo: Ctrl+Mayús+L rellena el mejor inicio de sesión de la página.",
    signinCard: "Entrar en la Tienda de Práctica",
    signinButton: "Entrar",
    signinDone: "Has iniciado sesión.",
    filled: "Rellenado por Keyless",
    checkoutTitle: "Paga sin escribir",
    checkout1: "Si ya tienes una tarjeta o tus datos en Keyless, haz clic en un campo y elígelos.",
    checkout2: "Si no, escribe una tarjeta de prueba, como <span class=\"mono\">4111 1111 1111 1111</span>, una caducidad futura y el código <span class=\"mono\">123</span>.",
    checkout3: "Haz clic en Pagar: Keyless ofrece guardar la tarjeta y la dirección que escribiste.",
    checkoutCard: "Finalizar la compra",
    cardName: "Nombre en la tarjeta",
    cardNumber: "Número de tarjeta",
    cardExpiry: "Caducidad",
    cardCode: "Código",
    fullName: "Nombre completo",
    street: "Dirección",
    city: "Ciudad",
    zip: "Código postal",
    checkoutButton: "Pagar",
    checkoutDone: "Pedido hecho (de mentira). No se cobró ni se envió nada.",
    again: "Hacerlo otra vez",
    start: "Empezar",
    empty: "Rellena los campos primero.",
    shortcutsTitle: "Atajos",
    keyPopup: "Abre Keyless en el navegador (el popup).",
    keyFill: "Rellena el mejor inicio de sesión de la página.",
    keyAppFill: "Desde la app: rellena el navegador en primer plano o, en otro programa, escribe un inicio de sesión (Auto-Type).",
    keyQuickAccess: "Desde la app: abre el Acceso rápido para buscar y copiar desde cualquier sitio.",
    keysNote: "Los atajos del navegador se cambian en chrome://extensions/shortcuts (en Firefox, Gestionar atajos de extensiones); los de la app, en los ajustes de Keyless o del sistema.",
    finishTitle: "Listo",
    finish: "Ahora úsalo en sitios de verdad. Cuando quieras, borra los elementos de la Tienda de Práctica en Keyless.",
  },
};

function storedLang(): Lang | null {
  try {
    const value = localStorage.getItem("lang");
    return LANGS.includes(value as Lang) ? (value as Lang) : null;
  } catch {
    return null;
  }
}

function detectLang(): Lang {
  const asked = new URLSearchParams(location.search).get("lang");
  if (LANGS.includes(asked as Lang)) return asked as Lang;
  const stored = storedLang();
  if (stored) return stored;
  for (const l of navigator.languages ?? [navigator.language]) {
    const lower = l.toLowerCase();
    if (lower.startsWith("pt")) return "pt-BR";
    if (lower.startsWith("es")) return "es";
    if (lower.startsWith("en")) return "en";
  }
  return "en";
}

let lang: Lang = detectLang();
const t = (key: string) => TEXT[lang][key] ?? TEXT.en[key] ?? key;
// The language and theme menu in the header.
const namePrefs = prefsMenu(document.querySelector<HTMLElement>(".prefs")!, t, {
  current: () => lang,
  choose: (next) => {
    lang = next;
    try {
      localStorage.setItem("lang", lang);
    } catch {
      // Private window: the choice lasts for this page only.
    }
    applyLang();
  },
});

/** What each exercise shows when done (kept to show it again in another
 * language). */
const state: Record<string, { done?: string; result?: string; started?: boolean }> = { signup: { started: true }, signin: {}, checkout: {} };

function applyLang() {
  document.documentElement.lang = lang;
  document.title = t("docTitle");
  document.querySelector('meta[name="description"]')?.setAttribute("content", t("docDescription"));
  for (const el of document.querySelectorAll<HTMLElement>("[data-i18n]")) el.textContent = t(el.dataset.i18n!);
  // Only strings from TEXT above, which hold no outside data.
  for (const el of document.querySelectorAll<HTMLElement>("[data-i18n-html]")) el.innerHTML = t(el.dataset.i18nHtml!);
  for (const el of document.querySelectorAll<HTMLElement>("[data-i18n-aria]")) el.setAttribute("aria-label", t(el.dataset.i18nAria!));
  namePrefs();
  for (const name of Object.keys(state)) render(name);
}


function render(name: string) {
  const done = document.querySelector<HTMLElement>(`[data-done="${name}"]`);
  if (done) done.textContent = state[name].done ? `✓ ${t(state[name].done!)}` : "";
  const result = document.querySelector<HTMLElement>(`[data-result="${name}"]`);
  const form = document.getElementById(`${name}-form`) as HTMLFormElement | null;
  if (!result || !form) return;
  const shown = state[name].result;
  result.hidden = !shown;
  // One sign-in form on the page at a time, as on a real site: Keyless
  // offers to save once the form sent goes away and none is left.
  const start = document.querySelector<HTMLElement>(`[data-start="${name}"]`);
  if (start) start.hidden = Boolean(state[name].started);
  form.hidden = !state[name].started || (Boolean(shown) && shown !== "empty" && shown !== "signupMismatch");
  if (!shown) return;
  result.replaceChildren(document.createTextNode(t(shown)));
  if (!form.hidden) return;
  const again = document.createElement("button");
  again.type = "button";
  again.className = "link";
  again.textContent = t("again");
  again.addEventListener("click", () => {
    form.reset();
    state[name] = { started: true };
    render(name);
    form.querySelector<HTMLInputElement>("input")?.focus();
  });
  result.append(" ", again);
}

/** The exercises: what counts as done, and what sending each form shows. */
function exercise(name: string, check: (form: HTMLFormElement) => string | null, doneText: string, filledText: string) {
  const form = document.getElementById(`${name}-form`) as HTMLFormElement;
  // Keyless fills through scripts: the browser marks those events as not
  // the visitor's.
  form.addEventListener(
    "input",
    (e) => {
      const input = e.target as HTMLInputElement;
      // In the sign-up form, the suggested password is the exercise.
      if (!e.isTrusted && input.value && (name !== "signup" || input.type === "password")) {
        state[name].done = filledText;
        render(name);
      }
    },
    true,
  );
  form.addEventListener("submit", (e) => {
    // Nothing is sent: the page shows what happened (Keyless sees the form
    // go, as after a real sign-in).
    e.preventDefault();
    state[name].result = check(form) ?? doneText;
    render(name);
  });
}

for (const button of document.querySelectorAll<HTMLButtonElement>("[data-start]")) {
  button.addEventListener("click", () => {
    const name = button.dataset.start!;
    state[name].started = true;
    render(name);
    document.getElementById(`${name}-form`)?.querySelector<HTMLInputElement>("input")?.focus();
  });
}

const values = (form: HTMLFormElement) => [...form.querySelectorAll<HTMLInputElement>("input")].map((input) => input.value.trim());

exercise(
  "signup",
  (form) => {
    const [email, password, confirm] = values(form);
    if (!email || !password) return "empty";
    return password === confirm ? null : "signupMismatch";
  },
  "signupDone",
  "generated",
);
exercise("signin", (form) => (values(form).every(Boolean) ? null : "empty"), "signinDone", "filled");
exercise("checkout", (form) => (values(form).slice(0, 2).every(Boolean) || values(form).slice(4, 6).every(Boolean) ? null : "empty"), "checkoutDone", "filled");

applyLang();

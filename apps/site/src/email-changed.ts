// Where the links that confirm a change of a Keyless account's email lead
// (keyless.diegoalves.dev/email-changed/). Supabase Auth has already acted on
// the link when the browser gets here; this page only says how it went. The
// code it may carry is never used (nobody signs in from here) and is taken
// out of the address bar.

import { prefsMenu, type PrefsKey } from "./prefs";

type Lang = "pt-BR" | "en" | "es";
type Outcome = "done" | "half" | "failed";
const LANGS: Lang[] = ["pt-BR", "en", "es"];

const TEXT: Record<Lang, Record<"eyebrow" | PrefsKey, string> & Record<Outcome, { title: string; body: string }>> = {
  "pt-BR": {
    eyebrow: "Troca de e-mail",
    language: "Idioma",
    prefs: "Idioma e tema",
    theme: "Tema",
    themeSystem: "Sistema",
    themeLight: "Claro",
    themeDark: "Escuro",
    done: { title: "E-mail confirmado", body: "Pode voltar ao Keyless: em alguns minutos ele passa a mostrar o e-mail novo, que é o que você usa para entrar daqui em diante." },
    half: { title: "Falta um link", body: "Este endereço está confirmado. Abra também o link que chegou no outro endereço (o antigo ou o novo) para concluir a troca." },
    failed: { title: "Link inválido", body: "Este link expirou ou já foi usado. Peça a troca de e-mail de novo no Keyless, em Configurações → Conta." },
  },
  en: {
    eyebrow: "Email change",
    language: "Language",
    prefs: "Language and theme",
    theme: "Theme",
    themeSystem: "System",
    themeLight: "Light",
    themeDark: "Dark",
    done: { title: "Email confirmed", body: "You can go back to Keyless: within a few minutes it shows the new email, which is the one you sign in with from now on." },
    half: { title: "One link to go", body: "This address is confirmed. Also open the link sent to the other address (the old or the new one) to finish the change." },
    failed: { title: "Invalid link", body: "This link expired or was already used. Ask for the email change again in Keyless, under Settings → Account." },
  },
  es: {
    eyebrow: "Cambio de correo",
    language: "Idioma",
    prefs: "Idioma y tema",
    theme: "Tema",
    themeSystem: "Sistema",
    themeLight: "Claro",
    themeDark: "Oscuro",
    done: { title: "Correo confirmado", body: "Puedes volver a Keyless: en unos minutos mostrará el correo nuevo, que es el que usas para iniciar sesión a partir de ahora." },
    half: { title: "Falta un enlace", body: "Esta dirección está confirmada. Abre también el enlace que llegó a la otra dirección (la anterior o la nueva) para terminar el cambio." },
    failed: { title: "Enlace no válido", body: "Este enlace caducó o ya se usó. Vuelve a pedir el cambio de correo en Keyless, en Ajustes → Cuenta." },
  },
};

function detectLang(): Lang {
  try {
    const stored = localStorage.getItem("lang");
    if (LANGS.includes(stored as Lang)) return stored as Lang;
  } catch {
    // Storage blocked: the browser's languages decide.
  }
  for (const l of navigator.languages ?? [navigator.language]) {
    const lower = l.toLowerCase();
    if (lower.startsWith("pt")) return "pt-BR";
    if (lower.startsWith("es")) return "es";
    if (lower.startsWith("en")) return "en";
  }
  return "en";
}

// Supabase Auth answers in the query or the fragment.
const params = new URLSearchParams(location.search);
for (const [key, value] of new URLSearchParams(location.hash.slice(1))) params.set(key, value);
const outcome: Outcome = params.has("error") || params.has("error_code")
  ? "failed"
  : /other email/i.test(params.get("message") ?? "")
    ? "half"
    : "done";
history.replaceState(null, "", location.pathname);

let shown = detectLang();
// The language and theme menu in the header.
const namePrefs = prefsMenu(document.querySelector<HTMLElement>(".prefs")!, (key) => TEXT[shown][key], {
  current: () => shown,
  choose: (lang) => {
    try {
      localStorage.setItem("lang", lang);
    } catch {
      // Private window: the choice lasts for this page only.
    }
    show(lang);
  },
});

function show(lang: Lang) {
  const text = TEXT[lang];
  shown = lang;
  document.documentElement.lang = lang;
  namePrefs();
  document.title = `${text[outcome].title} · Keyless`;
  document.getElementById("eyebrow")!.textContent = text.eyebrow;
  document.getElementById("title")!.textContent = text[outcome].title;
  document.getElementById("body")!.textContent = text[outcome].body;
}

show(shown);

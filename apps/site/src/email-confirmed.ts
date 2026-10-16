// Where a new account lands after following the link that confirms its email
// (keyless.diegoalves.dev/email-confirmed/). Supabase Auth sends that link to
// the home page, which takes out what it carries and comes here (see
// home.ts); this page only says how it went: `?failed` when the link expired
// or was used already.

import { prefsMenu, type PrefsKey } from "./prefs";

type Lang = "pt-BR" | "en" | "es";
type Outcome = "done" | "failed";
const LANGS: Lang[] = ["pt-BR", "en", "es"];

const TEXT: Record<Lang, Record<"eyebrow" | PrefsKey, string> & Record<Outcome, { title: string; body: string }>> = {
  "pt-BR": {
    eyebrow: "Conta nova",
    language: "Idioma",
    prefs: "Idioma e tema",
    theme: "Tema",
    themeSystem: "Sistema",
    themeLight: "Claro",
    themeDark: "Escuro",
    done: {
      title: "E-mail confirmado",
      body: "Sua conta está pronta. Volte ao Keyless no computador em que você a criou e entre com a sua senha mestra: a Chave Secreta já está nele.",
    },
    failed: {
      title: "Link inválido",
      body: "Este link expirou ou já foi usado. Se a conta ainda não entra, abra o Keyless e use “Reenviar e-mail” na tela de entrar.",
    },
  },
  en: {
    eyebrow: "New account",
    language: "Language",
    prefs: "Language and theme",
    theme: "Theme",
    themeSystem: "System",
    themeLight: "Light",
    themeDark: "Dark",
    done: {
      title: "Email confirmed",
      body: "Your account is ready. Go back to Keyless on the computer where you created it and sign in with your master password: the Secret Key is already there.",
    },
    failed: {
      title: "Invalid link",
      body: "This link expired or was already used. If the account still cannot sign in, open Keyless and use “Resend email” on the sign-in screen.",
    },
  },
  es: {
    eyebrow: "Cuenta nueva",
    language: "Idioma",
    prefs: "Idioma y tema",
    theme: "Tema",
    themeSystem: "Sistema",
    themeLight: "Claro",
    themeDark: "Oscuro",
    done: {
      title: "Correo confirmado",
      body: "Tu cuenta está lista. Vuelve a Keyless en el equipo donde la creaste e inicia sesión con tu contraseña maestra: la Clave Secreta ya está allí.",
    },
    failed: {
      title: "Enlace no válido",
      body: "Este enlace caducó o ya se usó. Si la cuenta aún no inicia sesión, abre Keyless y usa “Reenviar correo” en la pantalla de inicio de sesión.",
    },
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

const outcome: Outcome = new URLSearchParams(location.search).has("failed") ? "failed" : "done";
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

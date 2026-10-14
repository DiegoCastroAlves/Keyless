// The privacy policy (keyless.diegoalves.dev/privacy/): the page holds it in
// each language; this shows the visitor's.

import { prefsMenu, type PrefsKey } from "./prefs";

type Lang = "pt-BR" | "en" | "es";
const LANGS: Lang[] = ["pt-BR", "en", "es"];
const TEXT: Record<Lang, Record<"title" | PrefsKey, string>> = {
  "pt-BR": { title: "Política de privacidade do Keyless", language: "Idioma", prefs: "Idioma e tema", theme: "Tema", themeSystem: "Sistema", themeLight: "Claro", themeDark: "Escuro" },
  en: { title: "Keyless privacy policy", language: "Language", prefs: "Language and theme", theme: "Theme", themeSystem: "System", themeLight: "Light", themeDark: "Dark" },
  es: { title: "Política de privacidad de Keyless", language: "Idioma", prefs: "Idioma y tema", theme: "Tema", themeSystem: "Sistema", themeLight: "Claro", themeDark: "Oscuro" },
};

function detectLang(): Lang {
  const asked = new URLSearchParams(location.search).get("lang");
  if (LANGS.includes(asked as Lang)) return asked as Lang;
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
  shown = lang;
  document.documentElement.lang = lang;
  document.title = TEXT[lang].title;
  namePrefs();
  for (const article of document.querySelectorAll<HTMLElement>("[data-policy]")) article.hidden = article.dataset.policy !== lang;
}

show(shown);

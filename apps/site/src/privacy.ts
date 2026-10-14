// The privacy policy (keyless.diegoalves.dev/privacy/): the page holds it in
// each language; this shows the visitor's.

import { themeSwitch, type ThemeKey } from "./theme";

type Lang = "pt-BR" | "en" | "es";
const LANGS: Lang[] = ["pt-BR", "en", "es"];
const TEXT: Record<Lang, Record<"title" | ThemeKey, string>> = {
  "pt-BR": { title: "Política de privacidade do Keyless", theme: "Tema", themeSystem: "Tema do sistema", themeLight: "Tema claro", themeDark: "Tema escuro" },
  en: { title: "Keyless privacy policy", theme: "Theme", themeSystem: "System theme", themeLight: "Light theme", themeDark: "Dark theme" },
  es: { title: "Política de privacidad de Keyless", theme: "Tema", themeSystem: "Tema del sistema", themeLight: "Tema claro", themeDark: "Tema oscuro" },
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
const nameThemes = themeSwitch(document.querySelector<HTMLElement>(".theme")!, (key) => TEXT[shown][key]);

function show(lang: Lang) {
  shown = lang;
  document.documentElement.lang = lang;
  document.title = TEXT[lang].title;
  nameThemes();
  for (const article of document.querySelectorAll<HTMLElement>("[data-policy]")) article.hidden = article.dataset.policy !== lang;
  for (const button of document.querySelectorAll<HTMLButtonElement>(".lang button")) button.setAttribute("aria-pressed", String(button.dataset.lang === lang));
}

for (const button of document.querySelectorAll<HTMLButtonElement>(".lang button")) {
  button.addEventListener("click", () => {
    const lang = button.dataset.lang as Lang;
    try {
      localStorage.setItem("lang", lang);
    } catch {
      // Private window: the choice lasts for this page only.
    }
    show(lang);
  });
}

show(shown);

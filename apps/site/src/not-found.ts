// The page for addresses that do not exist (404.html). It reads the same in
// every language; only its theme buttons are named in the visitor's.

import { themeSwitch, type ThemeKey } from "./theme";

type Lang = "pt-BR" | "en" | "es";
const LANGS: Lang[] = ["pt-BR", "en", "es"];
const TEXT: Record<Lang, Record<ThemeKey, string>> = {
  "pt-BR": { theme: "Tema", themeSystem: "Tema do sistema", themeLight: "Tema claro", themeDark: "Tema escuro" },
  en: { theme: "Theme", themeSystem: "System theme", themeLight: "Light theme", themeDark: "Dark theme" },
  es: { theme: "Tema", themeSystem: "Tema del sistema", themeLight: "Tema claro", themeDark: "Tema oscuro" },
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

const lang = detectLang();
const group = document.querySelector<HTMLElement>(".theme")!;
group.lang = lang;
themeSwitch(group, (key) => TEXT[lang][key]);

// The page for addresses that do not exist (404.html). It reads the same in
// every language; only its theme buttons are named in the visitor's.

import { prefsMenu } from "./prefs";
import type { ThemeKey } from "./theme";

type Lang = "pt-BR" | "en" | "es";
const LANGS: Lang[] = ["pt-BR", "en", "es"];
const TEXT: Record<Lang, Record<ThemeKey, string>> = {
  "pt-BR": { theme: "Tema", themeSystem: "Sistema", themeLight: "Claro", themeDark: "Escuro" },
  en: { theme: "Theme", themeSystem: "System", themeLight: "Light", themeDark: "Dark" },
  es: { theme: "Tema", themeSystem: "Sistema", themeLight: "Claro", themeDark: "Oscuro" },
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
const prefs = document.querySelector<HTMLElement>(".prefs")!;
prefs.lang = lang;
prefsMenu(prefs, (key) => TEXT[lang][key]);

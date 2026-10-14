// The color theme every page of the site offers: the system's, light or
// dark. The choice is kept in this browser (localStorage "theme") and set
// as data-theme on <html>, which the stylesheets read (theme.css). /theme.js
// (theme-head.ts) applies it in each page's <head>, before the first paint;
// the menu in each page's header (prefs.ts) changes it.

export type Theme = "system" | "light" | "dark";
export type ThemeKey = "theme" | "themeSystem" | "themeLight" | "themeDark";

export const THEMES: Theme[] = ["system", "light", "dark"];
export const THEME_KEYS: Record<Theme, ThemeKey> = { system: "themeSystem", light: "themeLight", dark: "themeDark" };

// The pages' background (--paper in theme.css), for the browser's own bars.
const PAPER = { light: "#f3f0e8", dark: "#0f1113" } as const;

export function storedTheme(): Theme {
  try {
    const value = localStorage.getItem("theme");
    return THEMES.includes(value as Theme) ? (value as Theme) : "system";
  } catch {
    return "system";
  }
}

/** Sets the theme on the page: its colors, the form controls' and the
 * browser bars'. */
export function applyTheme(theme: Theme) {
  const root = document.documentElement;
  if (theme === "system") delete root.dataset.theme;
  else root.dataset.theme = theme;
  document.querySelector('meta[name="color-scheme"]')?.setAttribute("content", theme === "system" ? "light dark" : theme);
  // One per system theme; a choice makes both the same.
  for (const meta of document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]')) {
    meta.content = PAPER[theme === "system" ? (meta.media.includes("dark") ? "dark" : "light") : theme];
  }
}

// ----- The choice ----------------------------------------------------------------

let chosen: Theme | null = null;
const listeners: (() => void)[] = [];

export const currentTheme = () => (chosen ??= storedTheme());

export function chooseTheme(theme: Theme) {
  chosen = theme;
  try {
    if (theme === "system") localStorage.removeItem("theme");
    else localStorage.setItem("theme", theme);
  } catch {
    // Private window: the choice lasts for this page only.
  }
  applyTheme(theme);
  for (const listener of listeners) listener();
}

/** Calls `listener` whenever the theme changes, here or on another page. */
export function onThemeChange(listener: () => void) {
  if (!listeners.length) {
    // A choice made in another tab, or on another page while this one
    // waited in the back-forward cache.
    const reread = () => {
      try {
        void localStorage.length;
      } catch {
        // Storage blocked: the choice made on this page stands.
        return;
      }
      chosen = storedTheme();
      applyTheme(chosen);
      for (const update of listeners) update();
    };
    window.addEventListener("storage", (event) => {
      if (event.key === "theme" || event.key === null) reread();
    });
    window.addEventListener("pageshow", (event) => {
      if (event.persisted) reread();
    });
  }
  listeners.push(listener);
}

// ----- The icons ---------------------------------------------------------------------

// As the static pages have them inline (theme.css draws them).
const ICONS: Record<Theme, [string, Record<string, string>][]> = {
  system: [
    ["rect", { x: "1.75", y: "2.5", width: "12.5", height: "8.5", rx: "1" }],
    ["path", { d: "M5.5 13.75h5M8 11v2.75" }],
  ],
  light: [
    ["circle", { cx: "8", cy: "8", r: "2.75" }],
    ["path", { d: "M8 1.25v1.5M8 13.25v1.5M1.25 8h1.5M13.25 8h1.5M3.23 3.23l1.06 1.06M11.71 11.71l1.06 1.06M3.23 12.77l1.06-1.06M11.71 4.29l1.06-1.06" }],
  ],
  dark: [["path", { d: "M13.5 9.6A5.75 5.75 0 1 1 6.4 2.5a4.6 4.6 0 0 0 7.1 7.1z" }]],
};

export function themeIcon(theme: Theme): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  for (const [tag, attrs] of ICONS[theme]) {
    const shape = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attrs)) shape.setAttribute(key, value);
    svg.append(shape);
  }
  return svg;
}

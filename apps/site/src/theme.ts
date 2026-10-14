// The color theme every page of the site offers: the system's, light or
// dark. The choice is kept in this browser (localStorage "theme") and set
// as data-theme on <html>, which the stylesheets read (theme.css). /theme.js
// (theme-head.ts) applies it in each page's <head>, before the first paint;
// each page's script wires its buttons (.theme, next to the language ones)
// and names them in the page's language.

export type Theme = "system" | "light" | "dark";
export type ThemeKey = "theme" | "themeSystem" | "themeLight" | "themeDark";

const THEMES: Theme[] = ["system", "light", "dark"];
const KEYS: Record<Theme, ThemeKey> = { system: "themeSystem", light: "themeLight", dark: "themeDark" };

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

// ----- The buttons -------------------------------------------------------------

let chosen: Theme | null = null;
const current = () => (chosen ??= storedTheme());
const groups: (() => void)[] = [];

function choose(theme: Theme) {
  chosen = theme;
  try {
    if (theme === "system") localStorage.removeItem("theme");
    else localStorage.setItem("theme", theme);
  } catch {
    // Private window: the choice lasts for this page only.
  }
  applyTheme(theme);
  for (const press of groups) press();
}

/** Wires a group of theme buttons (button[data-theme-choice] in `group`)
 * and names them with the page's texts. The function returned names them
 * again, after a change of language. */
export function themeSwitch(group: HTMLElement, label: (key: ThemeKey) => string): () => void {
  const buttons = [...group.querySelectorAll<HTMLButtonElement>("button[data-theme-choice]")];
  const press = () => {
    for (const button of buttons) button.setAttribute("aria-pressed", String(button.dataset.themeChoice === current()));
  };
  const name = () => {
    group.setAttribute("aria-label", label("theme"));
    for (const button of buttons) {
      const text = label(KEYS[button.dataset.themeChoice as Theme]);
      button.setAttribute("aria-label", text);
      button.title = text;
    }
  };
  for (const button of buttons) button.addEventListener("click", () => choose(button.dataset.themeChoice as Theme));
  if (!groups.length) {
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
      for (const update of groups) update();
    };
    window.addEventListener("storage", (event) => {
      if (event.key === "theme" || event.key === null) reread();
    });
    window.addEventListener("pageshow", (event) => {
      if (event.persisted) reread();
    });
  }
  groups.push(press);
  press();
  name();
  return name;
}

// The icons, as the static pages have them inline (theme.css draws them).
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

/** The group of theme buttons, for pages built by script (the static ones
 * have it in their HTML). */
export function themeGroup(): HTMLElement {
  const group = document.createElement("div");
  group.className = "theme";
  group.setAttribute("role", "group");
  for (const theme of THEMES) {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.themeChoice = theme;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("aria-hidden", "true");
    for (const [tag, attrs] of ICONS[theme]) {
      const shape = document.createElementNS("http://www.w3.org/2000/svg", tag);
      for (const [key, value] of Object.entries(attrs)) shape.setAttribute(key, value);
      svg.append(shape);
    }
    button.append(svg);
    group.append(button);
  }
  return group;
}

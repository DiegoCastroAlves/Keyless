// The one control in each page's header for the language and the theme: a
// small button (the language's code and the theme's icon) that opens a menu
// with both choices, each a group of radio items. The theme is the same on
// every page (theme.ts); the language, on the pages that offer a choice, is
// set by the page itself. The button is in the static pages' HTML, so that
// the header does not move when the script runs; the menu is built here.

import { chooseTheme, currentTheme, onThemeChange, THEME_KEYS, THEMES, themeIcon, type ThemeKey } from "./theme";

export type Lang = "pt-BR" | "en" | "es";
export type PrefsKey = ThemeKey | "language" | "prefs";

/** The page's language, for the pages that offer a choice. */
export interface Language {
  current: () => Lang;
  choose: (lang: Lang) => void;
}

// Each language in its own words.
const LANGS: Record<Lang, { code: string; name: string }> = {
  "pt-BR": { code: "PT", name: "Português" },
  en: { code: "EN", name: "English" },
  es: { code: "ES", name: "Español" },
};

/** The button, for pages built by script (the static ones have it in their
 * HTML). */
export function prefsControl(): HTMLElement {
  const container = document.createElement("div");
  container.className = "prefs";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "prefs-button";
  button.setAttribute("aria-haspopup", "menu");
  button.setAttribute("aria-expanded", "false");
  for (const theme of THEMES) {
    const icon = themeIcon(theme);
    icon.dataset.themeIcon = theme;
    button.append(icon);
  }
  container.append(button);
  return container;
}

/** Wires the control in `container` (.prefs, with its .prefs-button) and
 * names everything with the page's texts. The function returned names it
 * again, after a change of language. */
export function prefsMenu(container: HTMLElement, label: (key: ThemeKey) => string): () => void;
export function prefsMenu(container: HTMLElement, label: (key: PrefsKey) => string, language: Language): () => void;
export function prefsMenu(container: HTMLElement, texts: ((key: ThemeKey) => string) | ((key: PrefsKey) => string), language?: Language): () => void {
  // Only the theme's keys are asked for when there is no language.
  const label = texts as (key: PrefsKey) => string;
  const button = container.querySelector<HTMLButtonElement>(".prefs-button")!;
  const code = button.querySelector<HTMLElement>(".prefs-code");
  const menu = document.createElement("div");
  menu.className = "prefs-menu";
  menu.id = "prefs-menu";
  menu.setAttribute("role", "menu");
  menu.hidden = true;
  button.setAttribute("aria-controls", menu.id);

  const items: HTMLButtonElement[] = [];
  const named: [HTMLElement, PrefsKey][] = [];
  const group = (key: PrefsKey) => {
    const node = document.createElement("div");
    node.className = "prefs-group";
    node.setAttribute("role", "group");
    const title = document.createElement("span");
    title.className = "prefs-label";
    title.setAttribute("aria-hidden", "true");
    node.append(title);
    named.push([node, key], [title, key]);
    menu.append(node);
    return node;
  };
  const item = (choose: () => void) => {
    const node = document.createElement("button");
    node.type = "button";
    node.tabIndex = -1;
    node.setAttribute("role", "menuitemradio");
    const mark = document.createElement("span");
    mark.className = "prefs-mark";
    mark.setAttribute("aria-hidden", "true");
    node.append(mark);
    node.addEventListener("click", () => {
      choose();
      close(true);
    });
    items.push(node);
    return node;
  };

  if (language) {
    const languages = group("language");
    for (const [lang, { name }] of Object.entries(LANGS) as [Lang, (typeof LANGS)[Lang]][]) {
      const node = item(() => language.choose(lang));
      node.lang = lang;
      node.dataset.lang = lang;
      node.append(name);
      languages.append(node);
    }
  }
  const themes = group("theme");
  for (const theme of THEMES) {
    const node = item(() => chooseTheme(theme));
    node.dataset.themeChoice = theme;
    const name = document.createElement("span");
    named.push([name, THEME_KEYS[theme]]);
    node.append(themeIcon(theme), name);
    themes.append(node);
  }
  container.append(menu);

  /** The current choices, on the button and in the menu. */
  const refresh = () => {
    const theme = label(THEME_KEYS[currentTheme()]);
    for (const node of items) {
      const checked = node.dataset.lang ? node.dataset.lang === language?.current() : node.dataset.themeChoice === currentTheme();
      node.setAttribute("aria-checked", String(checked));
    }
    if (language && code) {
      const shown = LANGS[language.current()].code;
      code.textContent = shown;
      button.setAttribute("aria-label", `${label("prefs")}: ${shown}, ${theme}`);
    } else {
      button.setAttribute("aria-label", `${label("theme")}: ${theme}`);
    }
  };

  const name = () => {
    const title = label(language ? "prefs" : "theme");
    button.title = title;
    menu.setAttribute("aria-label", title);
    for (const [node, key] of named) {
      if (node.getAttribute("role") === "group") node.setAttribute("aria-label", label(key));
      else node.textContent = label(key);
    }
    refresh();
  };

  // ----- opening and closing -----

  const outside = (event: PointerEvent) => {
    if (!container.contains(event.target as Node)) close(false);
  };

  /** Keeps the menu on the screen: under the button, from its right edge
   * unless that leaves the screen. */
  const place = () => {
    menu.style.right = "";
    const rect = menu.getBoundingClientRect();
    const margin = 8;
    if (rect.left < margin) menu.style.right = `${rect.left - margin}px`;
    else if (rect.right > innerWidth - margin) menu.style.right = `${rect.right - innerWidth + margin}px`;
  };

  function open(focus: "checked" | "last" = "checked") {
    if (menu.hidden) {
      refresh();
      menu.hidden = false;
      button.setAttribute("aria-expanded", "true");
      place();
      document.addEventListener("pointerdown", outside, true);
    }
    const first = focus === "last" ? items[items.length - 1] : (items.find((node) => node.getAttribute("aria-checked") === "true") ?? items[0]);
    first.focus();
  }

  function close(returnFocus: boolean) {
    if (menu.hidden) return;
    menu.hidden = true;
    button.setAttribute("aria-expanded", "false");
    document.removeEventListener("pointerdown", outside, true);
    if (returnFocus) button.focus();
  }

  // A click keeps the focus where it is (some browsers would move it out of
  // the menu, closing it before the click lands); open() moves it.
  container.addEventListener("mousedown", (event) => event.preventDefault());
  button.addEventListener("click", () => (menu.hidden ? open() : close(true)));
  button.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    event.preventDefault();
    open(event.key === "ArrowUp" ? "last" : "checked");
  });
  menu.addEventListener("keydown", (event) => {
    const at = items.indexOf(document.activeElement as HTMLButtonElement);
    const next =
      event.key === "ArrowDown" ? (at + 1) % items.length
      : event.key === "ArrowUp" ? (at - 1 + items.length) % items.length
      : event.key === "Home" ? 0
      : event.key === "End" ? items.length - 1
      : -1;
    if (next < 0) return;
    event.preventDefault();
    items[next].focus();
  });
  container.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || menu.hidden) return;
    event.preventDefault();
    close(true);
  });
  // Tab, or a click elsewhere, takes the focus out of the menu.
  container.addEventListener("focusout", (event) => {
    if (!container.contains(event.relatedTarget as Node | null)) close(false);
  });

  onThemeChange(refresh);
  name();
  return name;
}


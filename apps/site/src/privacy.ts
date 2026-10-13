// The privacy policy (keyless.diegoalves.dev/privacy/): the page holds it in
// each language; this shows the visitor's.

export {};

type Lang = "pt-BR" | "en" | "es";
const LANGS: Lang[] = ["pt-BR", "en", "es"];
const TITLES: Record<Lang, string> = { "pt-BR": "Política de privacidade do Keyless", en: "Keyless privacy policy", es: "Política de privacidad de Keyless" };

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

function show(lang: Lang) {
  document.documentElement.lang = lang;
  document.title = TITLES[lang];
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

show(detectLang());

// "Sign in with Google" and the like: the buttons pages show for them, the
// providers' own sign-in pages, and their names. Shared by the content
// script and the background script.

/** Provider ids, as items store them (see the app's field kinds). */
export const PROVIDERS = ["google", "apple", "microsoft", "github", "facebook", "x", "amazon", "discord", "slack", "linkedin", "gitlab", "okta"] as const;
export type Provider = (typeof PROVIDERS)[number];

/** How pages name each provider on their buttons. */
const NAMES: Record<Provider, RegExp> = {
  google: /\bgoogle\b/i,
  apple: /\bapple\b/i,
  microsoft: /\b(microsoft|outlook|hotmail)\b/i,
  github: /\bgithub\b/i,
  facebook: /\bfacebook\b/i,
  x: /\b(twitter|x)\b/i,
  amazon: /\bamazon\b/i,
  discord: /\bdiscord\b/i,
  slack: /\bslack\b/i,
  linkedin: /\blinkedin\b/i,
  gitlab: /\bgitlab\b/i,
  okta: /\bokta\b/i,
};

/** Where each provider asks for its account. */
const HOSTS: Record<Provider, string[]> = {
  google: ["accounts.google.com"],
  apple: ["appleid.apple.com", "idmsa.apple.com"],
  microsoft: ["login.microsoftonline.com", "login.live.com", "account.live.com"],
  github: ["github.com"],
  facebook: ["www.facebook.com", "m.facebook.com", "facebook.com"],
  x: ["x.com", "twitter.com", "api.x.com", "api.twitter.com"],
  amazon: ["www.amazon.com", "na.account.amazon.com"],
  discord: ["discord.com"],
  slack: ["slack.com"],
  linkedin: ["www.linkedin.com", "linkedin.com"],
  gitlab: ["gitlab.com"],
  okta: [],
};

/** The words of a "sign in with" button, in the three languages. */
const SIGN_IN_WITH = /\b(sign ?in|log ?in|continue|sign ?up|entrar|continuar|acessar|cadastr\w*|iniciar sesi[oó]n|inicia sesi[oó]n|ingresar|reg[ií]str\w*)\b.{0,12}\b(with|com|con|using|via|usando)\b/i;

export function providerName(provider: string): string {
  const names: Record<string, string> = { x: "X", github: "GitHub", gitlab: "GitLab", linkedin: "LinkedIn" };
  return names[provider] ?? provider.charAt(0).toUpperCase() + provider.slice(1);
}

/** The provider a button or link is for ("Continue with Google", or a
 * button showing only the provider's name or logo). */
export function providerOf(element: Element): Provider | null {
  const images = Array.from(element.querySelectorAll("img[alt], svg[aria-label], [aria-label]")).map((e) => e.getAttribute("alt") ?? e.getAttribute("aria-label") ?? "");
  const text = [element.textContent ?? "", element.getAttribute("aria-label") ?? "", element.getAttribute("title") ?? "", ...images].join(" ").replace(/\s+/g, " ").trim();
  if (!text || text.length > 80) return null;
  const found = PROVIDERS.filter((p) => NAMES[p].test(text));
  if (found.length !== 1) return null;
  // "X" alone is too common a letter to trust without the words around it.
  const bare = text.replace(NAMES[found[0]], "").replace(/[^\p{L}]/gu, "") === "";
  return SIGN_IN_WITH.test(text) || (bare && found[0] !== "x") ? found[0] : null;
}

/** Whether a page is one of the provider's own sign-in pages. */
export function isProviderPage(provider: string, url: string): boolean {
  try {
    const host = new URL(url).hostname;
    if (provider === "okta") return host.endsWith(".okta.com");
    return (HOSTS[provider as Provider] ?? []).includes(host);
  } catch {
    return false;
  }
}

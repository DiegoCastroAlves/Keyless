// Icons for logins: the site's icon from the browser's own cache (Chromium;
// no network request), or a coloured initial like in the app.

import type { Login } from "./types";

/** Set at build time: Chromium has the favicon cache API, Firefox does not. */
declare const __FAVICONS__: boolean;

const COLORS = ["#0284c7", "#7c3aed", "#059669", "#e11d48", "#d97706", "#4f46e5", "#0d9488", "#c026d3", "#ea580c", "#0e7490"];

export function hostOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

function color(seed: string): string {
  let hash = 0;
  for (const ch of seed) hash = (hash * 31 + ch.charCodeAt(0)) | 0;
  return COLORS[Math.abs(hash) % COLORS.length];
}

function faviconUrl(page: string): string {
  return chrome.runtime.getURL(`/_favicon/?pageUrl=${encodeURIComponent(page.includes("://") ? page : `https://${page}`)}&size=32`);
}

async function load(url: string): Promise<{ blob: Blob; key: string }> {
  const blob = await (await fetch(url)).blob();
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let key = "";
  for (const byte of bytes) key += String.fromCharCode(byte);
  return { blob, key };
}

/** The browser answers with a generic globe for sites it has no icon for. */
let generic: Promise<string> | null = null;

/** The site's icon, or null when the browser has none. */
async function siteIcon(page: string): Promise<string | null> {
  generic ??= load(faviconUrl("https://keyless.invalid/")).then((icon) => icon.key);
  const [icon, globe] = await Promise.all([load(faviconUrl(page)), generic]);
  return icon.key === globe ? null : URL.createObjectURL(icon.blob);
}

/** `pageUrl`: the page the login matches, whose icon the browser surely has
 * (it keeps icons per page, not per site). */
export function avatar(login: Login, pageUrl?: string): HTMLElement {
  const box = document.createElement("span");
  box.className = "avatar initial";
  box.style.background = color(login.url ? hostOf(login.url) : login.title);
  box.textContent = (login.title.match(/[\p{L}\p{N}]/u)?.[0] ?? "?").toUpperCase();
  if (login.favorite) {
    const star = document.createElement("span");
    star.className = "star";
    star.innerHTML = `<svg viewBox="0 0 24 24" width="10" height="10"><path fill="currentColor" d="m12 2.5 2.9 6 6.6.9-4.8 4.6 1.2 6.5L12 17.4l-5.9 3.1 1.2-6.5L2.5 9.4l6.6-.9z"/></svg>`;
    box.append(star);
  }
  const site = pageUrl ?? login.url;
  if (__FAVICONS__ && site) {
    void siteIcon(site)
      .then((src) => {
        if (!src) return;
        const icon = document.createElement("img");
        icon.alt = "";
        icon.src = src;
        box.classList.remove("initial");
        box.style.background = "";
        box.firstChild?.replaceWith(icon);
      })
      .catch(() => undefined);
  }
  return box;
}

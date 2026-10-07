// The extension's settings in this browser. Kept in the extension's own
// IndexedDB (like its pairing key), which content scripts cannot read: only
// the background script reads and writes them, and the popup changes them
// through it. Pages learn only what applies to them.

import { kvGet, kvSet } from "./crypto";

export interface Settings {
  /** Offer to save logins typed in forms. */
  offerSave: boolean;
  /** Show the sign-in card at the top of login pages. */
  signInCard: boolean;
  /** Open the list when the user clicks a login field. */
  autoOpen: boolean;
  /** "Sign in" submits the form once filled. */
  autoSubmit: boolean;
  /** Copy the one-time password after filling a login that has one. */
  copyTotp: boolean;
  /** Sites (host names) where saving logins is never offered. */
  neverSave: string[];
  /** Sites where Keyless stays out of the page: no button, menus, card or
   * prompt. The popup still works there. */
  hidden: string[];
}

export const DEFAULT_SETTINGS: Settings = {
  offerSave: true,
  signInCard: true,
  autoOpen: true,
  autoSubmit: true,
  copyTotp: true,
  neverSave: [],
  hidden: [],
};

const KEY = "settings";
const FLAGS = ["offerSave", "signInCard", "autoOpen", "autoSubmit", "copyTotp"] as const;
const MAX_SITES = 500;

/** "https://www.Example.com/login" -> "example.com"; null for other pages. */
export function siteKey(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

function sites(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const clean = value.filter((s): s is string => typeof s === "string" && s.length > 0 && s.length <= 253).map((s) => s.toLowerCase());
  return Array.from(new Set(clean)).slice(0, MAX_SITES);
}

/** Anything stored or sent is checked: unknown keys and wrong types are
 * dropped. */
export function sanitize(value: unknown, base: Settings = DEFAULT_SETTINGS): Settings {
  const input = (value && typeof value === "object" ? value : {}) as Record<string, unknown>;
  const result: Settings = { ...base, neverSave: [...base.neverSave], hidden: [...base.hidden] };
  for (const flag of FLAGS) if (typeof input[flag] === "boolean") result[flag] = input[flag] as boolean;
  if ("neverSave" in input) result.neverSave = sites(input.neverSave);
  if ("hidden" in input) result.hidden = sites(input.hidden);
  return result;
}

let cached: Promise<Settings> | null = null;

export function loadSettings(): Promise<Settings> {
  cached ??= kvGet<unknown>(KEY)
    .then((stored) => sanitize(stored))
    .catch(() => ({ ...DEFAULT_SETTINGS }));
  return cached;
}

export async function updateSettings(patch: unknown): Promise<Settings> {
  const next = sanitize(patch, await loadSettings());
  await kvSet(KEY, next);
  cached = Promise.resolve(next);
  return next;
}

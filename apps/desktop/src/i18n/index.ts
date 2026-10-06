import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import type { AppError } from "../lib/api";
import en from "./en";
import es from "./es";

export const LANGUAGES = [
  { code: "en", name: "English" },
  { code: "es", name: "Español" },
] as const;

export type LanguageCode = (typeof LANGUAGES)[number]["code"];

function systemLanguage(): LanguageCode {
  const preferred = navigator.languages?.length ? navigator.languages : [navigator.language];
  for (const tag of preferred) {
    const base = tag.toLowerCase().split("-")[0];
    if (LANGUAGES.some((l) => l.code === base)) return base as LanguageCode;
  }
  return "en";
}

export function resolveLanguage(setting: string | undefined): LanguageCode {
  if (setting && LANGUAGES.some((l) => l.code === setting)) return setting as LanguageCode;
  return systemLanguage();
}

void i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, es: { translation: es } },
  lng: systemLanguage(),
  fallbackLng: "en",
  interpolation: { escapeValue: false },
  returnNull: false,
});

export function applyLanguage(setting: string | undefined) {
  const lng = resolveLanguage(setting);
  if (i18n.language !== lng) void i18n.changeLanguage(lng);
  document.documentElement.lang = lng;
}

/** Translates an error coming from the Rust side. */
export function translateError(err: unknown): string {
  if (err && typeof err === "object" && "key" in err) {
    const e = err as AppError & { key: string; params?: Record<string, string> };
    const key = `errors.${e.key}`;
    if (i18n.exists(key)) return i18n.t(key, e.params ?? {});
    return e.message;
  }
  if (err && typeof err === "object" && "message" in err) return String((err as AppError).message);
  return String(err);
}

/** Translates a stored field label when it is one of our built-in labels. */
export function fieldLabel(label: string): string {
  const key = `fieldLabels.${label}`;
  return label && i18n.exists(key) ? i18n.t(key) : label;
}

export default i18n;

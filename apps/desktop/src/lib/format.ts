import i18n from "../i18n";

export function formatDate(unixSeconds: number): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString(i18n.language, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function relativeTime(unixSeconds: number | null): string {
  if (!unixSeconds) return i18n.t("time.never");
  const diff = Math.max(0, Date.now() / 1000 - unixSeconds);
  if (diff < 45) return i18n.t("time.justNow");
  if (diff < 3600) return i18n.t("time.minutes", { count: Math.round(diff / 60) });
  if (diff < 86400) return i18n.t("time.hours", { count: Math.round(diff / 3600) });
  return i18n.t("time.days", { count: Math.round(diff / 86400) });
}

export function hostOf(url: string): string {
  try {
    const parsed = new URL(url.includes("://") ? url : `https://${url}`);
    return parsed.hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

const AVATAR_COLORS = [
  "bg-sky-600",
  "bg-violet-600",
  "bg-emerald-600",
  "bg-rose-600",
  "bg-amber-600",
  "bg-indigo-600",
  "bg-teal-600",
  "bg-fuchsia-600",
  "bg-orange-600",
  "bg-cyan-700",
];

export function avatarColor(seed: string): string {
  let hash = 0;
  for (const ch of seed) hash = (hash * 31 + ch.charCodeAt(0)) | 0;
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
}

/** Groups a TOTP code for readability: 123456 -> "123 456". */
export function formatTotp(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

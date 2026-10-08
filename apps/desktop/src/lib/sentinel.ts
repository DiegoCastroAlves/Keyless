import { useMemo } from "react";
import { create } from "zustand";

import { api, type HealthReport, type SentinelAlert } from "./api";

/** Every alert, most serious first. */
export const SENTINEL_ALERTS: SentinelAlert[] = ["breached", "compromised", "weak", "reused", "unsecured", "expiring", "two_factor", "passkey", "duplicate"];

/** The title of each alert's list (translation key). */
export const ALERT_TITLE: Record<SentinelAlert, string> = {
  breached: "sentinel.breached",
  compromised: "sentinel.compromised",
  weak: "sentinel.weak",
  reused: "sentinel.reused",
  unsecured: "sentinel.unsecured",
  expiring: "sentinel.expiring",
  two_factor: "sentinel.twoFactor",
  passkey: "sentinel.passkey",
  duplicate: "sentinel.duplicate",
};

/** What one alert says about one item. */
export interface AlertDetail {
  /** Times the password was seen in breaches. */
  seen?: number;
  /** The website concerned. */
  site?: string;
  /** When the website was breached (YYYY-MM-DD), or the item expires (unix seconds). */
  date?: string | number;
  expired?: boolean;
  /** Other items with the same password, or for the same account. */
  others?: number;
}

interface SentinelStore {
  report: HealthReport | null;
  loadReport: () => Promise<void>;
}

/** Sentinel's results, shared by its overview, its lists and the item view. */
export const useSentinel = create<SentinelStore>((set) => ({
  report: null,
  loadReport: async () => {
    try {
      set({ report: await api.passwordHealth() });
    } catch {
      // Locked meanwhile: kept as it was.
    }
  },
}));

/** The alert's data is not there yet: its list was never downloaded, or the
 * passwords never checked online. */
export function isPending(report: HealthReport | null, alert: SentinelAlert): boolean {
  return !!report?.pending.includes(alert);
}

export type Issues = Map<SentinelAlert, Map<string, AlertDetail>>;

/** The items each alert applies to, without the ones the user ignored. */
export function issuesOf(report: HealthReport | null): Issues {
  const issues: Issues = new Map(SENTINEL_ALERTS.map((alert) => [alert, new Map()]));
  if (!report) return issues;
  const ignored = new Set(report.ignored.map(([id, alert]) => `${id}:${alert}`));
  const add = (alert: SentinelAlert, id: string, detail: AlertDetail = {}) => {
    if (!ignored.has(`${id}:${alert}`)) issues.get(alert)!.set(id, detail);
  };
  for (const id of report.weak) add("weak", id);
  for (const group of report.reused) for (const id of group) add("reused", id, { others: group.length - 1 });
  for (const group of report.duplicates) for (const id of group) add("duplicate", id, { others: group.length - 1 });
  for (const id of report.unsecured) add("unsecured", id);
  for (const e of report.expiring) add("expiring", e.id, { date: e.expiresAt, expired: e.expired });
  for (const [id, seen] of report.breached) add("breached", id, { seen });
  for (const issue of report.compromised) add("compromised", issue.id, { site: issue.site, date: issue.date ?? undefined });
  for (const issue of report.twoFactor) add("two_factor", issue.id, { site: issue.site });
  for (const issue of report.passkeys) add("passkey", issue.id, { site: issue.site });
  return issues;
}

export function useIssues(): Issues {
  const report = useSentinel((s) => s.report);
  return useMemo(() => issuesOf(report), [report]);
}

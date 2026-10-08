import { useMemo } from "react";
import { create } from "zustand";

import { api, type BreachReport, type HealthReport, type SentinelAlert } from "./api";

/** Every alert, most serious first. */
export const SENTINEL_ALERTS: SentinelAlert[] = ["breached", "compromised", "weak", "reused", "unsecured", "expiring", "two_factor"];

/** What the online check covers: unknown until it ran. */
export const ONLINE_ALERTS: SentinelAlert[] = ["breached", "compromised", "two_factor"];

/** The title of each alert's list (translation key). */
export const ALERT_TITLE: Record<SentinelAlert, string> = {
  breached: "sentinel.breached",
  compromised: "sentinel.compromised",
  weak: "sentinel.weak",
  reused: "sentinel.reused",
  unsecured: "sentinel.unsecured",
  expiring: "sentinel.expiring",
  two_factor: "sentinel.twoFactor",
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
  /** Other items with the same password. */
  others?: number;
}

interface SentinelStore {
  report: HealthReport | null;
  /** The last online check, and when it ran (unix seconds). */
  breaches: BreachReport | null;
  checkedAt: number | null;
  loadReport: () => Promise<void>;
  loadBreaches: () => Promise<void>;
  setBreaches: (breaches: BreachReport, checkedAt: number) => void;
}

/** Sentinel's results, shared by its overview, its lists and the item view. */
export const useSentinel = create<SentinelStore>((set) => ({
  report: null,
  breaches: null,
  checkedAt: null,
  loadReport: async () => {
    try {
      set({ report: await api.passwordHealth() });
    } catch {
      // Locked meanwhile: kept as it was.
    }
  },
  loadBreaches: async () => {
    const last = await api.lastBreaches().catch(() => null);
    if (last) set({ breaches: last.report, checkedAt: last.checkedAt });
  },
  setBreaches: (breaches, checkedAt) => set({ breaches, checkedAt }),
}));

export type Issues = Map<SentinelAlert, Map<string, AlertDetail>>;

/** The items each alert applies to, without the ones the user ignored. The
 * online results are from the last check: alerts ignored since are left out
 * here. */
export function issuesOf(report: HealthReport | null, breaches: BreachReport | null): Issues {
  const issues: Issues = new Map(SENTINEL_ALERTS.map((alert) => [alert, new Map()]));
  if (!report) return issues;
  const ignored = new Set(report.ignored.map(([id, alert]) => `${id}:${alert}`));
  const add = (alert: SentinelAlert, id: string, detail: AlertDetail = {}) => {
    if (!ignored.has(`${id}:${alert}`)) issues.get(alert)!.set(id, detail);
  };
  for (const id of report.weak) add("weak", id);
  for (const group of report.reused) for (const id of group) add("reused", id, { others: group.length - 1 });
  for (const id of report.unsecured) add("unsecured", id);
  for (const e of report.expiring) add("expiring", e.id, { date: e.expiresAt, expired: e.expired });
  if (breaches) {
    for (const [id, seen] of breaches.breached) add("breached", id, { seen });
    for (const issue of breaches.compromised) add("compromised", issue.id, { site: issue.site, date: issue.date ?? undefined });
    for (const issue of breaches.twoFactor) add("two_factor", issue.id, { site: issue.site });
  }
  return issues;
}

export function useIssues(): Issues {
  const report = useSentinel((s) => s.report);
  const breaches = useSentinel((s) => s.breaches);
  return useMemo(() => issuesOf(report, breaches), [report, breaches]);
}

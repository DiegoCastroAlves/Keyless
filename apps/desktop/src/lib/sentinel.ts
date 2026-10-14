import { useMemo } from "react";
import { create } from "zustand";

import { api, type BreachDetails, type HealthReport, type SentinelAlert } from "./api";
import { useApp } from "./store";

/** Every alert, most serious first. */
export const SENTINEL_ALERTS: SentinelAlert[] = ["breached", "compromised", "lastpass", "weak", "reused", "unsecured", "expiring", "two_factor", "passkey", "duplicate"];

/** The serious alerts: what the summary on the item list counts. */
export const SERIOUS_ALERTS: SentinelAlert[] = ["breached", "compromised", "lastpass"];

/** The alerts that lower the score: problems with the password itself. */
const SCORED_ALERTS: SentinelAlert[] = ["breached", "compromised", "lastpass", "weak", "reused", "unsecured"];

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
  lastpass: "sentinel.lastpass",
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
  /** For a breached website: what the breach list says about it. */
  breach?: BreachDetails;
}

interface SentinelStore {
  report: HealthReport | null;
  /** The vault Sentinel's overview and lists look at; null for every vault. */
  scope: string | null;
  loadReport: () => Promise<void>;
  setScope: (scope: string | null) => void;
}

/** Sentinel's results, shared by its overview, its lists and the item view. */
export const useSentinel = create<SentinelStore>((set) => ({
  report: null,
  scope: null,
  loadReport: async () => {
    try {
      set({ report: await api.passwordHealth() });
    } catch {
      // Locked meanwhile: kept as it was.
    }
  },
  setScope: (scope) => set({ scope }),
}));

/** The alert's data is not there yet: its list was never downloaded, or the
 * passwords never checked online. */
export function isPending(report: HealthReport | null, alert: SentinelAlert): boolean {
  return !!report?.pending.includes(alert);
}

/** The alert's list is turned off in the settings. */
export function isOff(report: HealthReport | null, alert: SentinelAlert): boolean {
  return !!report?.off?.includes(alert);
}

export type Issues = Map<SentinelAlert, Map<string, AlertDetail>>;

/** The items each alert applies to, without the ones the user ignored;
 * with `inScope`, only the items it keeps. */
export function issuesOf(report: HealthReport | null, inScope?: (id: string) => boolean): Issues {
  const issues: Issues = new Map(SENTINEL_ALERTS.map((alert) => [alert, new Map()]));
  if (!report) return issues;
  const ignored = new Set(report.ignored.map(([id, alert]) => `${id}:${alert}`));
  const add = (alert: SentinelAlert, id: string, detail: AlertDetail = {}) => {
    if (!ignored.has(`${id}:${alert}`) && (!inScope || inScope(id))) issues.get(alert)!.set(id, detail);
  };
  for (const id of report.weak) add("weak", id);
  for (const group of report.reused) for (const id of group) add("reused", id, { others: group.length - 1 });
  for (const group of report.duplicates) for (const id of group) add("duplicate", id, { others: group.length - 1 });
  for (const id of report.unsecured) add("unsecured", id);
  for (const e of report.expiring) add("expiring", e.id, { date: e.expiresAt, expired: e.expired });
  for (const [id, seen] of report.breached) add("breached", id, { seen });
  for (const issue of report.compromised) add("compromised", issue.id, { site: issue.site, date: issue.date ?? undefined, breach: issue.breach });
  for (const issue of report.twoFactor) add("two_factor", issue.id, { site: issue.site });
  for (const issue of report.passkeys) add("passkey", issue.id, { site: issue.site });
  for (const id of report.lastpass ?? []) add("lastpass", id);
  return issues;
}

/** Every vault's issues: for the alerts on an item. */
export function useIssues(): Issues {
  const report = useSentinel((s) => s.report);
  return useMemo(() => issuesOf(report), [report]);
}

/** Whether an item is in the vault Sentinel looks at; undefined when it
 * looks at every vault. */
export function useInScope(): ((id: string) => boolean) | undefined {
  const scope = useSentinel((s) => s.scope);
  const items = useApp((s) => s.items);
  return useMemo(() => {
    if (!scope) return undefined;
    const ids = new Set(items.filter((i) => i.vaultId === scope).map((i) => i.id));
    return (id: string) => ids.has(id);
  }, [scope, items]);
}

/** The issues of the vault Sentinel looks at: for its overview and lists. */
export function useScopedIssues(): Issues {
  const report = useSentinel((s) => s.report);
  const inScope = useInScope();
  return useMemo(() => issuesOf(report, inScope), [report, inScope]);
}

/** How many passwords are at each strength level (0 to 6), in one vault or
 * all of them. */
export function strengthCounts(report: HealthReport | null, scope: string | null): number[] {
  const counts = [0, 0, 0, 0, 0, 0, 0];
  for (const [vault, levels] of Object.entries(report?.strengths ?? {})) {
    if (scope && vault !== scope) continue;
    levels.forEach((n, level) => (counts[level] += n));
  }
  return counts;
}

/** The score, 0 to 100: the share of the `checked` passwords without a
 * problem. */
export function scoreOf(issues: Issues, checked: number): number {
  const problems = new Set(SCORED_ALERTS.flatMap((a) => [...issues.get(a)!.keys()]));
  return checked ? Math.max(0, Math.round(((checked - problems.size) / checked) * 100)) : 100;
}

/** Shows an item in Sentinel's list of one of its alerts (looking at every
 * vault when the one chosen is not the item's). */
export function showInSentinel(itemId: string, alert: SentinelAlert) {
  const { items, setView, select } = useApp.getState();
  const { scope, setScope } = useSentinel.getState();
  if (scope && items.find((i) => i.id === itemId)?.vaultId !== scope) setScope(null);
  setView({ kind: "sentinel", alert });
  select(itemId, true);
}

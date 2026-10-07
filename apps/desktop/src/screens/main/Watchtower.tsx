import { BellOff, BellRing, CalendarClock, CircleCheck, Globe, KeyRound, LockOpen, Repeat, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { ItemIcon } from "../../components/common";
import { Button, IconButton, Spinner, Tooltip, cx } from "../../components/ui";
import { api, errorMessage, type BreachReport, type HealthReport, type ItemSummary, type WatchtowerAlert } from "../../lib/api";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";

export function Watchtower() {
  const { t, i18n } = useTranslation();
  const items = useApp((s) => s.items);
  const revision = useApp((s) => s.revision);
  const [report, setReport] = useState<HealthReport | null>(null);
  const [breaches, setBreaches] = useState<BreachReport | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    api.passwordHealth().then(setReport).catch((err) => toast.error(errorMessage(err)));
  }, [revision]);

  const byId = useMemo(() => new Map(items.map((i) => [i.id, i])), [items]);

  const checkBreaches = async () => {
    setChecking(true);
    try {
      setBreaches(await api.checkBreaches());
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setChecking(false);
    }
  };

  const reusedIds = useMemo(() => {
    const ignored = new Set(report?.ignored.filter(([, alert]) => alert === "reused").map(([id]) => id));
    const map = new Map<string, number>();
    for (const group of report?.reused ?? []) for (const id of group) if (!ignored.has(id)) map.set(id, group.length - 1);
    return map;
  }, [report]);

  if (!report) {
    return (
      <section className="flex flex-1 items-center justify-center bg-panel">
        <Spinner className="size-6 text-accent" />
      </section>
    );
  }

  // The online results are from the last check: alerts ignored since are
  // left out here.
  const ignoredSet = new Set(report.ignored.map(([id, alert]) => `${id}:${alert}`));
  const online = breaches && {
    ...breaches,
    breached: breaches.breached.filter(([id]) => !ignoredSet.has(`${id}:breached`)),
    compromised: breaches.compromised.filter((issue) => !ignoredSet.has(`${issue.id}:compromised`)),
    twoFactor: breaches.twoFactor.filter((issue) => !ignoredSet.has(`${issue.id}:two_factor`)),
  };
  const problems = new Set([
    ...report.weak,
    ...reusedIds.keys(),
    ...report.unsecured,
    ...(online?.breached.map(([id]) => id) ?? []),
    ...(online?.compromised.map((issue) => issue.id) ?? []),
  ]);
  const score = report.checked ? Math.max(0, Math.round(((report.checked - problems.size) / report.checked) * 100)) : 100;
  const day = (value: number | string) =>
    new Date(typeof value === "number" ? value * 1000 : `${value}T00:00:00Z`).toLocaleDateString(i18n.language, {
      year: "numeric",
      month: "short",
      day: "numeric",
      timeZone: typeof value === "number" ? undefined : "UTC",
    });
  const anything = problems.size > 0 || report.expiring.length > 0 || (online?.twoFactor.length ?? 0) > 0;

  return (
    <section className="flex min-w-0 flex-1 flex-col overflow-y-auto bg-panel">
      <div className="mx-auto w-full max-w-3xl px-8 py-8">
        <div className="flex items-center gap-5">
          <ScoreRing score={score} />
          <div>
            <h2 className="text-xl font-semibold tracking-tight">{t("watchtower.title")}</h2>
            <p className="mt-1 max-w-md text-[13px] leading-relaxed text-muted">{t("watchtower.subtitle")}</p>
            <p className="mt-1 text-xs text-subtle">{t("watchtower.checked", { count: report.checked })}</p>
          </div>
        </div>

        <div className="mt-8 grid grid-cols-3 gap-3">
          <StatCard
            icon={<ShieldX className="size-5" />}
            tone="danger"
            label={t("watchtower.breached")}
            value={online ? online.breached.length : null}
            placeholder={t("watchtower.notChecked")}
          />
          <StatCard
            icon={<Globe className="size-5" />}
            tone="danger"
            label={t("watchtower.compromised")}
            value={online ? online.compromised.length : null}
            placeholder={t("watchtower.notChecked")}
          />
          <StatCard icon={<ShieldAlert className="size-5" />} tone="warning" label={t("watchtower.weak")} value={report.weak.length} />
          <StatCard icon={<Repeat className="size-5" />} tone="warning" label={t("watchtower.reused")} value={reusedIds.size} />
          <StatCard icon={<LockOpen className="size-5" />} tone="warning" label={t("watchtower.unsecured")} value={report.unsecured.length} />
          <StatCard
            icon={<KeyRound className="size-5" />}
            tone="info"
            label={t("watchtower.twoFactor")}
            value={online ? online.twoFactor.length : null}
            placeholder={t("watchtower.notChecked")}
          />
        </div>

        <div className="mt-4 flex items-center gap-3 rounded-xl border border-line bg-panel-2 p-4">
          <ShieldCheck className="size-5 shrink-0 text-accent" />
          <p className="flex-1 text-xs leading-relaxed text-muted">{t("watchtower.breachPrivacy")}</p>
          <Button size="sm" onClick={checkBreaches} loading={checking}>
            {checking ? t("watchtower.checkingBreaches") : t("watchtower.checkBreaches")}
          </Button>
        </div>

        {!anything ? (
          <div className="mt-10 flex flex-col items-center text-center">
            <CircleCheck className="size-10 text-success" />
            <p className="mt-3 text-sm font-medium">{t("watchtower.allGood")}</p>
          </div>
        ) : (
          <div className="mt-8 space-y-8">
            {online && online.breached.length > 0 && (
              <IssueList
                alert="breached"
                title={t("watchtower.breached")}
                hint={t("watchtower.breachedHint")}
                entries={online.breached.map(([id, count]) => ({
                  item: byId.get(id),
                  note: t("watchtower.breachedSeen", { count, formatted: count.toLocaleString(i18n.language) }),
                }))}
                tone="danger"
              />
            )}
            {online && online.compromised.length > 0 && (
              <IssueList
                alert="compromised"
                title={t("watchtower.compromised")}
                hint={t("watchtower.compromisedHint")}
                entries={online.compromised.map((issue) => ({
                  item: byId.get(issue.id),
                  note: t("watchtower.compromisedNote", { site: issue.site, date: issue.date ? day(issue.date) : "" }),
                }))}
                tone="danger"
              />
            )}
            {report.weak.length > 0 && (
              <IssueList
                alert="weak"
                title={t("watchtower.weak")}
                hint={t("watchtower.weakHint")}
                entries={report.weak.map((id) => ({ item: byId.get(id) }))}
                tone="warning"
              />
            )}
            {reusedIds.size > 0 && (
              <IssueList
                alert="reused"
                title={t("watchtower.reused")}
                hint={t("watchtower.reusedHint")}
                entries={[...reusedIds.entries()].map(([id, others]) => ({ item: byId.get(id), note: t("watchtower.sharedWith", { count: others }) }))}
                tone="warning"
              />
            )}
            {report.unsecured.length > 0 && (
              <IssueList
                alert="unsecured"
                title={t("watchtower.unsecured")}
                hint={t("watchtower.unsecuredHint")}
                entries={report.unsecured.map((id) => ({ item: byId.get(id) }))}
                tone="warning"
              />
            )}
            {report.expiring.length > 0 && (
              <IssueList
                alert="expiring"
                title={t("watchtower.expiring")}
                hint={t("watchtower.expiringHint")}
                entries={report.expiring.map((e) => ({
                  item: byId.get(e.id),
                  note: t(e.expired ? "watchtower.expiredOn" : "watchtower.expiresOn", { date: day(e.expiresAt) }),
                }))}
                tone="warning"
                icon={<CalendarClock className="size-4" />}
              />
            )}
            {online && online.twoFactor.length > 0 && (
              <IssueList
                alert="two_factor"
                title={t("watchtower.twoFactor")}
                hint={t("watchtower.twoFactorHint")}
                entries={online.twoFactor.map((issue) => ({ item: byId.get(issue.id), note: t("watchtower.twoFactorNote", { site: issue.site }) }))}
                tone="info"
              />
            )}
          </div>
        )}
        {report.ignored.length > 0 && <IgnoredList ignored={report.ignored} byId={byId} />}
      </div>
    </section>
  );
}

/** Alerts the user chose to ignore, which can be watched again. */
function IgnoredList({ ignored, byId }: { ignored: [string, WatchtowerAlert][]; byId: Map<string, ItemSummary> }) {
  const { t } = useTranslation();
  const loadData = useApp((s) => s.loadData);
  const [open, setOpen] = useState(false);
  const watch = async (id: string, alert: WatchtowerAlert) => {
    try {
      await api.setWatchtowerIgnored(id, alert, false);
      await loadData();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <div className="mt-10">
      <button className="text-xs font-medium text-muted hover:text-fg" onClick={() => setOpen(!open)}>
        {t("watchtower.ignoredCount", { count: ignored.length })}
      </button>
      {open && (
        <div className="mt-2 divide-y divide-line overflow-hidden rounded-xl border border-line">
          {ignored
            .filter(([id]) => byId.has(id))
            .map(([id, alert]) => (
              <div key={`${id}-${alert}`} className="flex items-center gap-3 px-3 py-2">
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px] font-medium">{byId.get(id)!.title}</div>
                  <div className="truncate text-xs text-muted">{t(`watchtower.alert.${alert}`)}</div>
                </div>
                <Button size="sm" variant="ghost" onClick={() => watch(id, alert)}>
                  <BellRing className="size-4" /> {t("watchtower.watchAgain")}
                </Button>
              </div>
            ))}
        </div>
      )}
    </div>
  );
}

function ScoreRing({ score }: { score: number }) {
  const color = score >= 90 ? "var(--success)" : score >= 70 ? "var(--accent)" : score >= 40 ? "var(--warning)" : "var(--danger)";
  const circumference = 2 * Math.PI * 34;
  return (
    <div className="relative size-24 shrink-0">
      <svg viewBox="0 0 80 80" className="size-24 -rotate-90">
        <circle cx="40" cy="40" r="34" fill="none" stroke="var(--panel-3)" strokeWidth="7" />
        <circle
          cx="40"
          cy="40"
          r="34"
          fill="none"
          stroke={color}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * circumference} ${circumference}`}
          style={{ transition: "stroke-dasharray 600ms ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center text-2xl font-semibold tabular-nums">{score}</div>
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  tone,
  placeholder,
}: {
  icon: ReactNode;
  label: string;
  value: number | null;
  tone: "warning" | "danger" | "info";
  placeholder?: string;
}) {
  const active = value !== null && value > 0;
  return (
    <div className="rounded-xl border border-line p-4">
      <div
        className={cx(
          "flex size-9 items-center justify-center rounded-lg",
          !active
            ? "bg-panel-3 text-subtle"
            : tone === "danger"
              ? "bg-danger-soft text-danger"
              : tone === "info"
                ? "bg-accent-soft text-accent"
                : "bg-warning-soft text-warning",
        )}
      >
        {icon}
      </div>
      <div className="mt-3 text-2xl font-semibold tabular-nums">{value ?? "—"}</div>
      <div className="text-xs text-muted">{value === null ? placeholder : label}</div>
    </div>
  );
}

function IssueList({
  alert,
  title,
  hint,
  entries,
  tone,
  icon,
}: {
  alert: WatchtowerAlert;
  title: string;
  hint: string;
  entries: { item: ItemSummary | undefined; note?: string }[];
  tone: "warning" | "danger" | "info";
  icon?: ReactNode;
}) {
  const { t } = useTranslation();
  const setView = useApp((s) => s.setView);
  const select = useApp((s) => s.select);
  const loadData = useApp((s) => s.loadData);
  const ignore = async (id: string) => {
    try {
      await api.setWatchtowerIgnored(id, alert, true);
      await loadData();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <div>
      <h3
        className={cx(
          "flex items-center gap-1.5 text-sm font-semibold",
          tone === "danger" ? "text-danger" : tone === "info" ? "text-accent" : "text-warning",
        )}
      >
        {icon}
        {title}
      </h3>
      <p className="mt-0.5 text-xs text-muted">{hint}</p>
      <div className="mt-3 divide-y divide-line overflow-hidden rounded-xl border border-line">
        {entries
          .filter((e) => e.item)
          .map(({ item, note }) => (
            <div key={item!.id} className="group flex items-center hover:bg-panel-2">
              <button
                onClick={() => {
                  setView({ kind: "all" });
                  select(item!.id);
                }}
                className="flex min-w-0 flex-1 items-center gap-3 px-3 py-2.5 text-left"
              >
                <ItemIcon title={item!.title} category={item!.category} url={item!.urls[0]} size="sm" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px] font-medium">{item!.title}</div>
                  <div className="truncate text-xs text-muted">{note ?? item!.subtitle}</div>
                </div>
              </button>
              <Tooltip content={t("watchtower.ignore")}>
                <IconButton
                  label={t("watchtower.ignore")}
                  onClick={() => void ignore(item!.id)}
                  className="mr-2 opacity-0 group-hover:opacity-100 focus:opacity-100"
                >
                  <BellOff className="size-4" />
                </IconButton>
              </Tooltip>
            </div>
          ))}
      </div>
    </div>
  );
}

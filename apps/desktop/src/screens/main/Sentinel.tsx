import {
  ArrowRight,
  BellOff,
  BellRing,
  Binoculars,
  CalendarClock,
  Check,
  ChevronDown,
  CircleCheck,
  Copy,
  ExternalLink,
  Fingerprint,
  Globe,
  KeyRound,
  LockOpen,
  Repeat,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Button, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger, Spinner, Switch, cx } from "../../components/ui";
import { api, errorMessage, type SentinelAlert } from "../../lib/api";
import { ALERT_TITLE, SENTINEL_ALERTS, isPending, useIssues, useSentinel, type AlertDetail } from "../../lib/sentinel";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";

export const ALERT_ICONS: Record<SentinelAlert, LucideIcon> = {
  breached: ShieldX,
  compromised: Globe,
  weak: ShieldAlert,
  reused: Repeat,
  unsecured: LockOpen,
  expiring: CalendarClock,
  two_factor: KeyRound,
  passkey: Fingerprint,
  duplicate: Copy,
};

type Tone = "danger" | "warning" | "info";

const ALERT_TONE: Record<SentinelAlert, Tone> = {
  breached: "danger",
  compromised: "danger",
  weak: "warning",
  reused: "warning",
  unsecured: "warning",
  expiring: "warning",
  two_factor: "info",
  passkey: "info",
  duplicate: "info",
};

const ALERT_HINT: Record<SentinelAlert, string> = {
  breached: "sentinel.breachedHint",
  compromised: "sentinel.compromisedHint",
  weak: "sentinel.weakHint",
  reused: "sentinel.reusedHint",
  unsecured: "sentinel.unsecuredHint",
  expiring: "sentinel.expiringHint",
  two_factor: "sentinel.twoFactorHint",
  passkey: "sentinel.passkeyHint",
  duplicate: "sentinel.duplicateHint",
};

/** A date as the alerts show it: unix seconds, or YYYY-MM-DD (UTC). */
function useDay() {
  const { i18n } = useTranslation();
  return (value: number | string) =>
    new Date(typeof value === "number" ? value * 1000 : `${value}T00:00:00Z`).toLocaleDateString(i18n.language, {
      year: "numeric",
      month: "short",
      day: "numeric",
      timeZone: typeof value === "number" ? undefined : "UTC",
    });
}

/** Sentinel's overview: the score, a card per alert (each opens its items)
 * and the online check. */
export function Sentinel() {
  const { t, i18n } = useTranslation();
  const report = useSentinel((s) => s.report);
  const issues = useIssues();
  const [checking, setChecking] = useState(false);
  const settings = useApp((s) => s.settings);
  const setSettings = useApp((s) => s.setSettings);
  const setView = useApp((s) => s.setView);

  const checkBreaches = async () => {
    setChecking(true);
    try {
      await api.checkBreaches();
      await useSentinel.getState().loadReport();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setChecking(false);
    }
  };

  if (!report) {
    return (
      <section className="flex flex-1 items-center justify-center bg-panel">
        <Spinner className="size-6 text-accent" />
      </section>
    );
  }

  const problems = new Set(["breached", "compromised", "weak", "reused", "unsecured"].flatMap((a) => [...issues.get(a as SentinelAlert)!.keys()]));
  const score = report.checked ? Math.max(0, Math.round(((report.checked - problems.size) / report.checked) * 100)) : 100;
  const anything = SENTINEL_ALERTS.some((a) => issues.get(a)!.size > 0);
  const when = (at: number) => new Date(at * 1000).toLocaleString(i18n.language, { dateStyle: "medium", timeStyle: "short" });

  return (
    <section className="flex min-w-0 flex-1 flex-col overflow-y-auto bg-panel">
      <div className="mx-auto w-full max-w-4xl px-8 py-8">
        <div className="flex items-center gap-5">
          <ScoreRing score={score} />
          <div>
            <h2 className="text-xl font-semibold tracking-tight">{t("sentinel.title")}</h2>
            <p className="mt-1 max-w-md text-[13px] leading-relaxed text-muted">{t("sentinel.subtitle")}</p>
            <p className="mt-1 text-xs text-subtle">{t("sentinel.checked", { count: report.checked })}</p>
          </div>
        </div>

        <div className="mt-8 grid grid-cols-[repeat(auto-fill,minmax(180px,1fr))] gap-3">
          {SENTINEL_ALERTS.map((alert) => (
            <AlertCard
              key={alert}
              icon={ALERT_ICONS[alert]}
              tone={ALERT_TONE[alert]}
              label={t(ALERT_TITLE[alert])}
              value={isPending(report, alert) ? null : issues.get(alert)!.size}
              placeholder={t("sentinel.notChecked")}
              onOpen={() => setView({ kind: "sentinel", alert })}
            />
          ))}
          <AlertCard
            icon={BellOff}
            tone="info"
            muted
            label={t("sentinel.ignoredTitle")}
            value={report.ignored.length}
            onOpen={() => setView({ kind: "sentinel", alert: "ignored" })}
          />
        </div>

        <div className="mt-4 rounded-xl border border-line bg-panel-2 p-4">
          <div className="flex items-center gap-3">
            <ShieldCheck className="size-5 shrink-0 text-accent" />
            <p className="flex-1 text-xs leading-relaxed text-muted">{t("sentinel.breachPrivacy")}</p>
            <Button size="sm" onClick={checkBreaches} loading={checking}>
              {checking ? t("sentinel.checkingBreaches") : t("sentinel.checkBreaches")}
            </Button>
          </div>
          {settings && (
            <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-line pt-3 pl-8">
              <label className="flex flex-1 items-center gap-2.5 text-xs">
                <Switch
                  checked={settings.sentinel_auto}
                  label={t("sentinel.autoCheck")}
                  onChange={(on) => {
                    void setSettings({ ...settings, sentinel_auto: on })
                      .then(() => {
                        // Turned on: the first check now rather than later.
                        if (on && report.passwordsCheckedAt === null) void checkBreaches();
                      })
                      .catch((err) => toast.error(errorMessage(err)));
                  }}
                />
                {t("sentinel.autoCheck")}
              </label>
              <div className="flex flex-col items-end text-xs text-subtle">
                {report.passwordsCheckedAt !== null && <span>{t("sentinel.lastChecked", { when: when(report.passwordsCheckedAt) })}</span>}
                {report.listsUpdatedAt !== null && <span>{t("sentinel.listsUpdated", { when: when(report.listsUpdatedAt) })}</span>}
                {report.passwordsCheckedAt !== null && report.unchecked > 0 && !checking && (
                  <span className="text-warning">{t("sentinel.unchecked", { count: report.unchecked })}</span>
                )}
              </div>
            </div>
          )}
        </div>

        {!anything && (
          <div className="mt-10 flex flex-col items-center text-center">
            <CircleCheck className="size-10 text-success" />
            <p className="mt-3 text-sm font-medium">{t("sentinel.allGood")}</p>
          </div>
        )}
      </div>
    </section>
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

/** One alert's card: how many items have it; opens their list. */
function AlertCard({
  icon: Icon,
  label,
  value,
  tone,
  muted = false,
  placeholder,
  onOpen,
}: {
  icon: LucideIcon;
  label: string;
  value: number | null;
  tone: Tone;
  muted?: boolean;
  placeholder?: string;
  onOpen: () => void;
}) {
  const { t } = useTranslation();
  const active = !muted && value !== null && value > 0;
  return (
    <button
      type="button"
      onClick={onOpen}
      className="group flex flex-col rounded-xl border border-line p-4 text-left transition-colors hover:border-line-strong hover:bg-panel-2"
    >
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
        <Icon className="size-5" />
      </div>
      <div className="mt-3 text-2xl font-semibold tabular-nums">{value ?? "—"}</div>
      <div className="text-xs text-muted">{value === null ? placeholder : label}</div>
      <div className="mt-3 flex items-center gap-1 text-xs font-medium text-accent opacity-80 group-hover:opacity-100">
        {t("sentinel.viewItems")} <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
      </div>
    </button>
  );
}

/** Above a Sentinel list: which alert it shows, to switch to another (or
 * back to the overview). */
export function AlertPicker({ current }: { current: SentinelAlert | "ignored" }) {
  const { t } = useTranslation();
  const issues = useIssues();
  const report = useSentinel((s) => s.report);
  const setView = useApp((s) => s.setView);
  const Icon = current === "ignored" ? BellOff : ALERT_ICONS[current];
  const count = (alert: SentinelAlert) => (isPending(report, alert) ? "—" : String(issues.get(alert)!.size));
  const mark = (alert: SentinelAlert | "ignored") => (alert === current ? <Check className="size-4 text-accent" /> : null);
  return (
    <Menu>
      <MenuTrigger asChild>
        <button className="flex min-w-0 items-center gap-1.5 rounded-lg bg-accent-soft px-2.5 py-1 text-[13px] font-semibold text-accent hover:brightness-110">
          <Icon className="size-4 shrink-0" />
          <span className="truncate">{current === "ignored" ? t("sentinel.ignoredTitle") : t(ALERT_TITLE[current])}</span>
          <ChevronDown className="size-3.5 shrink-0" />
        </button>
      </MenuTrigger>
      <MenuContent align="start">
        {SENTINEL_ALERTS.map((alert) => {
          const AlertIcon = ALERT_ICONS[alert];
          return (
            <MenuItem key={alert} icon={mark(alert) ?? <AlertIcon className="size-4" />} shortcut={count(alert)} onSelect={() => setView({ kind: "sentinel", alert })}>
              {t(ALERT_TITLE[alert])}
            </MenuItem>
          );
        })}
        <MenuSeparator />
        <MenuItem icon={mark("ignored") ?? <BellOff className="size-4" />} shortcut={String(report?.ignored.length ?? 0)} onSelect={() => setView({ kind: "sentinel", alert: "ignored" })}>
          {t("sentinel.ignoredTitle")}
        </MenuItem>
        <MenuItem icon={<Binoculars className="size-4" />} onSelect={() => setView({ kind: "sentinel" })}>
          {t("sentinel.overview")}
        </MenuItem>
      </MenuContent>
    </Menu>
  );
}

/** At the top of an item: what Sentinel found about it, with what to do.
 * In the list of ignored alerts, those alerts too, to watch again. */
export function SentinelBanners({ itemId, hasUrl, canEdit }: { itemId: string; hasUrl: boolean; canEdit: boolean }) {
  const { t, i18n } = useTranslation();
  const issues = useIssues();
  const report = useSentinel((s) => s.report);
  const view = useApp((s) => s.view);
  const loadData = useApp((s) => s.loadData);
  const day = useDay();

  const active = SENTINEL_ALERTS.flatMap((alert) => {
    const detail = issues.get(alert)!.get(itemId);
    return detail ? [{ alert, detail }] : [];
  });
  const ignored =
    view.kind === "sentinel" && view.alert === "ignored" ? (report?.ignored ?? []).filter(([id]) => id === itemId).map(([, alert]) => alert) : [];
  if (!active.length && !ignored.length) return null;

  const setIgnored = async (alert: SentinelAlert, value: boolean) => {
    try {
      await api.setSentinelIgnored(itemId, alert, value);
      await loadData();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  const openSite = () => api.openItemUrl(itemId, 0).catch((err) => toast.error(errorMessage(err)));

  const note = (alert: SentinelAlert, d: AlertDetail): string | null => {
    switch (alert) {
      case "breached":
        return t("sentinel.breachedSeen", { count: d.seen ?? 0, formatted: (d.seen ?? 0).toLocaleString(i18n.language) });
      case "compromised":
        return t("sentinel.compromisedNote", { site: d.site, date: d.date ? day(d.date) : "" });
      case "reused":
        return t("sentinel.sharedWith", { count: d.others ?? 0 });
      case "expiring":
        return d.date ? t(d.expired ? "sentinel.expiredOn" : "sentinel.expiresOn", { date: day(d.date) }) : null;
      case "two_factor":
        return t("sentinel.twoFactorNote", { site: d.site });
      case "passkey":
        return t("sentinel.passkeyNote", { site: d.site });
      case "duplicate":
        return t("sentinel.duplicateNote", { count: d.others ?? 0 });
      default:
        return null;
    }
  };

  return (
    <div className="space-y-2">
      {active.map(({ alert, detail }) => {
        const tone = ALERT_TONE[alert];
        const Icon = ALERT_ICONS[alert];
        const line = note(alert, detail);
        return (
          <div
            key={alert}
            className={cx(
              "flex items-start gap-3 rounded-xl border px-4 py-3",
              tone === "danger" ? "border-danger/40 bg-danger-soft" : tone === "info" ? "border-accent/40 bg-accent-soft" : "border-warning/40 bg-warning-soft",
            )}
          >
            <Icon className={cx("mt-0.5 size-4 shrink-0", tone === "danger" ? "text-danger" : tone === "info" ? "text-accent" : "text-warning")} />
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-semibold">{t(`sentinel.alert.${alert}`)}</div>
              {line && <div className="mt-0.5 text-xs text-fg">{line}</div>}
              <div className="mt-0.5 text-xs leading-relaxed text-muted">{t(ALERT_HINT[alert])}</div>
              <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                {hasUrl && alert !== "expiring" && alert !== "duplicate" && (
                  <Button size="sm" onClick={() => void openSite()}>
                    <ExternalLink className="size-3.5" /> {t("sentinel.openSite")}
                  </Button>
                )}
                <Button size="sm" variant="ghost" onClick={() => void setIgnored(alert, true)} disabled={!canEdit} title={t("sentinel.ignore")}>
                  <BellOff className="size-3.5" /> {t("sentinel.ignoreShort")}
                </Button>
              </div>
            </div>
          </div>
        );
      })}
      {ignored.map((alert) => (
        <div key={`ignored-${alert}`} className="flex items-center gap-3 rounded-xl border border-line bg-panel-2 px-4 py-3">
          <BellOff className="size-4 shrink-0 text-subtle" />
          <div className="min-w-0 flex-1 text-[13px]">
            <span className="text-muted">{t("sentinel.ignoredAlert")}</span> <span className="font-medium">{t(`sentinel.alert.${alert}`)}</span>
          </div>
          <Button size="sm" variant="ghost" onClick={() => void setIgnored(alert, false)} disabled={!canEdit}>
            <BellRing className="size-3.5" /> {t("sentinel.watchAgain")}
          </Button>
        </div>
      ))}
    </div>
  );
}

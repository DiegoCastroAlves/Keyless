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
  Gauge,
  Globe,
  Info,
  KeyRound,
  Layers,
  Lock,
  LockOpen,
  Repeat,
  RotateCcwKey,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
  X,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { LEVELS, STRENGTH_COLORS, STRENGTH_TEXT } from "../../components/common";
import { Button, IconButton, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger, Spinner, Switch, Tooltip, cx } from "../../components/ui";
import { api, errorMessage, type BreachDetails, type SentinelAlert, type Settings } from "../../lib/api";
import {
  ALERT_TITLE,
  SENTINEL_ALERTS,
  SERIOUS_ALERTS,
  isOff,
  isPending,
  scoreOf,
  showInSentinel,
  strengthCounts,
  useInScope,
  useIssues,
  useScopedIssues,
  useSentinel,
  type AlertDetail,
} from "../../lib/sentinel";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { VaultGlyph } from "../../lib/vaultLook";
import { itemWindowId } from "../../lib/windows";
import { DevSecrets } from "./DevSecrets";
import { RecoveryAlert } from "./RecoveryKey";

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
  lastpass: ShieldQuestion,
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
  lastpass: "danger",
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
  lastpass: "sentinel.lastpassHint",
};

/** The public lists, each turned on or off on its own. */
const LIST_SETTINGS: { key: "sentinel_breach_list" | "sentinel_two_factor_list" | "sentinel_passkey_list"; label: string }[] = [
  { key: "sentinel_breach_list", label: "sentinel.listBreaches" },
  { key: "sentinel_two_factor_list", label: "sentinel.listTwoFactor" },
  { key: "sentinel_passkey_list", label: "sentinel.listPasskeys" },
];

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

/** Sentinel's overview: the score, a card per alert (each opens its items),
 * the strength of the passwords and the online check; for every vault or
 * one of them. */
export function Sentinel() {
  const { t, i18n } = useTranslation();
  const report = useSentinel((s) => s.report);
  const scope = useSentinel((s) => s.scope);
  const issues = useScopedIssues();
  const inScope = useInScope();
  const [checking, setChecking] = useState(false);
  const settings = useApp((s) => s.settings);
  const setSettings = useApp((s) => s.setSettings);
  const setView = useApp((s) => s.setView);
  const vaults = useApp((s) => s.vaults);

  // The vault chosen is gone (deleted, or another account): every vault.
  useEffect(() => {
    if (scope && vaults.length && !vaults.some((v) => v.id === scope)) useSentinel.getState().setScope(null);
  }, [scope, vaults]);

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

  const strengths = strengthCounts(report, scope);
  const checked = strengths.reduce((a, b) => a + b, 0);
  const score = scoreOf(issues, checked);
  const anything = SENTINEL_ALERTS.some((a) => issues.get(a)!.size > 0);
  const ignoredCount = report.ignored.filter(([id]) => !inScope || inScope(id)).length;
  const when = (at: number) => new Date(at * 1000).toLocaleString(i18n.language, { dateStyle: "medium", timeStyle: "short" });
  const saveSettings = (patch: Partial<Settings>) => settings && setSettings({ ...settings, ...patch });

  return (
    <section className="flex min-w-0 flex-1 flex-col overflow-y-auto bg-panel">
      <div className="mx-auto w-full max-w-4xl px-8 py-8">
        <div className="flex items-center gap-5">
          <ScoreRing score={score} />
          <div className="min-w-0 flex-1">
            <h2 className="text-xl font-semibold tracking-tight">{t("sentinel.title")}</h2>
            <p className="mt-1 max-w-md text-[13px] leading-relaxed text-muted">{t("sentinel.subtitle")}</p>
            <p className="mt-1 text-xs text-subtle">{t("sentinel.checked", { count: checked })}</p>
          </div>
          {vaults.length > 1 && <ScopePicker />}
        </div>

        <RecoveryAlert />

        <div className="mt-8 grid grid-cols-[repeat(auto-fill,minmax(180px,1fr))] gap-3">
          {SENTINEL_ALERTS.map((alert) => (
            <AlertCard
              key={alert}
              icon={ALERT_ICONS[alert]}
              tone={ALERT_TONE[alert]}
              label={t(ALERT_TITLE[alert])}
              value={isPending(report, alert) || isOff(report, alert) ? null : issues.get(alert)!.size}
              placeholder={isOff(report, alert) ? t("sentinel.off") : t("sentinel.notChecked")}
              onOpen={() => setView({ kind: "sentinel", alert })}
            />
          ))}
          <AlertCard
            icon={BellOff}
            tone="info"
            muted
            label={t("sentinel.ignoredTitle")}
            value={ignoredCount}
            onOpen={() => setView({ kind: "sentinel", alert: "ignored" })}
          />
        </div>

        {checked > 0 && <StrengthView counts={strengths} scope={scope} />}

        <div className="mt-4 rounded-xl border border-line bg-panel-2 p-4">
          <div className="flex items-center gap-3">
            <ShieldCheck className="size-5 shrink-0 text-accent" />
            <p className="flex-1 text-xs leading-relaxed text-muted">{t("sentinel.breachPrivacy")}</p>
            <Button size="sm" onClick={checkBreaches} loading={checking}>
              {checking ? t("sentinel.checkingBreaches") : t("sentinel.checkBreaches")}
            </Button>
          </div>
          {settings && (
            <div className="mt-3 flex flex-wrap items-start gap-x-3 gap-y-1 border-t border-line pt-3 pl-8">
              <div className="flex flex-1 flex-col gap-1.5">
                <label className="flex items-center gap-2.5 text-xs">
                  <Switch
                    checked={settings.sentinel_check_passwords}
                    label={t("sentinel.autoCheck")}
                    onChange={(on) => {
                      void setSettings({ ...settings, sentinel_check_passwords: on })
                        .then(() => {
                          // Turned on: the first check now rather than later.
                          if (on && report.passwordsCheckedAt === null) void checkBreaches();
                        })
                        .catch((err) => toast.error(errorMessage(err)));
                    }}
                  />
                  {t("sentinel.autoCheck")}
                </label>
                <label className="flex items-center gap-2.5 text-xs">
                  <Switch
                    checked={settings.sentinel_notifications}
                    label={t("sentinel.notifications")}
                    onChange={(on) => void setSettings({ ...settings, sentinel_notifications: on }).catch((err) => toast.error(errorMessage(err)))}
                  />
                  {t("sentinel.notifications")}
                </label>
                <div className="mt-1.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("sentinel.listsTitle")}</div>
                {LIST_SETTINGS.map(({ key, label }) => (
                  <label key={key} className="flex items-center gap-2.5 text-xs">
                    <Switch checked={settings[key]} label={t(label)} onChange={(on) => void saveSettings({ [key]: on })?.catch((err) => toast.error(errorMessage(err)))} />
                    {t(label)}
                  </label>
                ))}
              </div>
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

        <DevSecrets />

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

/** Which vaults Sentinel looks at: all of them, or one. */
function ScopePicker() {
  const { t } = useTranslation();
  const scope = useSentinel((s) => s.scope);
  const setScope = useSentinel((s) => s.setScope);
  const vaults = useApp((s) => s.vaults);
  const current = vaults.find((v) => v.id === scope);
  const mark = (id: string | null) => (id === scope ? <Check className="size-4 text-accent" /> : null);
  return (
    <Menu>
      <MenuTrigger asChild>
        <button
          aria-label={t("sentinel.scopeLabel")}
          className="flex max-w-56 shrink-0 items-center gap-1.5 self-start rounded-lg border border-line px-2.5 py-1.5 text-[13px] font-medium hover:bg-panel-2 data-[state=open]:bg-panel-2"
        >
          {current ? <VaultGlyph vault={current} className="size-4 shrink-0" /> : <Layers className="size-4 shrink-0 text-muted" />}
          <span className="truncate">{current ? current.name : t("sentinel.scopeAll")}</span>
          <ChevronDown className="size-3.5 shrink-0 text-muted" />
        </button>
      </MenuTrigger>
      <MenuContent>
        <MenuItem icon={mark(null) ?? <Layers className="size-4" />} onSelect={() => setScope(null)}>
          {t("sentinel.scopeAll")}
        </MenuItem>
        <MenuSeparator />
        {vaults.map((vault) => (
          <MenuItem key={vault.id} icon={mark(vault.id) ?? <VaultGlyph vault={vault} className="size-4" />} onSelect={() => setScope(vault.id)}>
            {vault.name}
          </MenuItem>
        ))}
      </MenuContent>
    </Menu>
  );
}

/** How many passwords are at each strength level; a level opens its items
 * (the list filtered by it). */
function StrengthView({ counts, scope }: { counts: number[]; scope: string | null }) {
  const { t } = useTranslation();
  const total = counts.reduce((a, b) => a + b, 0);
  const open = (level: number) => {
    const { setView, setFilters } = useApp.getState();
    setView(scope ? { kind: "vault", id: scope } : { kind: "all" });
    setFilters({ strength: level });
  };
  return (
    <div className="mt-4 rounded-xl border border-line p-4">
      <div className="flex items-center gap-3">
        <Gauge className="size-5 shrink-0 text-accent" />
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold">{t("sentinel.strengthTitle")}</div>
          <p className="text-xs leading-relaxed text-muted">{t("sentinel.strengthHint")}</p>
        </div>
      </div>
      <div className="mt-3 flex h-2 overflow-hidden rounded-full bg-panel-3" aria-hidden>
        {LEVELS.map((level) =>
          counts[level] ? <div key={level} className={STRENGTH_COLORS[level]} style={{ width: `${(counts[level] / total) * 100}%` }} /> : null,
        )}
      </div>
      <div className="mt-3 grid grid-cols-[repeat(auto-fill,minmax(100px,1fr))] gap-2">
        {LEVELS.map((level) => (
          <button
            key={level}
            type="button"
            disabled={!counts[level]}
            onClick={() => open(level)}
            className="rounded-lg border border-line px-3 py-2 text-left transition-colors enabled:hover:border-line-strong enabled:hover:bg-panel-2 disabled:opacity-50"
          >
            <div className="text-lg font-semibold tabular-nums">{counts[level]}</div>
            <div className={cx("truncate text-xs font-medium", STRENGTH_TEXT[level])}>{t(`strength.${level}`)}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

function ScoreRing({ score, small = false }: { score: number; small?: boolean }) {
  const color = score >= 90 ? "var(--success)" : score >= 70 ? "var(--accent)" : score >= 40 ? "var(--warning)" : "var(--danger)";
  const circumference = 2 * Math.PI * 34;
  return (
    <div className={cx("relative shrink-0", small ? "size-9" : "size-24")}>
      <svg viewBox="0 0 80 80" className={cx("-rotate-90", small ? "size-9" : "size-24")}>
        <circle cx="40" cy="40" r="34" fill="none" stroke="var(--panel-3)" strokeWidth={small ? 9 : 7} />
        <circle
          cx="40"
          cy="40"
          r="34"
          fill="none"
          stroke={color}
          strokeWidth={small ? 9 : 7}
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * circumference} ${circumference}`}
          style={{ transition: "stroke-dasharray 600ms ease" }}
        />
      </svg>
      <div className={cx("absolute inset-0 flex items-center justify-center font-semibold tabular-nums", small ? "text-[11px]" : "text-2xl")}>{score}</div>
    </div>
  );
}

/** Above every item: Sentinel's score and how many serious alerts there
 * are, in every vault; opens Sentinel. */
export function SentinelSummary() {
  const { t } = useTranslation();
  const report = useSentinel((s) => s.report);
  const issues = useIssues();
  if (!report || report.checked === 0) return null;
  const serious = SERIOUS_ALERTS.reduce((n, alert) => n + issues.get(alert)!.size, 0);
  return (
    <button
      type="button"
      onClick={() => {
        useSentinel.getState().setScope(null);
        useApp.getState().setView({ kind: "sentinel" });
      }}
      className="group mx-3 mb-2 flex items-center gap-3 rounded-lg border border-line px-2.5 py-2 text-left transition-colors hover:bg-panel-2"
    >
      <ScoreRing score={scoreOf(issues, report.checked)} small />
      <div className="min-w-0 flex-1">
        <div className="truncate text-[13px] font-medium">{t("sentinel.title")}</div>
        <div className={cx("truncate text-xs", serious ? "font-medium text-danger" : "text-muted")}>
          {serious ? t("sentinel.seriousAlerts", { count: serious }) : t("sentinel.noSeriousAlerts")}
        </div>
      </div>
      <ArrowRight className="size-3.5 shrink-0 text-subtle transition-transform group-hover:translate-x-0.5" />
    </button>
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
      <div className="text-xs text-muted">{label}</div>
      {value === null && placeholder && <div className="text-[11px] text-subtle">{placeholder}</div>}
      <div className="mt-auto flex items-center gap-1 pt-3 text-xs font-medium text-accent opacity-80 group-hover:opacity-100">
        {t("sentinel.viewItems")} <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
      </div>
    </button>
  );
}

/** Above a Sentinel list: which alert it shows, to switch to another (or
 * back to the overview). */
export function AlertPicker({ current }: { current: SentinelAlert | "ignored" }) {
  const { t } = useTranslation();
  const issues = useScopedIssues();
  const inScope = useInScope();
  const report = useSentinel((s) => s.report);
  const setView = useApp((s) => s.setView);
  const Icon = current === "ignored" ? BellOff : ALERT_ICONS[current];
  const count = (alert: SentinelAlert) => (isOff(report, alert) ? t("sentinel.offShort") : isPending(report, alert) ? "—" : String(issues.get(alert)!.size));
  const mark = (alert: SentinelAlert | "ignored") => (alert === current ? <Check className="size-4 text-accent" /> : null);
  const ignored = (report?.ignored ?? []).filter(([id]) => !inScope || inScope(id)).length;
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
        <MenuItem icon={mark("ignored") ?? <BellOff className="size-4" />} shortcut={String(ignored)} onSelect={() => setView({ kind: "sentinel", alert: "ignored" })}>
          {t("sentinel.ignoredTitle")}
        </MenuItem>
        <MenuItem icon={<Binoculars className="size-4" />} onSelect={() => setView({ kind: "sentinel" })}>
          {t("sentinel.overview")}
        </MenuItem>
      </MenuContent>
    </Menu>
  );
}

/** A breach's data class ("Email addresses") in the user's language, when
 * Keyless knows it; the list's own words otherwise. */
function useDataClass() {
  const { t } = useTranslation();
  return (name: string) => t(`sentinel.dataClasses.${name.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`, { defaultValue: name });
}

/** "Learn more" about a breached website: the breach, when it happened and
 * what leaked, as Have I Been Pwned's list says. */
function BreachInfo({ breach, date }: { breach: BreachDetails; date?: string }) {
  const { t, i18n } = useTranslation();
  const day = useDay();
  const dataClass = useDataClass();
  return (
    <div className="space-y-2 bg-panel-2 px-3 py-2.5 pl-13 text-xs leading-relaxed">
      <div className="text-muted">
        <span className="font-medium text-fg">{breach.title}</span>
        {date && <> · {t("sentinel.breachDate", { date: day(date) })}</>}
        {breach.accounts > 0 && <> · {t("sentinel.breachAccounts", { count: breach.accounts, formatted: breach.accounts.toLocaleString(i18n.language) })}</>}
      </div>
      {breach.dataClasses.length > 0 && (
        <div>
          <div className="text-muted">{t("sentinel.breachLeaked")}</div>
          <div className="mt-1 flex flex-wrap gap-1">
            {breach.dataClasses.map((name) => (
              <span key={name} className="rounded-full bg-panel-3 px-2 py-0.5 text-[11px] font-medium">
                {dataClass(name)}
              </span>
            ))}
          </div>
        </div>
      )}
      <div className="text-[11px] text-subtle">{t("sentinel.breachSource")}</div>
    </div>
  );
}

/** At the top of an item: what Sentinel found about it, with what to do.
 * In the list of ignored alerts, those alerts too, to watch again (or to
 * remove, when they no longer apply). */
export function SentinelBanners({ itemId, hasUrl, canEdit }: { itemId: string; hasUrl: boolean; canEdit: boolean }) {
  const { t, i18n } = useTranslation();
  const issues = useIssues();
  const report = useSentinel((s) => s.report);
  const view = useApp((s) => s.view);
  const loadData = useApp((s) => s.loadData);
  const day = useDay();
  // "Learn more" is open for this item (not for the next one shown).
  const [detailsOf, setDetailsOf] = useState<string | null>(null);
  const details = detailsOf === itemId;
  const [busy, setBusy] = useState(false);

  const active = SENTINEL_ALERTS.flatMap((alert) => {
    const detail = issues.get(alert)!.get(itemId);
    return detail ? [{ alert, detail }] : [];
  });
  const ignored =
    view.kind === "sentinel" && view.alert === "ignored" ? (report?.ignored ?? []).filter(([id]) => id === itemId).map(([, alert]) => alert) : [];
  const stale = new Set((report?.stale ?? []).filter(([id]) => id === itemId).map(([, alert]) => alert));
  if (!active.length && !ignored.length) return null;

  const setIgnored = async (alert: SentinelAlert, value: boolean) => {
    try {
      await api.setSentinelIgnored(itemId, alert, value);
      await loadData();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  const switchToHttps = async () => {
    setBusy(true);
    try {
      await api.sentinelUseHttps(itemId);
      await loadData();
      toast.success(t("sentinel.httpsDone"));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const openSite = () => api.openItemUrl(itemId, 0).catch((err) => toast.error(errorMessage(err)));
  const changePassword = () => api.openChangePassword(itemId).catch((err) => toast.error(errorMessage(err)));
  const PASSWORD_ALERTS: SentinelAlert[] = ["breached", "compromised", "lastpass", "weak", "reused"];

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

  // One compact row per alert; the longer explanation is in the tooltip.
  return (
    <div className="divide-y divide-line overflow-hidden rounded-xl border border-line">
      {active.map(({ alert, detail }) => {
        const tone = ALERT_TONE[alert];
        const Icon = ALERT_ICONS[alert];
        const line = note(alert, detail);
        // Already in that list, or in an item's own window (no lists there).
        const inList = (view.kind === "sentinel" && view.alert === alert) || !!itemWindowId;
        return (
          <div key={alert}>
            <div className={cx("flex items-center gap-3 py-2 pl-3 pr-2", tone === "danger" && "bg-danger-soft")}>
              <span
                className={cx(
                  "flex size-7 shrink-0 items-center justify-center rounded-lg",
                  tone === "danger" ? "bg-danger/15 text-danger" : tone === "info" ? "bg-accent-soft text-accent" : "bg-warning-soft text-warning",
                )}
              >
                <Icon className="size-3.5" />
              </span>
              <Tooltip content={<span className="block max-w-72 font-normal leading-relaxed">{t(ALERT_HINT[alert])}</span>}>
                <div className="min-w-0 flex-1 cursor-default">
                  <div className="text-[13px] font-medium leading-snug">{t(`sentinel.alert.${alert}`)}</div>
                  {line && <div className="text-xs leading-snug text-muted">{line}</div>}
                </div>
              </Tooltip>
              {alert === "unsecured" && canEdit && report?.httpsReady?.includes(itemId) && (
                <Tooltip content={t("sentinel.useHttpsHint")}>
                  <Button size="sm" variant="ghost" className="h-7 shrink-0 px-2 text-xs" loading={busy} onClick={() => void switchToHttps()}>
                    <Lock className="size-3.5" /> {t("sentinel.useHttps")}
                  </Button>
                </Tooltip>
              )}
              {alert === "compromised" && detail.breach && (
                <Tooltip content={details ? t("sentinel.lessDetails") : t("sentinel.learnMore")}>
                  <IconButton label={t("sentinel.learnMore")} active={details} onClick={() => setDetailsOf(details ? null : itemId)} className="size-7">
                    <Info className="size-3.5" />
                  </IconButton>
                </Tooltip>
              )}
              {hasUrl && PASSWORD_ALERTS.includes(alert) ? (
                <Tooltip content={t("sentinel.changePassword")}>
                  <IconButton label={t("sentinel.changePassword")} onClick={() => void changePassword()} className="size-7">
                    <RotateCcwKey className="size-3.5" />
                  </IconButton>
                </Tooltip>
              ) : (
                hasUrl &&
                alert !== "expiring" &&
                alert !== "duplicate" && (
                  <Tooltip content={t("sentinel.openSite")}>
                    <IconButton label={t("sentinel.openSite")} onClick={() => void openSite()} className="size-7">
                      <ExternalLink className="size-3.5" />
                    </IconButton>
                  </Tooltip>
                )
              )}
              {!inList && (
                <Tooltip content={t("sentinel.showInSentinel")}>
                  <IconButton label={t("sentinel.showInSentinel")} onClick={() => showInSentinel(itemId, alert)} className="size-7">
                    <Binoculars className="size-3.5" />
                  </IconButton>
                </Tooltip>
              )}
              {canEdit && (
                <Tooltip content={t("sentinel.ignore")}>
                  <IconButton label={t("sentinel.ignore")} onClick={() => void setIgnored(alert, true)} className="size-7">
                    <BellOff className="size-3.5" />
                  </IconButton>
                </Tooltip>
              )}
            </div>
            {alert === "compromised" && detail.breach && details && <BreachInfo breach={detail.breach} date={typeof detail.date === "string" ? detail.date : undefined} />}
          </div>
        );
      })}
      {ignored.map((alert) => (
        <div key={`ignored-${alert}`} className="flex items-center gap-3 py-2 pl-3 pr-2">
          <span className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-panel-3 text-subtle">
            <BellOff className="size-3.5" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="truncate text-[13px]">
              <span className="text-muted">{t("sentinel.ignoredAlert")}</span> <span className="font-medium">{t(`sentinel.alert.${alert}`)}</span>
            </div>
            {stale.has(alert) && <div className="text-xs leading-snug text-success">{t("sentinel.staleNote")}</div>}
          </div>
          {stale.has(alert) ? (
            <Button size="sm" variant="ghost" onClick={() => void setIgnored(alert, false)} disabled={!canEdit}>
              <X className="size-3.5" /> {t("sentinel.removeIgnore")}
            </Button>
          ) : (
            <Button size="sm" variant="ghost" onClick={() => void setIgnored(alert, false)} disabled={!canEdit}>
              <BellRing className="size-3.5" /> {t("sentinel.watchAgain")}
            </Button>
          )}
        </div>
      ))}
    </div>
  );
}

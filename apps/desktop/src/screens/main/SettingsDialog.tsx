import { Download, Fingerprint, Globe, Info, KeyRound, Settings2, ShieldCheck, Trash, User, X } from "lucide-react";
import { Dialog as RDialog } from "radix-ui";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { PasswordInput, StrengthMeter, useStrength } from "../../components/common";
import { EmergencyKit } from "../../components/EmergencyKit";
import { Button, Combobox, Dialog, ErrorText, Label, Switch, cx } from "../../components/ui";
import { LANGUAGES } from "../../i18n";
import { api, errorMessage, type AccountInfo, type BridgePeer, type Settings } from "../../lib/api";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { UpdateDialog, useUpdateAction } from "./UpdateDialog";
import { ExportPanel, ImportPanel } from "./ImportDialog";

export type SettingsTab = "general" | "security" | "browser" | "account" | "import" | "about";

export function SettingsDialog({
  open,
  onOpenChange,
  initialTab = "general",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialTab?: SettingsTab;
}) {
  const { t } = useTranslation();
  const [tab, setTab] = useState<SettingsTab>(initialTab);
  useEffect(() => {
    if (open) setTab(initialTab);
  }, [open, initialTab]);

  const tabs: { id: SettingsTab; label: string; icon: ReactNode }[] = [
    { id: "general", label: t("settings.general"), icon: <Settings2 className="size-4" /> },
    { id: "security", label: t("settings.security"), icon: <ShieldCheck className="size-4" /> },
    { id: "browser", label: t("settings.browser"), icon: <Globe className="size-4" /> },
    { id: "account", label: t("settings.account"), icon: <User className="size-4" /> },
    { id: "import", label: t("settings.import"), icon: <Download className="size-4" /> },
    { id: "about", label: t("settings.about"), icon: <Info className="size-4" /> },
  ];

  const current = tabs.find((item) => item.id === tab);

  // A fixed sidebar and header; only the section content scrolls.
  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px] animate-fade" />
        <RDialog.Content
          aria-describedby={undefined}
          className="fixed left-1/2 top-1/2 z-50 flex h-[min(720px,calc(100vh-2rem))] w-[min(960px,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 overflow-hidden rounded-2xl border border-line bg-panel shadow-2xl outline-none animate-pop"
        >
          <nav className="flex w-52 shrink-0 flex-col gap-0.5 border-r border-line bg-panel-2 p-3">
            <RDialog.Title className="px-2.5 pb-3 pt-1.5 text-base font-semibold">{t("settings.title")}</RDialog.Title>
            {tabs.map((item) => (
              <button
                key={item.id}
                onClick={() => setTab(item.id)}
                className={cx(
                  "flex h-9 w-full items-center gap-2.5 rounded-lg px-2.5 text-left text-[13px]",
                  tab === item.id ? "bg-accent-soft font-medium text-accent" : "text-muted hover:bg-panel-3 hover:text-fg",
                )}
              >
                {item.icon}
                {item.label}
              </button>
            ))}
          </nav>
          <div className="flex min-w-0 flex-1 flex-col">
            <div className="flex h-14 shrink-0 items-center justify-between border-b border-line pl-7 pr-4">
              <span className="text-sm font-semibold">{current?.label}</span>
              <RDialog.Close
                aria-label={t("common.close")}
                className="flex size-8 items-center justify-center rounded-lg text-muted hover:bg-panel-3 hover:text-fg"
              >
                <X className="size-4" />
              </RDialog.Close>
            </div>
            <div key={tab} className="min-h-0 flex-1 overflow-y-auto px-7 py-5">
              {tab === "general" && <GeneralTab />}
              {tab === "security" && <SecurityTab />}
              {tab === "browser" && <BrowserTab />}
              {tab === "account" && <AccountTab onClose={() => onOpenChange(false)} />}
              {tab === "import" && (
                <div className="space-y-8">
                  <ImportPanel onDone={() => onOpenChange(false)} />
                  <div className="border-t border-line pt-6">
                    <ExportPanel />
                  </div>
                </div>
              )}
              {tab === "about" && <AboutTab />}
            </div>
          </div>
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}

function Row({ title, hint, children }: { title: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-6 border-b border-line py-4 last:border-0">
      <div>
        <div className="text-sm font-medium">{title}</div>
        {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
      </div>
      <div className="w-56 shrink-0">{children}</div>
    </div>
  );
}

function GeneralTab() {
  const { t } = useTranslation();
  const settings = useApp((s) => s.settings);
  const setSettings = useApp((s) => s.setSettings);
  if (!settings) return null;
  const save = (patch: Partial<Settings>) => setSettings({ ...settings, ...patch }).catch((err) => toast.error(errorMessage(err)));

  const durations = [1, 2, 5, 10, 15, 30, 60, 120, 240, 480].map((m) => ({
    value: String(m),
    label: m < 60 ? t("settings.minutes", { count: m }) : t("settings.hours", { count: m / 60 }),
  }));
  const clipboard = [10, 30, 60, 90, 120, 300, 600].map((s) => ({
    value: String(s),
    label: s % 60 === 0 ? t("settings.minutes", { count: s / 60 }) : t("settings.seconds", { count: s }),
  }));

  return (
    <div>
      <Row title={t("settings.language")}>
        <Combobox
          value={settings.language}
          onChange={(language) => save({ language: language as Settings["language"] })}
          options={[{ value: "system", label: t("settings.languageSystem") }, ...LANGUAGES.map((l) => ({ value: l.code, label: l.name }))]}
          searchPlaceholder={t("common.searchPlaceholder")}
        />
      </Row>
      <Row title={t("settings.theme")}>
        <Combobox
          value={settings.theme}
          onChange={(theme) => save({ theme: theme as Settings["theme"] })}
          options={[
            { value: "system", label: t("settings.themeSystem") },
            { value: "light", label: t("settings.themeLight") },
            { value: "dark", label: t("settings.themeDark") },
          ]}
          searchPlaceholder={t("common.searchPlaceholder")}
        />
      </Row>
      <Row title={t("settings.autoLock")} hint={t("settings.autoLockHint")}>
        <Combobox
          value={String(settings.auto_lock_minutes)}
          onChange={(v) => save({ auto_lock_minutes: Number(v) })}
          options={durations}
          searchPlaceholder={t("common.searchPlaceholder")}
        />
      </Row>
      <Row title={t("settings.lockOnSleep")}>
        <div className="flex justify-end">
          <Switch checked={settings.lock_on_sleep} onChange={(lock_on_sleep) => save({ lock_on_sleep })} label={t("settings.lockOnSleep")} />
        </div>
      </Row>
      <Row title={t("settings.clipboard")}>
        <Combobox
          value={String(settings.clipboard_clear_seconds)}
          onChange={(v) => save({ clipboard_clear_seconds: Number(v) })}
          options={clipboard}
          searchPlaceholder={t("common.searchPlaceholder")}
        />
      </Row>
      <QuickAccessRow />
      <Row title={t("settings.closeToTray")} hint={t("settings.closeToTrayHint")}>
        <div className="flex justify-end">
          <Switch checked={settings.close_to_tray} onChange={(close_to_tray) => save({ close_to_tray })} label={t("settings.closeToTray")} />
        </div>
      </Row>
      <Row title={t("settings.startAtLogin")}>
        <div className="flex justify-end">
          <Switch checked={settings.start_at_login} onChange={(start_at_login) => save({ start_at_login })} label={t("settings.startAtLogin")} />
        </div>
      </Row>
      {settings.start_at_login && (
        <Row title={t("settings.startMode")}>
          <Combobox
            value={settings.start_minimized ? "tray" : "window"}
            onChange={(mode) => save({ start_minimized: mode === "tray" })}
            options={[
              { value: "window", label: t("settings.startWindow") },
              { value: "tray", label: t("settings.startTray") },
            ]}
            searchPlaceholder={t("common.searchPlaceholder")}
          />
        </Row>
      )}
      <Row title={t("settings.checkUpdates")} hint={t("settings.checkUpdatesHint")}>
        <div className="flex justify-end">
          <Switch checked={settings.check_updates} onChange={(check_updates) => save({ check_updates })} label={t("settings.checkUpdates")} />
        </div>
      </Row>
    </div>
  );
}

const QUICK_ACCESS_COMMAND = "keyless-desktop --quick-access";
const isWindows = navigator.userAgent.includes("Windows");

/** "Ctrl+Shift+Space" from a key press, or null for a lone modifier. */
function shortcutFrom(e: React.KeyboardEvent): string | null {
  const key = e.code.startsWith("Key")
    ? e.code.slice(3)
    : e.code.startsWith("Digit")
      ? e.code.slice(5)
      : /^(F\d{1,2}|Space)$/.test(e.code)
        ? e.code
        : null;
  if (!key || !(e.ctrlKey || e.altKey || e.metaKey)) return null;
  return [e.ctrlKey && "Ctrl", e.altKey && "Alt", e.shiftKey && "Shift", e.metaKey && "Super", key].filter(Boolean).join("+");
}

function QuickAccessRow() {
  const { t } = useTranslation();
  const settings = useApp((s) => s.settings);
  const [recording, setRecording] = useState(false);
  if (!settings) return null;

  const saveShortcut = async (shortcut: string) => {
    setRecording(false);
    try {
      useApp.setState({ settings: await api.setQuickAccessShortcut(shortcut) });
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  const copyCommand = async () => {
    try {
      await api.copyText(QUICK_ACCESS_COMMAND);
      toast.success(t("settings.quickAccessCopied"));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <>
      <Row title={t("settings.quickAccess")} hint={isWindows ? t("settings.quickAccessHintWindows") : t("settings.quickAccessHintLinux")}>
        <div className="flex justify-end gap-2">
          {isWindows && (
            <button
              onClick={() => setRecording(true)}
              onBlur={() => setRecording(false)}
              onKeyDown={(e) => {
                if (!recording) return;
                e.preventDefault();
                if (e.key === "Escape") setRecording(false);
                else if (e.key === "Backspace") void saveShortcut("");
                else {
                  const shortcut = shortcutFrom(e);
                  if (shortcut) void saveShortcut(shortcut);
                }
              }}
              className={cx(
                "h-8 min-w-36 rounded-lg border px-3 text-sm",
                recording ? "border-accent text-accent" : "border-line bg-panel-2 hover:bg-panel-3",
              )}
            >
              {recording ? t("settings.quickAccessPress") : settings.quick_access_shortcut || t("settings.quickAccessOff")}
            </button>
          )}
          <Button size="sm" className="h-8" onClick={() => void api.showQuickAccess()}>
            {t("settings.quickAccessTry")}
          </Button>
        </div>
      </Row>
      {!isWindows && (
        <div className="-mt-1 mb-2 flex items-center gap-2 rounded-lg bg-panel-2 px-3 py-2 text-xs text-muted">
          <span className="flex-1">
            {t("settings.quickAccessCommand")} <code className="selectable font-mono text-fg">{QUICK_ACCESS_COMMAND}</code>
          </span>
          <Button size="sm" onClick={copyCommand}>
            {t("common.copy")}
          </Button>
        </div>
      )}
    </>
  );
}

function SecurityTab() {
  const { t } = useTranslation();
  const status = useApp((s) => s.status);
  const [secretKey, setSecretKey] = useState<string | null>(null);
  const [kitPrompt, setKitPrompt] = useState(false);
  const [kitPassword, setKitPassword] = useState("");
  const [kitError, setKitError] = useState<string | null>(null);
  const [info, setInfo] = useState<AccountInfo | null>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const strength = useStrength(next, status?.email ?? undefined);

  useEffect(() => {
    api.accountInfo().then(setInfo).catch(() => setInfo(null));
  }, []);

  const showKit = async (e: FormEvent) => {
    e.preventDefault();
    setKitError(null);
    try {
      setSecretKey(await api.revealSecretKey(kitPassword));
      setKitPassword("");
      setKitPrompt(false);
    } catch (err) {
      setKitError(errorMessage(err));
    }
  };

  const change = async (e: FormEvent) => {
    e.preventDefault();
    if (next !== confirm) return;
    setBusy(true);
    setError(null);
    try {
      await api.changeMasterPassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      toast.success(t("settings.passwordChanged"));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-2 text-sm font-semibold">
          <KeyRound className="size-4 text-accent" /> {t("settings.secretKeyTitle")}
        </div>
        <p className="mt-1 text-xs leading-relaxed text-muted">{t("settings.secretKeyBody")}</p>
        {info?.secretKeyInFile && (
          <p className="mt-3 rounded-lg bg-warning-soft px-3 py-2 text-xs leading-relaxed text-warning">{t("settings.secretKeyInFile")}</p>
        )}
        {secretKey ? (
          <div className="mt-4">
            <EmergencyKit email={status?.email ?? ""} secretKey={secretKey} />
          </div>
        ) : kitPrompt ? (
          <form onSubmit={showKit} className="mt-3 space-y-2">
            <Label>{t("settings.confirmWithPassword")}</Label>
            <div className="flex gap-2">
              <div className="flex-1">
                <PasswordInput value={kitPassword} onChange={(e) => setKitPassword(e.target.value)} autoFocus />
              </div>
              <Button type="submit" variant="primary" className="h-10" disabled={!kitPassword}>
                {t("settings.showKit")}
              </Button>
            </div>
            <ErrorText>{kitError}</ErrorText>
          </form>
        ) : (
          <Button size="sm" className="mt-3" onClick={() => setKitPrompt(true)}>
            {t("settings.showKit")}
          </Button>
        )}
      </div>

      <SystemUnlockSection />

      <form onSubmit={change} className="space-y-3 border-t border-line pt-6">
        <div className="text-sm font-semibold">{t("settings.changePassword")}</div>
        <div>
          <Label>{t("settings.currentPassword")}</Label>
          <PasswordInput value={current} onChange={(e) => setCurrent(e.target.value)} />
        </div>
        <div>
          <Label>{t("settings.newPassword")}</Label>
          <PasswordInput value={next} onChange={(e) => setNext(e.target.value)} />
          <StrengthMeter strength={strength} />
        </div>
        <div>
          <Label>{t("settings.confirmPassword")}</Label>
          <PasswordInput value={confirm} onChange={(e) => setConfirm(e.target.value)} invalid={!!confirm && confirm !== next} />
        </div>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" variant="primary" loading={busy} disabled={!current || !next || next !== confirm || (strength?.score ?? 0) < 3}>
          {t("settings.changePassword")}
        </Button>
      </form>
    </div>
  );
}

function SystemUnlockSection() {
  const { t } = useTranslation();
  const settings = useApp((s) => s.settings);
  const supported = useApp((s) => s.status?.systemUnlockSupported ?? false);
  const [prompt, setPrompt] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!settings) return null;

  const saved = (next: Settings) => useApp.setState({ settings: next });
  const close = () => {
    setPrompt(false);
    setPassword("");
    setError(null);
  };
  const turnOff = async () => {
    try {
      saved(await api.setSystemUnlock(false, null));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  const turnOn = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      saved(await api.setSystemUnlock(true, password));
      close();
      toast.success(t("settings.systemUnlockOn"));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="border-t border-line pt-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Fingerprint className="size-4 text-accent" /> {t("settings.systemUnlock")}
          </div>
          <p className="mt-1 text-xs leading-relaxed text-muted">
            {supported ? t("settings.systemUnlockHint") : t("settings.systemUnlockUnsupported")}
          </p>
        </div>
        <Switch
          checked={settings.system_unlock}
          disabled={!supported && !settings.system_unlock}
          onChange={(on) => (on ? setPrompt(true) : void turnOff())}
          label={t("settings.systemUnlock")}
        />
      </div>
      {prompt && !settings.system_unlock && (
        <form onSubmit={turnOn} className="mt-3 space-y-2">
          <Label>{t("settings.confirmWithPassword")}</Label>
          <div className="flex gap-2">
            <div className="flex-1">
              <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
            </div>
            <Button type="submit" variant="primary" className="h-10" loading={busy} disabled={!password}>
              {t("settings.systemUnlockEnable")}
            </Button>
            <Button className="h-10" onClick={close}>
              {t("common.cancel")}
            </Button>
          </div>
          <ErrorText>{error}</ErrorText>
        </form>
      )}
    </div>
  );
}

function BrowserTab() {
  const { t } = useTranslation();
  const settings = useApp((s) => s.settings);
  const setSettings = useApp((s) => s.setSettings);
  const [peers, setPeers] = useState<BridgePeer[]>([]);

  const load = () => api.listBridgePeers().then(setPeers).catch(() => setPeers([]));
  useEffect(() => {
    void load();
  }, []);

  if (!settings) return null;
  const remove = async (peer: BridgePeer) => {
    try {
      await api.removeBridgePeer(peer.publicKey);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <div className="text-sm font-semibold">{t("settings.browserTitle")}</div>
        <p className="mt-1 text-xs leading-relaxed text-muted">{t("settings.browserBody")}</p>
      </div>
      <Row title={t("settings.browserIntegration")} hint={t("settings.browserIntegrationHint")}>
        <div className="flex justify-end">
          <Switch
            checked={settings.browser_integration}
            onChange={(browser_integration) =>
              setSettings({ ...settings, browser_integration }).catch((err) => toast.error(errorMessage(err)))
            }
            label={t("settings.browserIntegration")}
          />
        </div>
      </Row>
      <div>
        <div className="mb-2 text-sm font-medium">{t("settings.pairedBrowsers")}</div>
        {peers.length === 0 ? (
          <p className="text-xs text-muted">{t("settings.noPairedBrowsers")}</p>
        ) : (
          <div className="divide-y divide-line overflow-hidden rounded-xl border border-line">
            {peers.map((peer) => (
              <div key={peer.publicKey} className="flex items-center gap-3 px-3 py-2">
                <Globe className="size-4 text-muted" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm">{peer.name}</div>
                  <div className="text-xs text-subtle">{new Date(peer.pairedAt * 1000).toLocaleDateString()}</div>
                </div>
                <Button size="sm" variant="ghost" onClick={() => remove(peer)} title={t("settings.unpair")}>
                  <Trash className="size-3.5" /> {t("settings.unpair")}
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function AccountTab({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const status = useApp((s) => s.status);
  const refreshStatus = useApp((s) => s.refreshStatus);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const signOut = async () => {
    await api.signOut();
    onClose();
    await refreshStatus();
  };

  const deleteAccount = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.deleteAccount(password);
      setConfirmOpen(false);
      onClose();
      await refreshStatus();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <div className="text-xs text-muted">{t("settings.signedInAs")}</div>
        <div className="selectable mt-0.5 text-sm font-medium">{status?.email}</div>
        <Button size="sm" className="mt-3" onClick={signOut}>
          {t("common.signOutDevice")}
        </Button>
      </div>
      <div className="rounded-xl border border-danger/30 bg-danger-soft p-4">
        <div className="text-sm font-semibold text-danger">{t("settings.deleteAccount")}</div>
        <p className="mt-1 text-xs leading-relaxed text-muted">{t("settings.deleteAccountBody")}</p>
        <Button size="sm" variant="danger" className="mt-3" onClick={() => setConfirmOpen(true)}>
          {t("settings.deleteAccount")}
        </Button>
      </div>
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen} title={t("settings.deleteAccount")} description={t("settings.deleteAccountBody")}>
        <form onSubmit={deleteAccount} className="space-y-3">
          <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} placeholder={t("common.masterPassword")} autoFocus />
          <ErrorText>{error}</ErrorText>
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={() => setConfirmOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant="danger" loading={busy} disabled={!password}>
              {t("settings.deleteAccountConfirm")}
            </Button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}

function AboutTab() {
  const { t } = useTranslation();
  const update = useApp((s) => s.update);
  const setUpdate = useApp((s) => s.setUpdate);
  const [current, setCurrent] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const action = useUpdateAction();

  useEffect(() => {
    void api.versionInfo().then((info) => setCurrent(info.current));
  }, []);

  const check = async () => {
    setChecking(true);
    try {
      const info = await api.checkForUpdates();
      setUpdate(info.update);
      if (!info.update) toast.success(t("update.upToDate"));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="space-y-4 text-sm leading-relaxed">
      <div className="text-lg font-semibold">Keyless</div>
      <div className="flex items-center justify-between gap-3">
        <div className="text-xs text-muted">{current && t("settings.version", { version: current })}</div>
        {!update && (
          <Button size="sm" onClick={check} loading={checking}>
            {t("update.check")}
          </Button>
        )}
      </div>
      {update && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-accent/30 bg-accent-soft px-3 py-2.5">
          <span className="text-[13px]">{t("update.newVersion", { version: update.version })}</span>
          <Button size="sm" variant="primary" onClick={action.start}>
            {t("update.updateNow")}
          </Button>
          <UpdateDialog open={action.open} onOpenChange={action.setOpen} />
        </div>
      )}
      <p className="text-muted">{t("settings.aboutBody")}</p>
      <p className="rounded-lg bg-warning-soft px-3 py-2 text-xs text-warning">{t("settings.beta")}</p>
    </div>
  );
}

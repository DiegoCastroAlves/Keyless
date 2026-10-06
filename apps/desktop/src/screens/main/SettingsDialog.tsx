import { Download, Globe, Info, KeyRound, Settings2, ShieldCheck, Trash, User } from "lucide-react";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { PasswordInput, StrengthMeter, useStrength } from "../../components/common";
import { EmergencyKit } from "../../components/EmergencyKit";
import { Button, Combobox, Dialog, ErrorText, Label, Switch, cx } from "../../components/ui";
import { LANGUAGES } from "../../i18n";
import { api, errorMessage, type AccountInfo, type BridgePeer, type Settings } from "../../lib/api";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
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

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("settings.title")} width="max-w-3xl">
      <div className="flex min-h-[460px] gap-6">
        <nav className="w-44 shrink-0 space-y-0.5">
          {tabs.map((item) => (
            <button
              key={item.id}
              onClick={() => setTab(item.id)}
              className={cx(
                "flex h-8 w-full items-center gap-2.5 rounded-lg px-2.5 text-left text-[13px]",
                tab === item.id ? "bg-accent-soft font-medium text-accent" : "text-muted hover:bg-panel-3 hover:text-fg",
              )}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </nav>
        <div className="min-w-0 flex-1">
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
    </Dialog>
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
    </div>
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
  return (
    <div className="space-y-4 text-sm leading-relaxed">
      <div className="text-lg font-semibold">Keyless</div>
      <div className="text-xs text-muted">{t("settings.version", { version: "0.1.0" })}</div>
      <p className="text-muted">{t("settings.aboutBody")}</p>
      <p className="rounded-lg bg-warning-soft px-3 py-2 text-xs text-warning">{t("settings.beta")}</p>
    </div>
  );
}

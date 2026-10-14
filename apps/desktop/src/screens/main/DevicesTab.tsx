import { Copy, ExternalLink, Fingerprint, Globe, Laptop, LogOut, Monitor, QrCode, Smartphone } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { PasswordInput } from "../../components/common";
import { countryName, platformName, reviewDeviceSetups } from "../../components/DeviceApprovalDialog";
import { Button, Dialog, ErrorText, Label, cx } from "../../components/ui";
import { api, errorMessage, events, type AccountPasskey, type DeviceView, type SetupQr, type SetupRequestView } from "../../lib/api";
import { formatDate, relativeTime } from "../../lib/format";
import { toast } from "../../lib/toast";

function DeviceIcon({ platform }: { platform: string }) {
  const className = "size-5 text-muted";
  if (platform === "android" || platform === "ios") return <Smartphone className={className} />;
  if (platform === "web") return <Globe className={className} />;
  if (platform === "linux") return <Monitor className={className} />;
  return <Laptop className={className} />;
}

const seconds = (iso: string) => Math.floor(new Date(iso).getTime() / 1000);

/** Settings → Devices: where the account is signed in, signing devices
 * out, and setting up a new one. */
export function DevicesTab() {
  const { t, i18n } = useTranslation();
  const [devices, setDevices] = useState<DeviceView[] | null>(null);
  const [requests, setRequests] = useState<SetupRequestView[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<DeviceView | null>(null);
  const [othersOpen, setOthersOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setDevices(await api.listDevices());
      setError(null);
    } catch (err) {
      setError(errorMessage(err));
    }
    setRequests(await api.pendingDeviceSetups().catch(() => []));
  }, []);

  useEffect(() => {
    void load();
    const unlisten = events.onDeviceSetupRequested(() => void load());
    const timer = window.setInterval(() => void load(), 30_000);
    return () => {
      window.clearInterval(timer);
      void unlisten.then((u) => u());
    };
  }, [load]);

  const revoke = async () => {
    if (!revoking) return;
    setBusy(true);
    try {
      await api.revokeDevice(revoking.id);
      toast.success(t("devices.revoked", { name: revoking.name || platformName(revoking.platform, t("devices.web")) }));
      setRevoking(null);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const signOutOthers = async () => {
    setBusy(true);
    try {
      await api.signOutOtherDevices();
      toast.success(t("devices.othersSignedOut"));
      setOthersOpen(false);
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const waiting = requests.filter((r) => r.status !== "elsewhere");

  return (
    <div className="space-y-8">
      <SetUpAnotherDevice />

      {waiting.length > 0 && (
        <div className="flex items-center justify-between gap-4 rounded-xl border border-accent/30 bg-accent-soft p-4">
          <div className="text-[13px] leading-relaxed">{t("devices.requestsWaiting", { count: waiting.length })}</div>
          <Button size="sm" variant="primary" onClick={reviewDeviceSetups}>
            {t("devices.review")}
          </Button>
        </div>
      )}

      <div>
        <div className="text-sm font-semibold">{t("devices.listTitle")}</div>
        <p className="mt-1 text-xs leading-relaxed text-muted">{t("devices.listBody")}</p>
        <ErrorText>{error}</ErrorText>
        <div className={cx("mt-3 divide-y divide-line rounded-xl border border-line", error && devices === null && "hidden")}>
          {devices === null && !error && <div className="p-4 text-xs text-muted">{t("devices.loading")}</div>}
          {devices?.map((device) => {
            const where = [countryName(device.country, i18n.language), device.ip].filter(Boolean).join(" · ");
            return (
              <div key={device.id} className="flex items-center gap-3 p-3.5">
                <DeviceIcon platform={device.platform} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 text-sm font-medium">
                    <span className="truncate">{device.name || platformName(device.platform, t("devices.web"))}</span>
                    {device.current && <span className="rounded-full bg-accent-soft px-2 py-0.5 text-[10px] font-semibold text-accent">{t("devices.thisDevice")}</span>}
                  </div>
                  <div className="mt-0.5 truncate text-xs text-muted">
                    {[device.os || platformName(device.platform, t("devices.web")), device.appVersion && `Keyless ${device.appVersion}`].filter(Boolean).join(" · ")}
                  </div>
                  <div className="mt-0.5 truncate text-xs text-subtle">
                    {[where, device.current ? t("devices.activeNow") : t("devices.lastSeen", { time: relativeTime(seconds(device.lastSeenAt)) })]
                      .filter(Boolean)
                      .join(" · ")}
                    {" · "}
                    {t("devices.since", { date: formatDate(seconds(device.createdAt)) })}
                  </div>
                </div>
                {!device.current && (
                  <Button size="sm" variant="ghost" onClick={() => setRevoking(device)}>
                    <LogOut className="size-4" /> {t("devices.signOut")}
                  </Button>
                )}
              </div>
            );
          })}
        </div>
        <Button size="sm" className="mt-3" onClick={() => setOthersOpen(true)}>
          {t("devices.signOutOthers")}
        </Button>
      </div>

      <Passkeys />

      <Dialog
        open={!!revoking}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={t("devices.revokeTitle", { name: revoking?.name || platformName(revoking?.platform ?? "", t("devices.web")) })}
        description={t("devices.revokeBody")}
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setRevoking(null)}>{t("common.cancel")}</Button>
          <Button variant="danger" loading={busy} onClick={revoke}>
            {t("devices.signOut")}
          </Button>
        </div>
      </Dialog>
      <Dialog open={othersOpen} onOpenChange={setOthersOpen} title={t("devices.signOutOthers")} description={t("devices.signOutOthersBody")}>
        <div className="flex justify-end gap-2">
          <Button onClick={() => setOthersOpen(false)}>{t("common.cancel")}</Button>
          <Button variant="danger" loading={busy} onClick={signOutOthers}>
            {t("devices.signOutOthers")}
          </Button>
        </div>
      </Dialog>
    </div>
  );
}

/** The account's setup code, for a new device to read (after the master
 * password, since it holds the Secret Key). */
function SetUpAnotherDevice() {
  const { t } = useTranslation();
  const [prompt, setPrompt] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [qr, setQr] = useState<SetupQr | null>(null);
  const [busy, setBusy] = useState(false);

  const show = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setQr(await api.accountSetupCode(password));
      setPassword("");
      setPrompt(false);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const copyLink = async () => {
    if (!qr) return;
    try {
      const result = await api.copyText(qr.link);
      toast.copied(t("devices.setupLink"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <div>
      <div className="flex items-center gap-2 text-sm font-semibold">
        <QrCode className="size-4 text-accent" /> {t("devices.setUpTitle")}
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted">{t("devices.setUpBody")}</p>
      {qr ? (
        <div className="mt-4 flex items-center gap-5 rounded-xl border border-line bg-panel-2 p-4">
          <img src={`data:image/svg+xml;utf8,${encodeURIComponent(qr.svg)}`} alt="" className="size-40 shrink-0 rounded-lg bg-white p-1.5" />
          <div className="space-y-3">
            <p className="text-xs leading-relaxed text-muted">{t("devices.setUpQrHelp")}</p>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={copyLink}>
                <Copy className="size-4" /> {t("devices.copySetupLink")}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setQr(null)}>
                {t("common.hide")}
              </Button>
            </div>
          </div>
        </div>
      ) : prompt ? (
        <form onSubmit={show} className="mt-3 space-y-2">
          <Label>{t("settings.confirmWithPassword")}</Label>
          <div className="flex gap-2">
            <div className="flex-1">
              <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
            </div>
            <Button type="submit" variant="primary" className="h-10" loading={busy} disabled={!password}>
              {t("devices.showSetupCode")}
            </Button>
          </div>
          <ErrorText>{error}</ErrorText>
        </form>
      ) : (
        <Button size="sm" className="mt-3" onClick={() => setPrompt(true)}>
          <QrCode className="size-4" /> {t("devices.showSetupCode")}
        </Button>
      )}
    </div>
  );
}

/** Passkeys that sign in to the account (added in the web vault). */
function Passkeys() {
  const { t } = useTranslation();
  const [passkeys, setPasskeys] = useState<AccountPasskey[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .listPasskeys()
      .then((list) => {
        setPasskeys(list);
        setError(null);
      })
      .catch((err) => setError(errorMessage(err)));
  }, []);

  useEffect(load, [load]);

  const remove = async (id: string) => {
    try {
      await api.removePasskey(id);
      load();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <div className="border-t border-line pt-6">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <Fingerprint className="size-4 text-accent" /> {t("devices.passkeysTitle")}
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted">{t("devices.passkeysBody")}</p>
      <ErrorText>{error}</ErrorText>
      {passkeys && passkeys.length > 0 && (
        <div className="mt-3 divide-y divide-line rounded-xl border border-line">
          {passkeys.map((passkey) => (
            <div key={passkey.id} className="flex items-center gap-3 p-3">
              <Fingerprint className="size-4 text-muted" />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{passkey.name || t("devices.passkeyUnnamed")}</div>
                <div className="text-xs text-subtle">
                  {t("devices.passkeyAdded", { date: formatDate(seconds(passkey.createdAt)) })}
                  {passkey.lastUsedAt ? ` · ${t("devices.passkeyUsed", { date: formatDate(seconds(passkey.lastUsedAt)) })}` : ""}
                </div>
              </div>
              <Button size="sm" variant="ghost" onClick={() => remove(passkey.id)}>
                {t("common.remove")}
              </Button>
            </div>
          ))}
        </div>
      )}
      {passkeys && passkeys.length === 0 && <p className="mt-2 text-xs text-subtle">{t("devices.passkeysNone")}</p>}
      <Button size="sm" className="mt-3" onClick={() => void api.openWebVault()}>
        <ExternalLink className="size-4" /> {t("devices.passkeysAdd")}
      </Button>
    </div>
  );
}

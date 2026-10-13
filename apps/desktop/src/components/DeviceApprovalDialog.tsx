import { MonitorSmartphone, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { api, errorMessage, events, type AppError, type SetupRequestView } from "../lib/api";
import { toast } from "../lib/toast";
import { Button, Dialog, ErrorText, Input } from "./ui";

/** Opens the approval dialog (from the device list). */
export function reviewDeviceSetups() {
  window.dispatchEvent(new CustomEvent(REVIEW_EVENT));
}

const REVIEW_EVENT = "keyless:review-device-setups";

const PLATFORMS: Record<string, string> = { linux: "Linux", windows: "Windows", macos: "macOS", android: "Android", ios: "iOS" };

export function platformName(platform: string, web: string): string {
  return platform === "web" ? web : (PLATFORMS[platform] ?? platform);
}

export function countryName(code: string | null, language: string): string | null {
  if (!code) return null;
  try {
    return new Intl.DisplayNames([language], { type: "region" }).of(code) ?? code;
  } catch {
    return code;
  }
}

type Phase = "review" | "waiting" | "code";

/**
 * A new device asks to sign in to the account (see `device_setup`): the user
 * checks where it is, then types here the code the new device shows. Only
 * then does it get the email and Secret Key; it still needs the master
 * password.
 */
export function DeviceApprovalDialog() {
  const { t, i18n } = useTranslation();
  const [request, setRequest] = useState<SetupRequestView | null>(null);
  const [phase, setPhase] = useState<Phase>("review");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const openRef = useRef(false);

  const load = useCallback(async () => {
    try {
      const requests = await api.pendingDeviceSetups();
      // The one this device is handling, else the oldest nobody answered.
      const next = requests.find((r) => r.status === "code" || r.status === "answering") ?? requests.find((r) => r.status === "pending") ?? null;
      setRequest(next);
      openRef.current = !!next;
      if (next) setPhase(next.status === "code" ? "code" : next.status === "answering" ? "waiting" : "review");
      return next;
    } catch {
      return null;
    }
  }, []);

  useEffect(() => {
    const unlisten = events.onDeviceSetupRequested(() => {
      if (!openRef.current) void load();
    });
    const review = () => void load();
    window.addEventListener(REVIEW_EVENT, review);
    // Requests that arrived before this window was ready.
    void load();
    return () => {
      void unlisten.then((u) => u());
      window.removeEventListener(REVIEW_EVENT, review);
    };
  }, [load]);

  // Waits for the new device to reveal its part (then it shows the code).
  useEffect(() => {
    if (phase !== "waiting" || !request) return;
    const timer = window.setInterval(async () => {
      const requests = await api.pendingDeviceSetups().catch(() => null);
      if (!requests) return;
      const current = requests.find((r) => r.id === request.id);
      if (!current) {
        setError(t("approve.expired"));
        setPhase("review");
        setRequest(null);
        openRef.current = false;
      } else if (current.status === "code") {
        setPhase("code");
      }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [phase, request, t]);

  const close = () => {
    setRequest(null);
    openRef.current = false;
    setCode("");
    setError(null);
    setPhase("review");
  };

  const deny = async () => {
    if (request) await api.denyDeviceSetup(request.id).catch(() => {});
    toast.show(t("approve.deniedToast"));
    close();
  };

  const proceed = async () => {
    if (!request) return;
    setBusy(true);
    setError(null);
    try {
      await api.answerDeviceSetup(request.id);
      setPhase("waiting");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const approve = async (e: FormEvent) => {
    e.preventDefault();
    if (!request) return;
    setBusy(true);
    setError(null);
    try {
      await api.approveDeviceSetup(request.id, code);
      toast.success(t("approve.approvedToast"));
      close();
    } catch (err) {
      const message = errorMessage(err);
      if ((err as AppError | null)?.key === "device_setup_code_denied") {
        toast.error(message);
        close();
      } else {
        setError(message);
        setCode("");
      }
    } finally {
      setBusy(false);
    }
  };

  const where = request
    ? [platformName(request.platform, t("devices.web")), countryName(request.country, i18n.language), request.ip].filter(Boolean).join(" · ")
    : "";

  return (
    <Dialog open={!!request} onOpenChange={(open) => !open && close()} title={t("approve.title")} hideClose>
      <div className="flex items-start gap-3 rounded-xl border border-line bg-panel-2 p-4">
        <MonitorSmartphone className="mt-0.5 size-6 shrink-0 text-accent" />
        <div className="min-w-0">
          <div className="text-sm font-medium">{where}</div>
          {request && (
            <div className="mt-0.5 text-xs text-muted">
              {t("approve.askedAt", { time: new Date(request.createdAt).toLocaleTimeString(i18n.language, { hour: "2-digit", minute: "2-digit" }) })}
            </div>
          )}
        </div>
      </div>
      {phase === "review" && (
        <>
          <p className="mt-4 text-[13px] leading-relaxed text-muted">{t("approve.body")}</p>
          <div className="mt-3 flex gap-2.5 rounded-xl bg-warning-soft px-3.5 py-3 text-xs leading-relaxed text-warning">
            <ShieldAlert className="size-4 shrink-0" />
            {t("approve.warning")}
          </div>
          <ErrorText>{error}</ErrorText>
          <div className="mt-5 flex justify-end gap-2">
            <Button onClick={deny}>{t("approve.deny")}</Button>
            <Button variant="primary" loading={busy} onClick={proceed}>
              {t("approve.itsMe")}
            </Button>
          </div>
        </>
      )}
      {phase === "waiting" && (
        <>
          <p className="mt-4 text-[13px] leading-relaxed text-muted">{t("approve.waiting")}</p>
          <div className="mt-5 flex justify-end">
            <Button onClick={deny}>{t("approve.deny")}</Button>
          </div>
        </>
      )}
      {phase === "code" && (
        <form onSubmit={approve}>
          <p className="mt-4 text-[13px] leading-relaxed text-muted">{t("approve.typeCode")}</p>
          <Input
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
            inputMode="numeric"
            autoFocus
            placeholder="000000"
            className="mt-3 h-12 text-center font-mono text-2xl tracking-[0.4em]"
          />
          <ErrorText>{error}</ErrorText>
          <div className="mt-5 flex justify-end gap-2">
            <Button type="button" onClick={deny}>
              {t("approve.deny")}
            </Button>
            <Button type="submit" variant="primary" loading={busy} disabled={code.length !== 6}>
              {t("approve.approve")}
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

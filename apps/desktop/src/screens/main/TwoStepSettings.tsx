import { Copy, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { PasswordInput } from "../../components/common";
import { Button, ErrorText, Input, Label } from "../../components/ui";
import { api, errorMessage, type MfaEnrollment, type MfaStatus } from "../../lib/api";
import { toast } from "../../lib/toast";

type Step = { kind: "idle" } | { kind: "enrolling"; enrollment: MfaEnrollment } | { kind: "codes"; codes: string[] } | { kind: "disabling" };

/** Two-step verification for the Keyless account: a code from an
 * authenticator app when signing in on a new device, with recovery codes. */
export function TwoStepSettings() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [step, setStep] = useState<Step>({ kind: "idle" });
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .mfaStatus()
      .then((s) => {
        setStatus(s);
        setLoadError(null);
      })
      .catch((err) => setLoadError(errorMessage(err)));
  }, []);
  useEffect(load, [load]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const start = () => run(async () => setStep({ kind: "enrolling", enrollment: await api.mfaEnroll() }));

  const activate = (e: FormEvent) => {
    e.preventDefault();
    if (step.kind !== "enrolling") return;
    void run(async () => {
      const codes = await api.mfaActivate(step.enrollment.factorId, code);
      setCode("");
      setStep({ kind: "codes", codes });
      toast.success(t("mfa.enabled"));
      load();
    });
  };

  const regenerate = () => run(async () => setStep({ kind: "codes", codes: await api.mfaRegenerate() }));

  const disable = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.mfaDisable(password);
      setPassword("");
      setStep({ kind: "idle" });
      toast.success(t("mfa.disabled"));
      load();
    });
  };

  const copyCodes = async (codes: string[]) => {
    try {
      const result = await api.copyText(codes.join("\n"));
      toast.copied(t("mfa.codesTitle"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  // Only an image the server made for this: never anything else as a URL.
  const qr = step.kind === "enrolling" && step.enrollment.qrCode.startsWith("data:image/svg+xml") ? step.enrollment.qrCode : null;

  return (
    <div className="rounded-xl border border-line p-4">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <ShieldCheck className="size-4 text-accent" /> {t("mfa.settingsTitle")}
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted">{t("mfa.settingsBody")}</p>

      {loadError && <p className="mt-3 text-xs text-danger">{loadError}</p>}

      {step.kind === "idle" && status && (
        <div className="mt-3">
          {status.enabled ? (
            <>
              <p className="text-xs font-medium text-success">{t("mfa.on", { count: status.recoveryCodesLeft })}</p>
              <div className="mt-3 flex gap-2">
                <Button size="sm" onClick={() => void regenerate()} loading={busy}>
                  {t("mfa.regenerate")}
                </Button>
                <Button size="sm" variant="danger" onClick={() => setStep({ kind: "disabling" })}>
                  {t("mfa.disable")}
                </Button>
              </div>
            </>
          ) : (
            <Button size="sm" variant="primary" onClick={() => void start()} loading={busy}>
              {t("mfa.enable")}
            </Button>
          )}
          <ErrorText>{error}</ErrorText>
        </div>
      )}

      {step.kind === "enrolling" && (
        <form onSubmit={activate} className="mt-4 space-y-3">
          <p className="text-xs leading-relaxed text-muted">{t("mfa.scan")}</p>
          {qr && <img src={qr} alt={t("mfa.qrAlt")} className="size-44 rounded-lg bg-white p-2" />}
          <div>
            <Label>{t("mfa.manualSecret")}</Label>
            <div className="selectable mt-1 break-all rounded-lg bg-panel-2 px-3 py-2 font-mono text-xs">{step.enrollment.secret}</div>
          </div>
          <div>
            <Label htmlFor="mfa-new-code">{t("mfa.enterCode")}</Label>
            <div className="mt-1.5 w-40">
              <Input
                id="mfa-new-code"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/[^0-9 ]/g, ""))}
                inputMode="numeric"
                placeholder="123 456"
                className="h-10 font-mono tracking-wider"
                autoFocus
              />
            </div>
          </div>
          <ErrorText>{error}</ErrorText>
          <div className="flex gap-2">
            <Button type="submit" size="sm" variant="primary" loading={busy} disabled={code.replace(/\D/g, "").length !== 6}>
              {t("mfa.activate")}
            </Button>
            <Button type="button" size="sm" onClick={() => setStep({ kind: "idle" })}>
              {t("common.cancel")}
            </Button>
          </div>
        </form>
      )}

      {step.kind === "codes" && (
        <div className="mt-4 space-y-3">
          <div className="text-sm font-semibold">{t("mfa.codesTitle")}</div>
          <p className="text-xs leading-relaxed text-muted">{t("mfa.codesBody")}</p>
          <ul className="selectable grid grid-cols-2 gap-1.5 rounded-lg bg-panel-2 p-3 font-mono text-[13px]">
            {step.codes.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => void copyCodes(step.codes)}>
              <Copy className="size-3.5" /> {t("mfa.copyCodes")}
            </Button>
            <Button size="sm" variant="primary" onClick={() => setStep({ kind: "idle" })}>
              {t("mfa.savedCodes")}
            </Button>
          </div>
        </div>
      )}

      {step.kind === "disabling" && (
        <form onSubmit={disable} className="mt-4 space-y-2">
          <Label>{t("mfa.disableConfirm")}</Label>
          <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} placeholder={t("common.masterPassword")} autoFocus />
          <ErrorText>{error}</ErrorText>
          <div className="flex gap-2">
            <Button type="submit" size="sm" variant="danger" loading={busy} disabled={!password}>
              {t("mfa.disable")}
            </Button>
            <Button type="button" size="sm" onClick={() => setStep({ kind: "idle" })}>
              {t("common.cancel")}
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}

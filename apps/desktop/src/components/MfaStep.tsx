import { ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { api, errorMessage } from "../lib/api";
import { toast } from "../lib/toast";
import { Button, ErrorText, Input, Label } from "./ui";

/** The second step of signing in, for accounts with two-step verification:
 * a code from the authenticator app, or a recovery code. */
export function MfaStep({ onDone, onCancel }: { onDone: () => void | Promise<void>; onCancel: () => void }) {
  const { t } = useTranslation();
  const [recovery, setRecovery] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const recovered = await api.mfaFinishSignIn(recovery ? null : code, recovery ? code : null);
      setCode("");
      if (recovered) toast.show(t("mfa.recoveredNotice"));
      await onDone();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const cancel = () => {
    void api.mfaCancelSignIn();
    onCancel();
  };

  return (
    <form onSubmit={submit} className="space-y-4">
      <div className="flex items-center gap-2.5">
        <ShieldCheck className="size-5 text-accent" />
        <h2 className="text-base font-semibold">{t("mfa.title")}</h2>
      </div>
      <p className="text-[13px] leading-relaxed text-muted">{recovery ? t("mfa.recoveryPrompt") : t("mfa.codePrompt")}</p>
      <div>
        <Label htmlFor="mfa-code">{recovery ? t("mfa.recoveryCode") : t("mfa.code")}</Label>
        <Input
          id="mfa-code"
          value={code}
          onChange={(e) => setCode(recovery ? e.target.value.toUpperCase() : e.target.value.replace(/[^0-9 ]/g, ""))}
          inputMode={recovery ? "text" : "numeric"}
          autoComplete="one-time-code"
          placeholder={recovery ? "XXXX-XXXX-XXXX-XXXX" : "123 456"}
          className="h-10 font-mono tracking-wider"
          autoFocus
          key={recovery ? "recovery" : "code"}
        />
      </div>
      <ErrorText>{error}</ErrorText>
      <button
        type="button"
        onClick={() => {
          setRecovery(!recovery);
          setCode("");
          setError(null);
        }}
        className="text-[13px] font-medium text-accent hover:underline"
      >
        {recovery ? t("mfa.useApp") : t("mfa.useRecovery")}
      </button>
      <div className="flex justify-end gap-2">
        <Button type="button" onClick={cancel}>
          {t("common.cancel")}
        </Button>
        <Button type="submit" variant="primary" loading={busy} disabled={recovery ? code.replace(/[^0-9A-Z]/gi, "").length < 16 : code.replace(/\D/g, "").length !== 6}>
          {t("mfa.verify")}
        </Button>
      </div>
    </form>
  );
}

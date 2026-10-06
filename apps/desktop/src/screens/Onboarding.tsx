import { ArrowLeft, ArrowRight, Cloud, KeyRound, MailCheck, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Trans, useTranslation } from "react-i18next";

import { AuthShell, Logo, PasswordInput, StrengthMeter, useStrength } from "../components/common";
import { EmergencyKit } from "../components/EmergencyKit";
import { Button, ErrorText, Input, Label } from "../components/ui";
import { api, errorMessage, type AppStatus } from "../lib/api";
import { useApp } from "../lib/store";
import { toast } from "../lib/toast";

type Step =
  | { kind: "welcome" }
  | { kind: "create" }
  | { kind: "kit"; email: string; secretKey: string; confirmationRequired: boolean }
  | { kind: "signin"; email?: string; notice?: "confirm" };

export function Onboarding({ status }: { status: AppStatus }) {
  const [step, setStep] = useState<Step>(
    status.pendingEmail ? { kind: "signin", email: status.pendingEmail, notice: "confirm" } : { kind: "welcome" },
  );

  switch (step.kind) {
    case "welcome":
      return <Welcome onCreate={() => setStep({ kind: "create" })} onSignIn={() => setStep({ kind: "signin" })} />;
    case "create":
      return (
        <CreateAccount
          onBack={() => setStep({ kind: "welcome" })}
          onCreated={(email, secretKey, confirmationRequired) => setStep({ kind: "kit", email, secretKey, confirmationRequired })}
        />
      );
    case "kit":
      return (
        <KitStep
          email={step.email}
          secretKey={step.secretKey}
          onDone={() => {
            if (step.confirmationRequired) {
              setStep({ kind: "signin", email: step.email, notice: "confirm" });
            } else {
              void useApp.getState().refreshStatus();
            }
          }}
        />
      );
    case "signin":
      return (
        <SignIn
          initialEmail={step.email}
          notice={step.notice}
          knownSecretKey={status.hasSecretKey && !!step.email && step.email === status.pendingEmail}
          onBack={() => setStep({ kind: "welcome" })}
        />
      );
  }
}

function Welcome({ onCreate, onSignIn }: { onCreate: () => void; onSignIn: () => void }) {
  const { t } = useTranslation();
  return (
    <AuthShell>
      <div className="flex flex-col items-center text-center">
        <Logo className="size-20 drop-shadow-lg" />
        <h1 className="mt-6 text-2xl font-semibold tracking-tight">{t("welcome.title")}</h1>
        <p className="mt-2 text-sm leading-relaxed text-muted">{t("welcome.subtitle")}</p>
      </div>
      <div className="mt-8 space-y-2.5">
        <Button variant="primary" size="lg" className="w-full" onClick={onCreate}>
          {t("welcome.create")}
        </Button>
        <Button size="lg" className="w-full" onClick={onSignIn}>
          {t("welcome.signIn")}
        </Button>
      </div>
      <div className="mt-8 grid grid-cols-3 gap-3 text-center text-[11px] text-subtle">
        <div className="flex flex-col items-center gap-1.5">
          <ShieldCheck className="size-4 text-accent" />
          {t("welcome.zeroKnowledge")}
        </div>
        <div className="flex flex-col items-center gap-1.5">
          <KeyRound className="size-4 text-accent" />
          {t("welcome.twoSecrets")}
        </div>
        <div className="flex flex-col items-center gap-1.5">
          <Cloud className="size-4 text-accent" />
          {t("welcome.synced")}
        </div>
      </div>
    </AuthShell>
  );
}

function CreateAccount({
  onBack,
  onCreated,
}: {
  onBack: () => void;
  onCreated: (email: string, secretKey: string, confirmationRequired: boolean) => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const strength = useStrength(password, email);
  const { t } = useTranslation();

  const mismatch = confirm.length > 0 && confirm !== password;
  const tooShort = password.length > 0 && password.trim().length < 10;
  const canSubmit = email && password && confirm && !mismatch && !tooShort && understood && (strength?.score ?? 0) >= 2;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.createAccount(email, password);
      setPassword("");
      setConfirm("");
      onCreated(email.trim().toLowerCase(), result.secretKey, result.confirmationRequired);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell>
      <button onClick={onBack} className="mb-6 flex items-center gap-1.5 text-sm text-muted hover:text-fg">
        <ArrowLeft className="size-4" /> {t("common.back")}
      </button>
      <h1 className="text-xl font-semibold tracking-tight">{t("create.title")}</h1>
      <p className="mt-1.5 text-sm text-muted">{t("create.subtitle")}</p>
      <form onSubmit={submit} className="mt-6 space-y-4">
        <div>
          <Label htmlFor="email">{t("common.email")}</Label>
          <Input id="email" type="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" className="h-10" />
        </div>
        <div>
          <Label htmlFor="password">{t("common.masterPassword")}</Label>
          <PasswordInput id="password" value={password} onChange={(e) => setPassword(e.target.value)} invalid={tooShort} />
          <StrengthMeter strength={strength} />
          {tooShort && <p className="mt-1 text-xs text-danger">{t("create.tooShort")}</p>}
        </div>
        <div>
          <Label htmlFor="confirm">{t("create.confirm")}</Label>
          <PasswordInput id="confirm" value={confirm} onChange={(e) => setConfirm(e.target.value)} invalid={mismatch} />
          {mismatch && <p className="mt-1 text-xs text-danger">{t("create.mismatch")}</p>}
        </div>
        <label className="flex cursor-pointer items-start gap-2.5 rounded-lg border border-line bg-panel-2 p-3 text-[13px] leading-relaxed text-muted">
          <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} className="mt-0.5 size-4 accent-[var(--accent)]" />
          <span>
            <Trans i18nKey="create.understand" components={{ strong: <strong className="text-fg" /> }} />
          </span>
        </label>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" variant="primary" size="lg" className="w-full" disabled={!canSubmit} loading={busy}>
          {t("create.submit")} <ArrowRight className="size-4" />
        </Button>
        {password && (strength?.score ?? 0) < 2 && !tooShort && (
          <p className="text-center text-xs text-subtle">{t("create.stronger")}</p>
        )}
      </form>
    </AuthShell>
  );
}

function KitStep({ email, secretKey, onDone }: { email: string; secretKey: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const { t } = useTranslation();
  return (
    <AuthShell wide>
      <h1 className="text-xl font-semibold tracking-tight">{t("kit.stepTitle")}</h1>
      <p className="mt-1.5 text-sm text-muted">{t("kit.stepSubtitle")}</p>
      <div className="mt-5">
        <EmergencyKit email={email} secretKey={secretKey} />
      </div>
      <label className="mt-5 flex cursor-pointer items-center gap-2.5 text-sm">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} className="size-4 accent-[var(--accent)]" />
        {t("kit.saved")}
      </label>
      <Button variant="primary" size="lg" className="mt-4 w-full" disabled={!saved} onClick={onDone}>
        {t("common.continue")} <ArrowRight className="size-4" />
      </Button>
    </AuthShell>
  );
}

function SignIn({
  initialEmail,
  notice,
  knownSecretKey,
  onBack,
}: {
  initialEmail?: string;
  notice?: "confirm";
  knownSecretKey: boolean;
  onBack: () => void;
}) {
  const [email, setEmail] = useState(initialEmail ?? "");
  const [secretKey, setSecretKey] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [resending, setResending] = useState(false);
  const refreshStatus = useApp((s) => s.refreshStatus);
  const { t } = useTranslation();

  const needsSecretKey = !(knownSecretKey && email.trim().toLowerCase() === (initialEmail ?? "").toLowerCase());

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.signIn(email, needsSecretKey ? secretKey : null, password);
      setPassword("");
      await refreshStatus();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const resend = async () => {
    setResending(true);
    try {
      await api.resendConfirmation(email);
      toast.success(t("signIn.resent"));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setResending(false);
    }
  };

  return (
    <AuthShell>
      <button onClick={onBack} className="mb-6 flex items-center gap-1.5 text-sm text-muted hover:text-fg">
        <ArrowLeft className="size-4" /> {t("common.back")}
      </button>
      <div className="flex items-center gap-3">
        <Logo className="size-10" />
        <h1 className="text-xl font-semibold tracking-tight">{t("signIn.title")}</h1>
      </div>
      {notice === "confirm" && (
        <div className="mt-5 flex gap-3 rounded-xl border border-accent/30 bg-accent-soft p-3.5 text-[13px] leading-relaxed">
          <MailCheck className="mt-0.5 size-5 shrink-0 text-accent" />
          <div>
            <Trans i18nKey="signIn.confirmNotice" values={{ email: initialEmail }} components={{ strong: <strong /> }} />{" "}
            <button type="button" onClick={resend} disabled={resending} className="font-medium text-accent hover:underline disabled:opacity-50">
              {t("signIn.resend")}
            </button>
          </div>
        </div>
      )}
      <form onSubmit={submit} className="mt-6 space-y-4">
        <div>
          <Label htmlFor="email">{t("common.email")}</Label>
          <Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus={!initialEmail} className="h-10" />
        </div>
        {needsSecretKey && (
          <div>
            <Label htmlFor="secret-key">{t("common.secretKey")}</Label>
            <Input
              id="secret-key"
              value={secretKey}
              onChange={(e) => setSecretKey(e.target.value.toUpperCase())}
              placeholder="K1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX"
              className="h-10 font-mono tracking-wide"
            />
            <p className="mt-1 text-xs text-subtle">{t("signIn.secretKeyHint")}</p>
          </div>
        )}
        <div>
          <Label htmlFor="password">{t("common.masterPassword")}</Label>
          <PasswordInput id="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus={!!initialEmail} />
        </div>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" variant="primary" size="lg" className="w-full" loading={busy} disabled={!email || !password || (needsSecretKey && !secretKey)}>
          {t("signIn.submit")}
        </Button>
      </form>
    </AuthShell>
  );
}

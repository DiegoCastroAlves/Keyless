import { ArrowLeft, ArrowRight, Cloud, KeyRound, Loader2, MailCheck, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Trans, useTranslation } from "react-i18next";

import { AuthShell, Logo, PasswordInput, StrengthMeter, useStrength } from "../components/common";
import { MfaStep } from "../components/MfaStep";
import { EmergencyKit } from "../components/EmergencyKit";
import { Button, ErrorText, Input, Label } from "../components/ui";
import { api, errorKey, errorMessage, isCancelled, type AppStatus, type GoogleResult } from "../lib/api";
import { useApp } from "../lib/store";
import { toast } from "../lib/toast";

type Step =
  | { kind: "welcome" }
  | { kind: "create"; googleEmail?: string }
  | { kind: "kit"; email: string; secretKey: string; confirmationRequired: boolean }
  | { kind: "signin"; email?: string; notice?: "confirm" | "google" };

export function Onboarding({ status }: { status: AppStatus }) {
  const [step, setStep] = useState<Step>(
    status.pendingEmail ? { kind: "signin", email: status.pendingEmail, notice: "confirm" } : { kind: "welcome" },
  );

  switch (step.kind) {
    case "welcome":
      return (
        <Welcome
          onCreate={() => setStep({ kind: "create" })}
          onSignIn={() => setStep({ kind: "signin" })}
          onGoogle={(result) =>
            setStep(
              result.kind === "new"
                ? { kind: "create", googleEmail: result.email }
                : { kind: "signin", email: result.email, notice: "google" },
            )
          }
        />
      );
    case "create":
      return (
        <CreateAccount
          googleEmail={step.googleEmail}
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

function GoogleLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 48 48" className={className} aria-hidden="true">
      <path
        fill="#FFC107"
        d="M43.6 20.1H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 8 3l5.7-5.7C34 6.1 29.3 4 24 4 13 4 4 13 4 24s9 20 20 20 20-9 20-20c0-1.3-.1-2.6-.4-3.9z"
      />
      <path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 8 3l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
      <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2A11.9 11.9 0 0 1 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z" />
      <path fill="#1976D2" d="M43.6 20.1H42V20H24v8h11.3a12 12 0 0 1-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.6-.4-3.9z" />
    </svg>
  );
}

function Welcome({
  onCreate,
  onSignIn,
  onGoogle,
}: {
  onCreate: () => void;
  onSignIn: () => void;
  onGoogle: (result: GoogleResult) => void;
}) {
  const { t } = useTranslation();
  const [waiting, setWaiting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const continueWithGoogle = async () => {
    setWaiting(true);
    setError(null);
    try {
      const result = await api.signInWithGoogle({
        doneTitle: t("google.browserDoneTitle"),
        doneBody: t("google.browserDoneBody"),
        errorTitle: t("google.browserErrorTitle"),
      });
      onGoogle(result);
    } catch (err) {
      if (!isCancelled(err)) setError(errorMessage(err));
    } finally {
      setWaiting(false);
    }
  };

  return (
    <AuthShell>
      <div className="flex flex-col items-center text-center">
        <Logo className="size-20 drop-shadow-lg" />
        <h1 className="mt-6 text-2xl font-semibold tracking-tight">{t("welcome.title")}</h1>
        <p className="mt-2 text-sm leading-relaxed text-muted">{t("welcome.subtitle")}</p>
      </div>
      <div className="mt-8 space-y-2.5">
        {waiting ? (
          <div className="rounded-xl border border-line bg-panel-2 p-5 text-center">
            <Loader2 className="mx-auto size-5 animate-spin text-accent" />
            <p className="mt-3 text-sm font-medium">{t("google.waitingTitle")}</p>
            <p className="mt-1 text-[13px] leading-relaxed text-muted">{t("google.waitingBody")}</p>
            <Button size="sm" variant="ghost" className="mt-3" onClick={() => void api.cancelGoogleSignIn()}>
              {t("common.cancel")}
            </Button>
          </div>
        ) : (
          <>
            <Button size="lg" className="w-full" onClick={continueWithGoogle}>
              <GoogleLogo className="size-[18px]" />
              {t("welcome.google")}
            </Button>
            <div className="flex items-center gap-3 py-1 text-[11px] uppercase tracking-wider text-subtle">
              <span className="h-px flex-1 bg-line" />
              {t("welcome.or")}
              <span className="h-px flex-1 bg-line" />
            </div>
            <Button variant="primary" size="lg" className="w-full" onClick={onCreate}>
              {t("welcome.create")}
            </Button>
            <Button size="lg" className="w-full" onClick={onSignIn}>
              {t("welcome.signIn")}
            </Button>
          </>
        )}
        <ErrorText>{error}</ErrorText>
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
  googleEmail,
  onBack,
  onCreated,
}: {
  /** Set when Google already confirmed the email. */
  googleEmail?: string;
  onBack: () => void;
  onCreated: (email: string, secretKey: string, confirmationRequired: boolean) => void;
}) {
  const [email, setEmail] = useState(googleEmail ?? "");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const strength = useStrength(password, email);
  const { t } = useTranslation();

  const mismatch = confirm.length > 0 && confirm !== password;
  const tooShort = password.length > 0 && password.trim().length < 10;
  const canSubmit = email && password && confirm && !mismatch && !tooShort && understood && (strength?.score ?? 0) >= 3;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const result = googleEmail ? await api.createAccountWithGoogle(password) : await api.createAccount(email, password);
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
      <button
        onClick={() => {
          if (googleEmail) void api.cancelGoogleSignIn();
          onBack();
        }}
        className="mb-6 flex items-center gap-1.5 text-sm text-muted hover:text-fg"
      >
        <ArrowLeft className="size-4" /> {t("common.back")}
      </button>
      <h1 className="text-xl font-semibold tracking-tight">{t(googleEmail ? "google.createTitle" : "create.title")}</h1>
      <p className="mt-1.5 text-sm leading-relaxed text-muted">{t(googleEmail ? "google.createSubtitle" : "create.subtitle")}</p>
      <form onSubmit={submit} className="mt-6 space-y-4">
        {googleEmail ? (
          <div className="flex items-center gap-3 rounded-lg border border-line bg-panel-2 px-3 py-2.5">
            <GoogleLogo className="size-5 shrink-0" />
            <div className="min-w-0">
              <p className="text-[11px] text-subtle">{t("google.account")}</p>
              <p className="truncate text-sm font-medium">{googleEmail}</p>
            </div>
          </div>
        ) : (
          <div>
            <Label htmlFor="email">{t("common.email")}</Label>
            <Input id="email" type="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" className="h-10" />
          </div>
        )}
        <div>
          <Label htmlFor="password">{t("common.masterPassword")}</Label>
          <PasswordInput id="password" autoFocus={!!googleEmail} value={password} onChange={(e) => setPassword(e.target.value)} invalid={tooShort} />
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
        {password && (strength?.score ?? 0) < 3 && !tooShort && (
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
  notice?: "confirm" | "google";
  knownSecretKey: boolean;
  onBack: () => void;
}) {
  const [email, setEmail] = useState(initialEmail ?? "");
  const [secretKey, setSecretKey] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [resending, setResending] = useState(false);
  const [mfa, setMfa] = useState(false);
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
      // Two-step verification: the code comes next.
      if (errorKey(err) === "mfa_required") setMfa(true);
      else setError(errorMessage(err));
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

  if (mfa) {
    return (
      <AuthShell>
        <MfaStep
          onDone={async () => {
            setPassword("");
            setMfa(false);
            await refreshStatus();
          }}
          onCancel={() => setMfa(false)}
        />
      </AuthShell>
    );
  }

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
      {notice === "google" && (
        <div className="mt-5 flex gap-3 rounded-xl border border-accent/30 bg-accent-soft p-3.5 text-[13px] leading-relaxed">
          <GoogleLogo className="mt-0.5 size-5 shrink-0" />
          <div>
            <Trans i18nKey="signIn.googleNotice" values={{ email: initialEmail }} components={{ strong: <strong /> }} />
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

import {
  ArrowLeft,
  ArrowRight,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  ClipboardPaste,
  FileText,
  KeyRound,
  LifeBuoy,
  Loader2,
  MailCheck,
  MonitorSmartphone,
  ScanLine,
  ShieldAlert,
} from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Trans, useTranslation } from "react-i18next";

import { AccountAvatar, AuthShell, Logo, PasswordInput, StrengthMeter, UnlockField, useStrength } from "../components/common";
import { EmergencyKit } from "../components/EmergencyKit";
import { RecoveryKit } from "../components/RecoveryKit";
import { Button, ErrorText, Input, Label, cx } from "../components/ui";
import { api, errorCode, errorMessage, isCancelled, type AppStatus, type RecoveryPrepare } from "../lib/api";
import { useApp } from "../lib/store";
import { toast } from "../lib/toast";

type Notice = "confirm" | "recovered";

type Step =
  | { kind: "welcome" }
  | { kind: "create" }
  | { kind: "kit"; email: string; secretKey: string; confirmationRequired: boolean }
  /** "Sign in": the QR code for a phone, and the other ways. */
  | { kind: "qr" }
  | { kind: "email"; email?: string }
  /** The last step: the master password, and the Secret Key unless this
   * device already has it. */
  | { kind: "signin"; email: string; notice?: Notice }
  | { kind: "otherDevice"; email: string }
  | { kind: "recover"; email?: string }
  | { kind: "recoverPassword"; email: string }
  | { kind: "recoverKits"; prepared: RecoveryPrepare };

type ScanSource = "screen" | "clipboard" | "file";

export function Onboarding({ status }: { status: AppStatus }) {
  const [step, setStep] = useState<Step>(() => {
    // Sent here by the lock screen's "Forgot your master password?".
    const recoverEmail = useApp.getState().recoverEmail;
    if (recoverEmail) {
      useApp.setState({ recoverEmail: null });
      return { kind: "recover", email: recoverEmail };
    }
    if (status.setupEmail) return { kind: "signin", email: status.setupEmail };
    return status.pendingEmail ? { kind: "signin", email: status.pendingEmail, notice: "confirm" } : { kind: "welcome" };
  });

  // A setup code arrived (a keyless://setup link was opened): sign in with it.
  useEffect(() => {
    if (status.setupEmail) setStep((current) => (current.kind === "signin" && current.email === status.setupEmail ? current : { kind: "signin", email: status.setupEmail ?? "" }));
  }, [status.setupEmail]);

  switch (step.kind) {
    case "welcome":
      return <Welcome onCreate={() => setStep({ kind: "create" })} onSignIn={() => setStep({ kind: "qr" })} />;
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
    case "qr":
      return (
        <QrSignIn
          onBack={() => setStep({ kind: "welcome" })}
          onManual={() => setStep({ kind: "email" })}
          onReceived={(email) => setStep({ kind: "signin", email })}
        />
      );
    case "email":
      return <SignInEmail initialEmail={step.email} onBack={() => setStep({ kind: "qr" })} onNext={(email) => setStep({ kind: "signin", email })} />;
    case "signin": {
      const email = step.email.toLowerCase();
      // The Secret Key came with a setup code or from another device, or
      // stayed here (an account waiting for its email confirmation).
      const received = !!status.setupEmail && status.setupEmail.toLowerCase() === email;
      const kept = status.hasSecretKey && (status.pendingEmail ?? "").toLowerCase() === email;
      return received || kept ? (
        <SignInPassword
          email={step.email}
          notice={step.notice}
          onOtherAccount={async () => {
            if (received) {
              await api.clearSetupCode();
              await useApp.getState().refreshStatus();
            }
            setStep({ kind: "qr" });
          }}
          onRecover={() => setStep({ kind: "recover", email: step.email })}
        />
      ) : (
        <SignInKey
          email={step.email}
          notice={step.notice}
          onBack={() => setStep({ kind: "email", email: step.email })}
          onReceived={(email) => setStep({ kind: "signin", email })}
          onRecover={() => setStep({ kind: "recover", email: step.email })}
          onOtherDevice={() => setStep({ kind: "otherDevice", email: step.email })}
        />
      );
    }
    case "otherDevice":
      return <OtherDevice email={step.email} onBack={() => setStep({ kind: "signin", email: step.email })} />;
    case "recover":
      return (
        <RecoverStart
          initialEmail={step.email}
          onBack={() => setStep(step.email ? { kind: "signin", email: step.email } : { kind: "qr" })}
          onOpened={(email) => setStep({ kind: "recoverPassword", email })}
        />
      );
    case "recoverPassword":
      return (
        <RecoverPassword
          email={step.email}
          onBack={() => {
            void api.recoveryCancel();
            setStep({ kind: "recover", email: step.email });
          }}
          onPrepared={(prepared) => setStep({ kind: "recoverKits", prepared })}
        />
      );
    case "recoverKits":
      return (
        <RecoverKits
          prepared={step.prepared}
          onSignIn={() => setStep({ kind: "signin", email: step.prepared.email, notice: "recovered" })}
          onRestart={() => setStep({ kind: "recover", email: step.prepared.email })}
        />
      );
  }
}

function BackButton({ onClick }: { onClick: () => void }) {
  const { t } = useTranslation();
  return (
    <button onClick={onClick} className="mb-6 flex items-center gap-1.5 text-sm text-muted hover:text-fg">
      <ArrowLeft className="size-4" /> {t("common.back")}
    </button>
  );
}

function Welcome({ onCreate, onSignIn }: { onCreate: () => void; onSignIn: () => void }) {
  const { t } = useTranslation();
  const revoked = useApp((s) => s.deviceRevoked);
  return (
    <AuthShell>
      <div className="flex flex-col items-center text-center">
        <Logo className="size-20 drop-shadow-lg" />
        <h1 className="mt-6 text-2xl font-semibold tracking-tight">{t("welcome.title")}</h1>
        <p className="mt-2 text-sm leading-relaxed text-muted">{t("welcome.subtitle")}</p>
      </div>
      {revoked && (
        <div className="mt-6 flex gap-3 rounded-xl border border-warning/30 bg-warning-soft p-3.5 text-[13px] leading-relaxed">
          <ShieldAlert className="mt-0.5 size-5 shrink-0 text-warning" />
          <div>{t("devices.revokedHere")}</div>
        </div>
      )}
      <div className="mt-8 space-y-2.5">
        <Button variant="primary" size="lg" className="w-full" onClick={onSignIn}>
          {t("welcome.signIn")}
        </Button>
        <Button size="lg" className="w-full" onClick={onCreate}>
          {t("welcome.create")}
        </Button>
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
  const canSubmit = email && password && confirm && !mismatch && !tooShort && understood && (strength?.score ?? 0) >= 3;

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
      <BackButton onClick={onBack} />
      <h1 className="text-xl font-semibold tracking-tight">{t("create.title")}</h1>
      <p className="mt-1.5 text-sm leading-relaxed text-muted">{t("create.subtitle")}</p>
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

/** A list of other ways, each a row with an icon, a title and a hint. */
function Options({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-2 px-1 text-xs font-medium uppercase tracking-wide text-subtle">{title}</div>
      <div className="divide-y divide-line overflow-hidden rounded-2xl border border-line bg-panel">{children}</div>
    </div>
  );
}

function OptionRow({
  icon,
  title,
  hint,
  onClick,
  open,
  children,
}: {
  icon: ReactNode;
  title: string;
  hint?: string;
  onClick: () => void;
  /** Set for a row that opens below itself. */
  open?: boolean;
  children?: ReactNode;
}) {
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <div>
      <button type="button" onClick={onClick} aria-expanded={open} className="flex w-full items-center gap-3 px-3.5 py-3 text-left transition-colors hover:bg-panel-2">
        <span className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-accent-soft text-accent">{icon}</span>
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-medium">{title}</span>
          {hint && <span className="mt-0.5 block text-xs leading-relaxed text-muted">{hint}</span>}
        </span>
        <Chevron className="size-4 shrink-0 text-subtle" />
      </button>
      {open && children && <div className="px-3.5 pb-3.5 pl-[3.75rem]">{children}</div>}
    </div>
  );
}

/** Reads the Emergency Kit's setup code (or the one "Set up another device"
 * shows): from its PDF or a picture, the screen or the clipboard. */
function KitCodeOption({ open, onToggle, onRead }: { open: boolean; onToggle: () => void; onRead: (source: ScanSource) => void }) {
  const { t } = useTranslation();
  return (
    <OptionRow icon={<ScanLine className="size-[18px]" />} title={t("signIn.kitCode")} hint={t("signIn.kitCodeHint")} onClick={onToggle} open={open}>
      <p className="text-xs leading-relaxed text-subtle">{t("setup.codeHint")}</p>
      <div className="mt-2 flex flex-wrap gap-2">
        <Button type="button" size="sm" onClick={() => onRead("file")}>
          <FileText className="size-4" /> {t("setup.fromFile")}
        </Button>
        <Button type="button" size="sm" onClick={() => onRead("screen")}>
          <ScanLine className="size-4" /> {t("setup.fromScreen")}
        </Button>
        <Button type="button" size="sm" onClick={() => onRead("clipboard")}>
          <ClipboardPaste className="size-4" /> {t("setup.fromClipboard")}
        </Button>
      </div>
    </OptionRow>
  );
}

/** Reads a setup code; returns its email, or null (cancelled, or failed
 * with the error shown through `setError`). */
async function readSetupCode(read: () => Promise<string>, setError: (error: string | null) => void): Promise<string | null> {
  setError(null);
  try {
    const email = await read();
    await useApp.getState().refreshStatus();
    return email;
  } catch (err) {
    if (!isCancelled(err)) setError(errorMessage(err));
    return null;
  }
}

function Notices({ notice, email }: { notice?: Notice; email: string }) {
  const { t } = useTranslation();
  const [resending, setResending] = useState(false);
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
  if (notice === "confirm") {
    return (
      <div className="mt-5 flex gap-3 rounded-xl border border-accent/30 bg-accent-soft p-3.5 text-left text-[13px] leading-relaxed">
        <MailCheck className="mt-0.5 size-5 shrink-0 text-accent" />
        <div>
          <Trans i18nKey="signIn.confirmNotice" values={{ email }} components={{ strong: <strong /> }} />{" "}
          <button type="button" onClick={resend} disabled={resending} className="font-medium text-accent hover:underline disabled:opacity-50">
            {t("signIn.resend")}
          </button>
        </div>
      </div>
    );
  }
  if (notice === "recovered") {
    return (
      <div className="mt-5 flex gap-3 rounded-xl border border-accent/30 bg-accent-soft p-3.5 text-left text-[13px] leading-relaxed">
        <LifeBuoy className="mt-0.5 size-5 shrink-0 text-accent" />
        <div>{t("recovery.recoveredSignIn")}</div>
      </div>
    );
  }
  return null;
}

/** Signing in by hand, first the email. */
function SignInEmail({ initialEmail, onBack, onNext }: { initialEmail?: string; onBack: () => void; onNext: (email: string) => void }) {
  const { t } = useTranslation();
  const [email, setEmail] = useState(initialEmail ?? "");
  const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  return (
    <AuthShell>
      <BackButton onClick={onBack} />
      <h1 className="text-xl font-semibold tracking-tight">{t("signIn.emailTitle")}</h1>
      <p className="mt-1.5 text-sm leading-relaxed text-muted">{t("signIn.emailBody")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) onNext(email.trim().toLowerCase());
        }}
        className="mt-6 space-y-4"
      >
        <div>
          <Label htmlFor="email">{t("common.email")}</Label>
          <Input id="email" type="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" className="h-10" />
        </div>
        <Button type="submit" variant="primary" size="lg" className="w-full" disabled={!valid}>
          {t("common.continue")} <ArrowRight className="size-4" />
        </Button>
      </form>
    </AuthShell>
  );
}

/** The last step when this device has no Secret Key yet: the Secret Key and
 * the master password, or another way to bring the Secret Key. */
function SignInKey({
  email,
  notice,
  onBack,
  onReceived,
  onRecover,
  onOtherDevice,
}: {
  email: string;
  notice?: Notice;
  onBack: () => void;
  onReceived: (email: string) => void;
  onRecover: () => void;
  onOtherDevice: () => void;
}) {
  const { t } = useTranslation();
  const [secretKey, setSecretKey] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<"kit" | "where" | null>(null);
  const refreshStatus = useApp((s) => s.refreshStatus);

  const useSetup = async (read: () => Promise<string>) => {
    const found = await readSetupCode(read, setError);
    if (found) onReceived(found);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.signIn(email, secretKey, password);
      setPassword("");
      await refreshStatus();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell wide="md">
      <BackButton onClick={onBack} />
      <h1 className="text-xl font-semibold tracking-tight">{t("signIn.keyTitle")}</h1>
      <p className="mt-1.5 text-sm leading-relaxed text-muted">{t("signIn.keyBody")}</p>
      <Notices notice={notice} email={email} />
      <div className="mt-5 flex items-center gap-3 rounded-xl border border-line bg-panel px-3 py-2.5">
        <AccountAvatar email={email} className="size-8 rounded-lg text-sm" />
        <span className="selectable min-w-0 flex-1 truncate text-sm font-medium">{email}</span>
        <button type="button" onClick={onBack} className="text-[13px] font-medium text-accent hover:underline">
          {t("signIn.changeEmail")}
        </button>
      </div>
      <form onSubmit={submit} className="mt-4 space-y-4">
        <div>
          <Label htmlFor="secret-key">{t("common.secretKey")}</Label>
          <Input
            id="secret-key"
            autoFocus
            value={secretKey}
            onChange={(e) => {
              const value = e.target.value;
              // A setup link pasted here does the same as reading its code.
              if (value.trim().toLowerCase().startsWith("keyless://setup")) {
                setSecretKey("");
                void useSetup(() => api.useSetupLink(value));
              } else {
                setSecretKey(value.toUpperCase());
              }
            }}
            placeholder="K1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX"
            className="h-10 font-mono tracking-wide"
          />
        </div>
        <div>
          <Label htmlFor="password">{t("common.masterPassword")}</Label>
          <PasswordInput id="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" variant="primary" size="lg" className="w-full" loading={busy} disabled={!password || !secretKey}>
          {t("signIn.submit")}
        </Button>
      </form>
      <div className="mt-6">
        <Options title={t("signIn.otherOptions")}>
          <KitCodeOption open={open === "kit"} onToggle={() => setOpen((v) => (v === "kit" ? null : "kit"))} onRead={(source) => void useSetup(() => api.scanSetupCode(source))} />
          <OptionRow icon={<MonitorSmartphone className="size-[18px]" />} title={t("signIn.askDevice")} hint={t("signIn.askDeviceHint")} onClick={onOtherDevice} />
          <OptionRow icon={<CircleHelp className="size-[18px]" />} title={t("signIn.whereKey")} onClick={() => setOpen((v) => (v === "where" ? null : "where"))} open={open === "where"}>
            <p className="text-[13px] leading-relaxed text-muted">{t("signIn.whereKeyBody")}</p>
          </OptionRow>
        </Options>
      </div>
      <div className="mt-5 text-center">
        <button type="button" onClick={onRecover} className="text-[13px] text-muted hover:text-fg hover:underline">
          {t("recovery.forgot")}
        </button>
      </div>
    </AuthShell>
  );
}

/** The last step when the Secret Key is already here (it came with a QR
 * code, a setup code or another device): only the master password. */
function SignInPassword({ email, notice, onOtherAccount, onRecover }: { email: string; notice?: Notice; onOtherAccount: () => void; onRecover: () => void }) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [shake, setShake] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const refreshStatus = useApp((s) => s.refreshStatus);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.signIn(email, null, password);
      setPassword("");
      await refreshStatus();
    } catch (err) {
      setError(errorMessage(err));
      if (errorCode(err) === "wrong_password") setShake((s) => s + 1);
      requestAnimationFrame(() => {
        inputRef.current?.focus();
        inputRef.current?.select();
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell>
      <div className="flex flex-col items-center text-center">
        <AccountAvatar email={email} />
        <h1 className="mt-5 text-xl font-semibold tracking-tight">{t("signIn.passwordTitle")}</h1>
        <p className="selectable mt-1 text-sm text-muted">{email}</p>
      </div>
      <Notices notice={notice} email={email} />
      <form onSubmit={submit} className="mt-7">
        <UnlockField
          ref={inputRef}
          value={password}
          onChange={setPassword}
          placeholder={t("lock.placeholder")}
          submitLabel={t("signIn.submit")}
          busy={busy}
          invalid={!!error}
          shake={shake}
        />
        <p className={cx("mt-2 min-h-5 text-center text-[13px]", error ? "text-danger" : "text-subtle")}>{error ?? t("signIn.passwordBody")}</p>
      </form>
      <div className="mt-5 flex flex-col items-center gap-2.5">
        <button type="button" onClick={onRecover} className="text-[13px] text-subtle hover:text-fg hover:underline">
          {t("recovery.forgot")}
        </button>
        <button type="button" onClick={onOtherAccount} className="text-[13px] text-subtle hover:text-fg hover:underline">
          {t("signIn.otherAccount")}
        </button>
      </div>
    </AuthShell>
  );
}

function RecoverStart({ initialEmail, onBack, onOpened }: { initialEmail?: string; onBack: () => void; onOpened: (email: string) => void }) {
  const { t } = useTranslation();
  const [email, setEmail] = useState(initialEmail ?? "");
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.recoveryBegin(email, key);
      setKey("");
      onOpened(email.trim().toLowerCase());
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
      <div className="flex items-center gap-3">
        <div className="flex size-10 items-center justify-center rounded-xl bg-accent-soft text-accent">
          <LifeBuoy className="size-5" />
        </div>
        <h1 className="text-xl font-semibold tracking-tight">{t("recovery.recoverTitle")}</h1>
      </div>
      <p className="mt-3 text-sm leading-relaxed text-muted">{t("recovery.recoverBody")}</p>
      <form onSubmit={submit} className="mt-6 space-y-4">
        <div>
          <Label htmlFor="email">{t("common.email")}</Label>
          <Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus={!initialEmail} className="h-10" />
        </div>
        <div>
          <Label htmlFor="recovery-key">{t("recovery.keyLabel")}</Label>
          <textarea
            id="recovery-key"
            value={key}
            onChange={(e) => setKey(e.target.value.toUpperCase())}
            autoFocus={!!initialEmail}
            rows={3}
            spellCheck={false}
            autoComplete="off"
            placeholder="KLRK-XXXX-XXXX-XXXX-…"
            className="w-full resize-none rounded-lg border border-line bg-panel px-3 py-2.5 font-mono text-[13px] tracking-wide outline-none placeholder:text-subtle focus:border-accent focus:ring-4 focus:ring-accent-soft"
          />
        </div>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" variant="primary" size="lg" className="w-full" loading={busy} disabled={!email || !key}>
          {t("common.continue")} <ArrowRight className="size-4" />
        </Button>
      </form>
    </AuthShell>
  );
}

function RecoverPassword({ email, onBack, onPrepared }: { email: string; onBack: () => void; onPrepared: (prepared: RecoveryPrepare) => void }) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const strength = useStrength(password, email);
  const mismatch = confirm.length > 0 && confirm !== password;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const prepared = await api.recoveryPrepare(password);
      setPassword("");
      setConfirm("");
      onPrepared(prepared);
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
      <h1 className="text-xl font-semibold tracking-tight">{t("recovery.newPasswordTitle")}</h1>
      <p className="mt-1.5 text-sm leading-relaxed text-muted">{t("recovery.newPasswordBody", { email })}</p>
      <form onSubmit={submit} className="mt-6 space-y-4">
        <div>
          <Label htmlFor="password">{t("settings.newPassword")}</Label>
          <PasswordInput id="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
          <StrengthMeter strength={strength} />
        </div>
        <div>
          <Label htmlFor="confirm">{t("create.confirm")}</Label>
          <PasswordInput id="confirm" value={confirm} onChange={(e) => setConfirm(e.target.value)} invalid={mismatch} />
          {mismatch && <p className="mt-1 text-xs text-danger">{t("create.mismatch")}</p>}
        </div>
        <ErrorText>{error}</ErrorText>
        <Button
          type="submit"
          variant="primary"
          size="lg"
          className="w-full"
          loading={busy}
          disabled={!password || password !== confirm || (strength?.score ?? 0) < 3}
        >
          {t("common.continue")} <ArrowRight className="size-4" />
        </Button>
      </form>
    </AuthShell>
  );
}

/** The new Secret Key and recovery key, saved before the recovery is sent:
 * should the answer get lost, the user already has what the server expects. */
function RecoverKits({ prepared, onSignIn, onRestart }: { prepared: RecoveryPrepare; onSignIn: () => void; onRestart: () => void }) {
  const { t } = useTranslation();
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<{ message: string; code: string | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const refreshStatus = useApp((s) => s.refreshStatus);

  const finish = async () => {
    setBusy(true);
    setError(null);
    try {
      const signedIn = await api.recoveryFinish();
      if (signedIn) await refreshStatus();
      else onSignIn();
    } catch (err) {
      setError({ message: errorMessage(err), code: errorCode(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell wide>
      <h1 className="text-xl font-semibold tracking-tight">{t("recovery.kitsTitle")}</h1>
      <p className="mt-1.5 text-sm leading-relaxed text-muted">{t("recovery.kitsBody")}</p>
      <div className="mt-5 space-y-5">
        <EmergencyKit email={prepared.email} secretKey={prepared.secretKey} recovering />
        <RecoveryKit email={prepared.email} recoveryKey={prepared.recoveryKey} />
      </div>
      <label className="mt-5 flex cursor-pointer items-center gap-2.5 text-sm">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} className="size-4 accent-[var(--accent)]" />
        {t("recovery.kitsSaved")}
      </label>
      {error && (
        <div className="mt-3 space-y-2">
          <ErrorText>{error.message}</ErrorText>
          {error.code === "recovery_failed" && <p className="text-xs leading-relaxed text-muted">{t("recovery.finishRetryHint")}</p>}
          {error.code === "recovery_expired" && (
            <Button size="sm" onClick={onRestart}>
              {t("recovery.restart")}
            </Button>
          )}
        </div>
      )}
      <Button variant="primary" size="lg" className="mt-4 w-full" disabled={!saved} loading={busy} onClick={finish}>
        {t("recovery.finish")} <ArrowRight className="size-4" />
      </Button>
      <p className="mt-3 text-center text-xs text-subtle">{t("recovery.otherDevices")}</p>
    </AuthShell>
  );
}

/** Asks a signed-in device to let this one in: shows the code to type
 * there, then goes back to the sign-in form with the Secret Key received. */
function OtherDevice({ email, onBack }: { email: string; onBack: () => void }) {
  const { t } = useTranslation();
  const refreshStatus = useApp((s) => s.refreshStatus);
  const [phase, setPhase] = useState<"starting" | "waiting" | "code" | "denied" | "expired" | "error">("starting");
  const [code, setCode] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const done = useRef(false);

  useEffect(() => {
    let live = true;
    let timer: number | undefined;
    done.current = false;
    setPhase("starting");
    setCode(null);
    setError(null);
    const poll = async () => {
      try {
        const progress = await api.pollDeviceSetup();
        if (!live) return;
        if (progress.status === "approved") {
          done.current = true;
          await refreshStatus();
          onBack();
          return;
        }
        if (progress.status === "denied" || progress.status === "expired") {
          done.current = true;
          setPhase(progress.status);
          return;
        }
        if (progress.status === "code" && progress.code) {
          setCode(progress.code);
          setPhase("code");
        } else {
          setPhase("waiting");
        }
      } catch (err) {
        if (!live) return;
        done.current = true;
        setError(errorMessage(err));
        setPhase("error");
        return;
      }
      timer = window.setTimeout(poll, 2000);
    };
    api
      .requestDeviceSetup(email)
      .then(() => live && void poll())
      .catch((err) => {
        if (!live) return;
        done.current = true;
        setError(errorMessage(err));
        setPhase("error");
      });
    return () => {
      live = false;
      window.clearTimeout(timer);
      if (!done.current) void api.cancelDeviceSetup();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [email, attempt]);

  return (
    <AuthShell>
      <button onClick={onBack} className="mb-6 flex items-center gap-1.5 text-sm text-muted hover:text-fg">
        <ArrowLeft className="size-4" /> {t("common.back")}
      </button>
      <div className="flex items-center gap-3">
        <MonitorSmartphone className="size-9 text-accent" />
        <h1 className="text-xl font-semibold tracking-tight">{t("setup.otherDeviceTitle")}</h1>
      </div>
      <p className="mt-3 text-sm leading-relaxed text-muted">
        <Trans i18nKey="setup.otherDeviceBody" values={{ email }} components={{ strong: <strong /> }} />
      </p>
      <div className="mt-6 flex min-h-40 flex-col items-center justify-center rounded-2xl border border-line bg-panel-2 px-6 py-6 text-center">
        {(phase === "starting" || phase === "waiting") && (
          <>
            <Loader2 className="size-6 animate-spin text-accent" />
            <p className="mt-3 text-[13px] leading-relaxed text-muted">{t("setup.waiting")}</p>
          </>
        )}
        {phase === "code" && code && (
          <>
            <div className="text-xs font-medium uppercase tracking-wide text-subtle">{t("setup.codeLabel")}</div>
            <div className="selectable mt-2 font-mono text-4xl font-semibold tracking-[0.25em]">
              {code.slice(0, 3)} {code.slice(3)}
            </div>
            <p className="mt-3 text-[13px] leading-relaxed text-muted">{t("setup.typeCodeThere")}</p>
          </>
        )}
        {(phase === "denied" || phase === "expired" || phase === "error") && (
          <>
            <ShieldAlert className="size-6 text-warning" />
            <p className="mt-3 text-[13px] leading-relaxed text-muted">
              {phase === "denied" ? t("setup.denied") : phase === "expired" ? t("setup.expired") : error}
            </p>
            <Button size="sm" className="mt-4" onClick={() => setAttempt((n) => n + 1)}>
              {t("common.retry")}
            </Button>
          </>
        )}
      </div>
      <p className="mt-4 text-center text-xs leading-relaxed text-subtle">{t("setup.passwordStill")}</p>
    </AuthShell>
  );
}

/** "Sign in": a QR code for a phone where the account is open, which sends
 * back the email and Secret Key (the master password is still typed here),
 * and the other ways. */
function QrSignIn({ onBack, onManual, onReceived }: { onBack: () => void; onManual: () => void; onReceived: (email: string) => void }) {
  const { t } = useTranslation();
  const refreshStatus = useApp((s) => s.refreshStatus);
  const [phase, setPhase] = useState<"starting" | "showing" | "denied" | "expired" | "error">("starting");
  const [svg, setSvg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [kitOpen, setKitOpen] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const done = useRef(false);

  useEffect(() => {
    let live = true;
    let timer: number | undefined;
    let id: string | null = null;
    done.current = false;
    setPhase("starting");
    setSvg(null);
    setError(null);
    const fail = (err: unknown) => {
      if (!live) return;
      done.current = true;
      setError(errorMessage(err));
      setPhase("error");
    };
    const poll = async () => {
      try {
        const progress = await api.pollQrSignIn(id!);
        if (!live) return;
        if (progress.status === "approved" && progress.email) {
          done.current = true;
          await refreshStatus();
          onReceived(progress.email);
          return;
        }
        if (progress.status === "denied" || progress.status === "expired") {
          done.current = true;
          setPhase(progress.status);
          return;
        }
      } catch (err) {
        fail(err);
        return;
      }
      timer = window.setTimeout(poll, 2000);
    };
    api
      .startQrSignIn()
      .then((code) => {
        // Gone meanwhile (the screen was left): the request goes too.
        if (!live) {
          void api.cancelQrSignIn(code.id);
          return;
        }
        id = code.id;
        setSvg(code.svg);
        setPhase("showing");
        timer = window.setTimeout(poll, 2000);
      })
      .catch(fail);
    return () => {
      live = false;
      window.clearTimeout(timer);
      if (!done.current && id) void api.cancelQrSignIn(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attempt]);

  const readKit = async (source: ScanSource) => {
    const found = await readSetupCode(() => api.scanSetupCode(source), setScanError);
    if (found) onReceived(found);
  };

  const steps = [t("setup.qrStep1"), t("setup.qrStep2"), t("setup.qrStep3")];

  return (
    <AuthShell wide="xl">
      <BackButton onClick={onBack} />
      <h1 className="text-xl font-semibold tracking-tight">{t("signIn.title")}</h1>
      <div className="mt-5 rounded-2xl border border-line bg-panel p-5 shadow-sm">
        <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-center">
          <div className="flex size-72 shrink-0 items-center justify-center rounded-2xl bg-white p-1 shadow-sm ring-1 ring-black/5">
            {phase === "starting" && <Loader2 className="size-6 animate-spin text-[#061a18]" />}
            {phase === "showing" && svg && (
              <img src={`data:image/svg+xml;utf8,${encodeURIComponent(svg)}`} alt={t("setup.qrTitle")} className="size-full" draggable={false} />
            )}
            {(phase === "denied" || phase === "expired" || phase === "error") && (
              <div className="flex flex-col items-center px-4 text-center text-[#3f4a48]">
                <ShieldAlert className="size-6 text-warning" />
                <p className="mt-2 text-[13px] leading-relaxed">{phase === "denied" ? t("setup.qrDenied") : phase === "expired" ? t("setup.qrExpired") : error}</p>
                <Button size="sm" variant="primary" className="mt-3" onClick={() => setAttempt((n) => n + 1)}>
                  {phase === "error" ? t("common.retry") : t("setup.qrNew")}
                </Button>
              </div>
            )}
          </div>
          <div className="min-w-0 flex-1">
            <h2 className="text-[15px] font-semibold">{t("setup.qrStepsTitle")}</h2>
            <ol className="mt-3 space-y-2.5">
              {steps.map((text, n) => (
                <li key={n} className="flex gap-2.5 text-[13px] leading-relaxed text-muted">
                  <span className="mt-px flex size-5 shrink-0 items-center justify-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">{n + 1}</span>
                  <span>{text}</span>
                </li>
              ))}
            </ol>
            {phase === "showing" && (
              <p className="mt-4 flex items-center gap-2 text-xs text-subtle">
                <Loader2 className="size-3.5 animate-spin" /> {t("setup.qrWaiting")}
              </p>
            )}
          </div>
        </div>
        <p className="mt-5 border-t border-line pt-3.5 text-xs leading-relaxed text-subtle">{t("setup.qrPasswordStill")}</p>
      </div>
      <div className="mt-6">
        <Options title={t("signIn.otherOptions")}>
          <OptionRow icon={<KeyRound className="size-[18px]" />} title={t("signIn.manual")} hint={t("signIn.manualHint")} onClick={onManual} />
          <KitCodeOption open={kitOpen} onToggle={() => setKitOpen((v) => !v)} onRead={(source) => void readKit(source)} />
        </Options>
        <ErrorText>{scanError}</ErrorText>
      </div>
    </AuthShell>
  );
}

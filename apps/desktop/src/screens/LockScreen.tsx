import { getCurrentWindow } from "@tauri-apps/api/window";
import { ArrowRight, Eye, EyeOff, Fingerprint, LogOut } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { AuthShell, Logo } from "../components/common";
import { Button, Dialog, cx } from "../components/ui";
import { api, errorCode, errorMessage, type AppStatus } from "../lib/api";
import { useApp } from "../lib/store";

export function LockScreen({ status }: { status: AppStatus }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [shake, setShake] = useState(0);
  const [confirmSignOut, setConfirmSignOut] = useState(false);
  const [confirmRecover, setConfirmRecover] = useState(false);
  const [systemBusy, setSystemBusy] = useState(false);
  const [visible, setVisible] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const refreshStatus = useApp((s) => s.refreshStatus);
  const { t } = useTranslation();

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.unlock(password);
      setPassword("");
      await refreshStatus();
    } catch (err) {
      setError(errorMessage(err));
      if (errorCode(err) === "wrong_password") setShake((s) => s + 1);
      // Keep what was typed, selected: fix it or type over it.
      requestAnimationFrame(() => {
        inputRef.current?.focus();
        inputRef.current?.select();
      });
    } finally {
      setBusy(false);
    }
  };

  const prompting = useRef(false);
  const promptEnded = useRef(0);

  const unlockWithSystem = async () => {
    if (prompting.current) return;
    prompting.current = true;
    setSystemBusy(true);
    setError(null);
    try {
      await api.unlockWithSystem();
      await refreshStatus();
    } catch (err) {
      if (errorCode(err) !== "cancelled") setError(errorMessage(err));
      // It may have expired: the button then disappears.
      await refreshStatus();
      requestAnimationFrame(() => inputRef.current?.focus());
    } finally {
      prompting.current = false;
      promptEnded.current = Date.now();
      setSystemBusy(false);
    }
  };

  // With unlock by computer password on, bringing Keyless to the front asks
  // the system right away, like opening it. Not when the lock happens with
  // the window already in front (Ctrl+L, inactivity), and not when focus
  // only comes back from the system dialog itself.
  const systemUnlock = status.systemUnlock;
  useEffect(() => {
    if (!systemUnlock) return;
    const unlisten = getCurrentWindow().onFocusChanged(({ payload: focused }) => {
      if (focused && !prompting.current && Date.now() - promptEnded.current > 1500) void unlockWithSystem();
    });
    return () => void unlisten.then((u) => u());
  }, [systemUnlock]);

  const signOut = async () => {
    await api.signOut();
    setConfirmSignOut(false);
    await refreshStatus();
  };

  // A recovery key works on a signed-out device: sign out, then recover.
  const recover = async () => {
    useApp.setState({ recoverEmail: status.email ?? null });
    await api.signOut();
    setConfirmRecover(false);
    await refreshStatus();
  };

  return (
    <AuthShell>
      <div className="flex flex-col items-center text-center">
        <Logo className="size-20 drop-shadow-lg" />
        <h1 className="mt-6 text-xl font-semibold tracking-tight">{t("lock.title")}</h1>
        <p className="selectable mt-1 text-sm text-muted">{status.email}</p>
      </div>
      <form onSubmit={submit} className="mt-8">
        <div key={shake} className={cx("relative", shake > 0 && "animate-shake")}>
          <input
            ref={inputRef}
            type={visible ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t("lock.placeholder")}
            autoComplete="off"
            spellCheck={false}
            disabled={busy}
            className={cx(
              "h-12 w-full rounded-xl border bg-panel pl-4 pr-24 text-[15px] shadow-sm outline-none transition-colors placeholder:text-subtle focus:ring-4",
              error ? "border-danger focus:ring-danger-soft" : "border-line focus:border-accent focus:ring-accent-soft",
            )}
          />
          <button
            type="button"
            onClick={() => {
              setVisible((v) => !v);
              inputRef.current?.focus();
            }}
            aria-label={visible ? t("common.hide") : t("common.show")}
            title={visible ? t("common.hide") : t("common.show")}
            className="absolute right-12 top-1/2 flex size-9 -translate-y-1/2 items-center justify-center rounded-lg text-muted transition-colors hover:text-fg"
          >
            {visible ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
          </button>
          <button
            type="submit"
            aria-label={t("lock.unlock")}
            disabled={!password || busy}
            className="absolute right-1.5 top-1/2 flex size-9 -translate-y-1/2 items-center justify-center rounded-lg bg-accent text-accent-fg transition-opacity hover:bg-accent-hover disabled:opacity-40"
          >
            {busy ? (
              <svg className="size-4 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.3" strokeWidth="3" />
                <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
              </svg>
            ) : (
              <ArrowRight className="size-4" />
            )}
          </button>
        </div>
        <p className={cx("mt-2 min-h-5 text-center text-[13px]", error ? "text-danger" : "text-subtle")}>
          {error ?? (busy ? t("lock.unlocking") : "")}
        </p>
      </form>
      {status.systemUnlock && (
        <Button size="lg" className="mt-2 w-full" onClick={unlockWithSystem} loading={systemBusy} disabled={busy}>
          <Fingerprint className="size-4" />
          {status.systemUnlockMethod === "windows_hello" ? t("lock.systemUnlockHello") : t("lock.systemUnlock")}
        </Button>
      )}
      <div className="mt-6 flex flex-col items-center gap-2.5">
        <button onClick={() => setConfirmRecover(true)} className="text-[13px] text-subtle hover:text-fg hover:underline">
          {t("recovery.lockForgot")}
        </button>
        <button onClick={() => setConfirmSignOut(true)} className="inline-flex items-center gap-1.5 text-[13px] text-subtle hover:text-fg">
          <LogOut className="size-3.5" /> {t("common.signOutDevice")}
        </button>
      </div>

      <Dialog open={confirmRecover} onOpenChange={setConfirmRecover} title={t("recovery.lockForgotTitle")} description={t("recovery.lockForgotBody")}>
        <div className="flex justify-end gap-2">
          <Button onClick={() => setConfirmRecover(false)}>{t("common.cancel")}</Button>
          <Button variant="primary" onClick={recover}>
            {t("recovery.lockForgotRun")}
          </Button>
        </div>
      </Dialog>

      <Dialog
        open={confirmSignOut}
        onOpenChange={setConfirmSignOut}
        title={t("lock.signOutTitle")}
        description={t("lock.signOutBody")}
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setConfirmSignOut(false)}>{t("common.cancel")}</Button>
          <Button variant="danger" onClick={signOut}>
            {t("common.signOut")}
          </Button>
        </div>
      </Dialog>
    </AuthShell>
  );
}

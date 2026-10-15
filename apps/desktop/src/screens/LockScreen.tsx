import { getCurrentWindow } from "@tauri-apps/api/window";
import { LogOut } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { AuthShell, Logo, UnlockField } from "../components/common";
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
        <UnlockField
          ref={inputRef}
          value={password}
          onChange={setPassword}
          placeholder={t("lock.placeholder")}
          submitLabel={t("lock.unlock")}
          busy={busy}
          invalid={!!error}
          shake={shake}
          system={
            status.systemUnlock
              ? {
                  label: status.systemUnlockMethod === "windows_hello" ? t("lock.systemUnlockHello") : t("lock.systemUnlock"),
                  busy: systemBusy,
                  onClick: () => void unlockWithSystem(),
                }
              : undefined
          }
        />
        <p className={cx("mt-2 min-h-5 text-center text-[13px]", error ? "text-danger" : "text-subtle")}>
          {error ?? (busy ? t("lock.unlocking") : systemBusy ? t("lock.systemWaiting") : "")}
        </p>
      </form>
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

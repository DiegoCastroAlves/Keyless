import { getCurrentWindow } from "@tauri-apps/api/window";
import { ArrowRight, Eye, EyeOff } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Logo } from "../components/common";
import { applyLanguage } from "../i18n";
import { api, errorMessage, events } from "../lib/api";
import { useTheme } from "../lib/theme";

/** The window Keyless shows when the browser extension asks to unlock and
 * the computer password cannot be used. The master password is typed here,
 * never in the browser; closing the window cancels. */
export function UnlockPrompt() {
  const { t } = useTranslation();
  const [theme, setTheme] = useState<string>();
  const [email, setEmail] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useTheme(theme);

  useEffect(() => {
    void Promise.all([api.getSettings(), api.status()])
      .then(([settings, status]) => {
        applyLanguage(settings.language);
        setTheme(settings.theme);
        setEmail(status.email);
        if (status.state === "unlocked") void api.closeUnlockPrompt();
      })
      // Rust shows the window only once this page has rendered.
      .finally(() => void api.unlockPromptReady());
    // Unlocked in the main window meanwhile.
    const unlocked = events.onUnlocked(() => void api.closeUnlockPrompt());
    const focused = getCurrentWindow().onFocusChanged(({ payload }) => payload && inputRef.current?.focus());
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") void api.closeUnlockPrompt();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      void unlocked.then((unlisten) => unlisten());
      void focused.then((unlisten) => unlisten());
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.unlock(password);
      setPassword("");
      await api.closeUnlockPrompt();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
      // Kept so a typo can be fixed.
      requestAnimationFrame(() => inputRef.current?.select());
    }
  };

  return (
    <div className="flex h-screen select-none flex-col items-center justify-center bg-panel px-8 text-fg">
      <Logo className="size-12" />
      <p className="mt-4 text-center text-[15px] font-semibold leading-snug">{t("unlockPrompt.title")}</p>
      {email && <p className="mt-1 truncate text-xs text-muted">{email}</p>}
      <form onSubmit={submit} className="mt-5 w-full">
        <div className="relative">
          <input
            ref={inputRef}
            type={visible ? "text" : "password"}
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t("unlockPrompt.placeholder")}
            disabled={busy}
            spellCheck={false}
            className="h-10 w-full rounded-lg border border-line bg-panel-2 pl-3 pr-[4.5rem] text-sm outline-none focus:border-accent"
          />
          <div className="absolute right-1 top-1/2 flex -translate-y-1/2 items-center">
            <button
              type="button"
              onClick={() => setVisible((v) => !v)}
              aria-label={visible ? t("common.hide") : t("common.show")}
              className="flex size-8 items-center justify-center rounded-md text-muted hover:text-fg"
            >
              {visible ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
            </button>
            <button
              type="submit"
              disabled={!password || busy}
              aria-label={t("lock.unlock")}
              className="flex size-8 items-center justify-center rounded-md text-accent hover:bg-panel-3 disabled:opacity-40"
            >
              <ArrowRight className="size-4" />
            </button>
          </div>
        </div>
      </form>
      <p className="mt-2 min-h-4 text-center text-xs text-danger">{error}</p>
      <button
        type="button"
        onClick={() => void api.closeUnlockPrompt()}
        className="mt-2 h-9 w-full rounded-lg border border-line bg-panel-2 text-sm hover:bg-panel-3"
      >
        {t("common.cancel")}
      </button>
    </div>
  );
}

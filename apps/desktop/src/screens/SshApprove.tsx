import { KeyRound, Terminal } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "../components/ui";
import { applyLanguage } from "../i18n";
import { api, errorMessage, type SshAnswer, type SshRequest } from "../lib/api";
import { useTheme } from "../lib/theme";

/** How long the buttons wait after a request appears: a click meant for
 * something else (the window opens under the pointer, or the next request
 * replaces the one just answered) must not answer it. */
const ARM_MS = 600;

/** The window Keyless shows when a program asks the SSH agent to sign with
 * a key: which program, which key and what for. Closing it denies. */
export function SshApprove() {
  const { t } = useTranslation();
  const [theme, setTheme] = useState<string>();
  const [request, setRequest] = useState<SshRequest | null>(null);
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [armed, setArmed] = useState(false);

  useTheme(theme);

  useEffect(() => {
    setArmed(false);
    const timer = setTimeout(() => setArmed(true), ARM_MS);
    return () => clearTimeout(timer);
  }, [request?.id]);

  const load = useCallback(async () => {
    const next = await api.sshRequest();
    setRequest(next);
    setRemember(false);
    // Nothing left (it gave up waiting): the window goes.
    if (!next) void api.sshClose();
  }, []);

  useEffect(() => {
    void api
      .getSettings()
      .then((settings) => {
        applyLanguage(settings.language);
        setTheme(settings.theme);
      })
      .then(load)
      // Rust shows the window only once this page has rendered.
      .finally(() => void api.sshRequestReady());
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") void api.sshClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [load]);

  const answer = async (value: SshAnswer) => {
    // Denying is always safe; approving waits until the request was seen.
    if (!request || (!armed && value !== "deny")) return;
    try {
      if (await api.sshAnswer(request.id, value)) await load();
    } catch (err) {
      setError(errorMessage(err));
      await load();
    }
  };

  if (!request) return <div className="h-screen bg-panel" />;

  const purpose =
    request.purpose === "login"
      ? t("sshApprove.login", { user: request.user ?? "?" })
      : request.purpose === "git"
        ? t("sshApprove.git")
        : request.purpose === "sign"
          ? t("sshApprove.sign", { namespace: request.namespace ?? "?" })
          : t("sshApprove.unknown");

  return (
    <div className="flex h-screen select-none flex-col bg-panel px-7 py-6 text-fg">
      <div className="flex items-center gap-3">
        <div className="flex size-10 items-center justify-center rounded-xl bg-accent-soft text-accent">
          <Terminal className="size-5" />
        </div>
        <div className="min-w-0">
          <p className="text-[15px] font-semibold leading-snug">{t("sshApprove.title", { program: request.program })}</p>
          {request.parent && <p className="truncate text-xs text-muted">{t("sshApprove.startedBy", { parent: request.parent })}</p>}
        </div>
      </div>
      <p className="mt-4 text-[13px] text-muted">{purpose}</p>
      <div className="mt-3 flex items-center gap-3 rounded-xl border border-line bg-panel-2 px-3 py-2.5">
        <KeyRound className="size-4 shrink-0 text-subtle" />
        <div className="min-w-0">
          <div className="truncate text-sm font-medium">{request.keyTitle}</div>
          <div className="truncate font-mono text-[11px] text-subtle">{request.fingerprint}</div>
        </div>
      </div>
      {request.canRemember && (
        <label className="mt-3 flex items-center gap-2 text-[13px]">
          <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} className="accent-[var(--accent)]" />
          {t(request.purpose === "git" ? "sshApprove.rememberGit" : "sshApprove.rememberLogin", { program: request.program })}
        </label>
      )}
      {error && <p className="mt-2 text-[13px] text-danger">{error}</p>}
      <div className="mt-auto flex justify-end gap-2 pt-4">
        <Button variant="secondary" onClick={() => answer("deny")}>
          {t("sshApprove.deny")}
        </Button>
        {/* Not focused: an Enter typed in the terminal must not approve. */}
        <Button variant="primary" disabled={!armed} onClick={() => answer(remember && request.canRemember ? "remember" : "once")}>
          {t("sshApprove.allow")}
        </Button>
      </div>
    </div>
  );
}

import { LifeBuoy } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { PasswordInput } from "../../components/common";
import { RecoveryKit } from "../../components/RecoveryKit";
import { Button, Dialog, ErrorText, Label } from "../../components/ui";
import { api, errorMessage } from "../../lib/api";
import { formatDate } from "../../lib/format";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";

/** Settings > Account: whether the account has a recovery key, and making,
 * replacing or removing it (always with the master password). */
export function RecoverySection() {
  const { t } = useTranslation();
  const email = useApp((s) => s.status?.email ?? "");
  // undefined while unknown (loading, or it could not be checked).
  const [created, setCreated] = useState<string | null | undefined>(undefined);
  const [unknown, setUnknown] = useState(false);
  const [action, setAction] = useState<"create" | "remove" | null>(null);
  const [shown, setShown] = useState<string | null>(null);

  const load = () =>
    api
      .recoveryKeyStatus()
      .then((value) => {
        setCreated(value);
        setUnknown(false);
      })
      .catch(() => {
        setCreated(undefined);
        setUnknown(true);
      });
  useEffect(() => {
    void load();
  }, []);

  const confirm = async (password: string) => {
    if (action === "remove") {
      await api.recoveryKeyRemove(password);
      toast.success(t("recovery.removed"));
    } else {
      setShown(await api.recoveryKeyCreate(password));
    }
    setAction(null);
    await load();
  };

  return (
    <div>
      <div className="flex items-center gap-2 text-sm font-semibold">
        <LifeBuoy className="size-4 text-accent" /> {t("recovery.title")}
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted">{t("recovery.settingsBody")}</p>
      {unknown && <p className="mt-3 text-[13px] text-muted">{t("recovery.statusUnknown")}</p>}
      {created !== undefined && (
        <p className="mt-3 text-[13px]">{created ? t("recovery.statusCreated", { date: formatDate(Date.parse(created) / 1000) }) : t("recovery.statusNone")}</p>
      )}
      <div className="mt-3 flex flex-wrap gap-2">
        <Button size="sm" variant={created ? undefined : "primary"} onClick={() => setAction("create")} disabled={created === undefined}>
          {created ? t("recovery.replace") : t("recovery.create")}
        </Button>
        {created && (
          <Button size="sm" variant="ghost" onClick={() => setAction("remove")}>
            {t("recovery.remove")}
          </Button>
        )}
      </div>
      <PasswordDialog
        open={action !== null}
        onOpenChange={(open) => !open && setAction(null)}
        title={action === "remove" ? t("recovery.removeTitle") : created ? t("recovery.replace") : t("recovery.create")}
        description={action === "remove" ? t("recovery.removeBody") : created ? t("recovery.replaceBody") : t("recovery.settingsBody")}
        confirmLabel={action === "remove" ? t("recovery.remove") : t("common.continue")}
        danger={action === "remove"}
        onConfirm={confirm}
      />
      <ShowRecoveryKey email={email} recoveryKey={shown} onDone={() => setShown(null)} />
    </div>
  );
}

/** The localStorage key remembering that the offer was answered for an
 * account. It holds a hash of the email, not the email itself. */
async function offeredFlag(email: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(email.trim().toLowerCase()));
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  const flag = `keyless.recoveryOffered.${hex.slice(0, 32)}`;
  // Earlier versions put the email in the key.
  const old = `keyless.recoveryOffered.${email}`;
  try {
    if (localStorage.getItem(old)) {
      localStorage.setItem(flag, "1");
      localStorage.removeItem(old);
    }
  } catch {
    // Nothing to move.
  }
  return flag;
}

/** Offered once per account, when it has no recovery key yet. */
export function RecoveryOffer() {
  const { t } = useTranslation();
  const email = useApp((s) => s.status?.email ?? "");
  const [open, setOpen] = useState(false);
  const [shown, setShown] = useState<string | null>(null);
  const [flag, setFlag] = useState<string | null>(null);

  useEffect(() => {
    if (!email) return;
    let cancelled = false;
    offeredFlag(email)
      .then((key) => {
        if (cancelled) return;
        setFlag(key);
        if (localStorage.getItem(key)) return;
        return api.recoveryKeyStatus().then((created) => !cancelled && setOpen(created === null));
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [email]);

  const dismiss = () => {
    try {
      if (flag) localStorage.setItem(flag, "1");
    } catch {
      // Offered again next time.
    }
    setOpen(false);
  };

  return (
    <>
      <PasswordDialog
        open={open}
        onOpenChange={(o) => !o && dismiss()}
        title={t("recovery.offerTitle")}
        description={t("recovery.offerBody")}
        confirmLabel={t("recovery.create")}
        cancelLabel={t("recovery.offerLater")}
        onConfirm={async (password) => {
          setShown(await api.recoveryKeyCreate(password));
          dismiss();
        }}
      />
      <ShowRecoveryKey email={email} recoveryKey={shown} onDone={() => setShown(null)} />
    </>
  );
}

/** Sentinel's account alert: no recovery key, so forgetting the master
 * password (or losing the Secret Key) would lock the user out. */
export function RecoveryAlert() {
  const { t } = useTranslation();
  const email = useApp((s) => s.status?.email ?? "");
  const [missing, setMissing] = useState(false);
  const [asking, setAsking] = useState(false);
  const [shown, setShown] = useState<string | null>(null);
  useEffect(() => {
    // Offline, it is not shown.
    api
      .recoveryKeyStatus()
      .then((created) => setMissing(created === null))
      .catch(() => undefined);
  }, []);
  if (!missing && !shown) return null;
  return (
    <>
      {missing && (
        <div className="mt-4 flex items-center gap-3 rounded-xl border border-warning/40 bg-warning-soft p-4">
          <LifeBuoy className="size-5 shrink-0 text-warning" />
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-semibold">{t("sentinel.noRecoveryKey")}</div>
            <p className="text-xs leading-relaxed text-muted">{t("sentinel.noRecoveryKeyHint")}</p>
          </div>
          <Button size="sm" onClick={() => setAsking(true)}>
            {t("recovery.create")}
          </Button>
        </div>
      )}
      <PasswordDialog
        open={asking}
        onOpenChange={setAsking}
        title={t("recovery.offerTitle")}
        description={t("recovery.offerBody")}
        confirmLabel={t("recovery.create")}
        cancelLabel={t("common.cancel")}
        onConfirm={async (password) => {
          setShown(await api.recoveryKeyCreate(password));
          setAsking(false);
          setMissing(false);
        }}
      />
      <ShowRecoveryKey email={email} recoveryKey={shown} onDone={() => setShown(null)} />
    </>
  );
}

function PasswordDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  cancelLabel,
  danger = false,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  danger?: boolean;
  onConfirm: (password: string) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setPassword("");
      setError(null);
    }
  }, [open]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onConfirm(password);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={title} description={description}>
      <form onSubmit={submit} className="space-y-3">
        <div>
          <Label>{t("common.masterPassword")}</Label>
          <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
        </div>
        <ErrorText>{error}</ErrorText>
        <div className="flex justify-end gap-2">
          <Button type="button" onClick={() => onOpenChange(false)}>
            {cancelLabel ?? t("common.cancel")}
          </Button>
          <Button type="submit" variant={danger ? "danger" : "primary"} loading={busy} disabled={!password}>
            {confirmLabel}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

/** The recovery key just made, until the user says it is saved. */
function ShowRecoveryKey({ email, recoveryKey, onDone }: { email: string; recoveryKey: string | null; onDone: () => void }) {
  const { t } = useTranslation();
  const [saved, setSaved] = useState(false);
  const done = () => {
    setSaved(false);
    void api.recoveryKeyHide();
    onDone();
  };
  return (
    <Dialog open={recoveryKey !== null} onOpenChange={(o) => !o && saved && done()} title={t("recovery.createdTitle")} width="max-w-lg" hideClose>
      {recoveryKey && <RecoveryKit email={email} recoveryKey={recoveryKey} />}
      <label className="mt-5 flex cursor-pointer items-center gap-2.5 text-sm">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} className="size-4 accent-[var(--accent)]" />
        {t("recovery.saved")}
      </label>
      <div className="mt-4 flex justify-end">
        <Button variant="primary" disabled={!saved} onClick={done}>
          {t("recovery.done")}
        </Button>
      </div>
    </Dialog>
  );
}

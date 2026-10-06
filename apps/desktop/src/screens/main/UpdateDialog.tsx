import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button, Dialog, ErrorText } from "../../components/ui";
import { api, errorMessage, events, isCancelled, type UpdateProgress } from "../../lib/api";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";

/** Opens the in-app update, or the release page when this copy can't update itself. */
export function useUpdateAction(): { open: boolean; setOpen: (open: boolean) => void; start: () => void } {
  const install = useApp((s) => s.install);
  const [open, setOpen] = useState(false);
  const start = () => {
    if (install?.kind === "manual") {
      void api.openUpdatePage().catch((err) => toast.error(errorMessage(err)));
    } else {
      setOpen(true);
    }
  };
  return { open, setOpen, start };
}

export function UpdateDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const update = useApp((s) => s.update);
  const install = useApp((s) => s.install);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<UpdateProgress | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    const unlisten = events.onUpdateProgress(setProgress);
    return () => void unlisten.then((u) => u());
  }, [open]);

  if (!update) return null;

  const start = async () => {
    setBusy(true);
    setError(null);
    setProgress(null);
    try {
      // Keyless restarts once the update is installed.
      await api.installUpdate();
    } catch (err) {
      if (!isCancelled(err)) setError(errorMessage(err));
      setBusy(false);
    }
  };

  const percent = progress?.total ? Math.min(100, Math.round((progress.downloaded / progress.total) * 100)) : null;
  const downloaded = progress?.total != null && progress.downloaded >= progress.total;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !busy && onOpenChange(next)}
      title={t("update.dialogTitle", { version: update.version })}
      hideClose={busy}
    >
      <div className="space-y-4 text-sm leading-relaxed">
        <p className="flex gap-2.5 text-muted">
          <ShieldCheck className="mt-0.5 size-4 shrink-0 text-accent" />
          {t("update.dialogBody")}
        </p>
        {install?.needsPassword && <p className="text-muted">{t("update.passwordNote")}</p>}
        {busy && (
          <div>
            <div className="mb-1.5 text-xs text-muted">
              {downloaded
                ? t("update.installing")
                : percent != null
                  ? t("update.downloading", { percent })
                  : t("update.downloadingUnknown")}
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-panel-3">
              <div
                className="h-full rounded-full bg-accent transition-[width]"
                style={{ width: `${downloaded ? 100 : (percent ?? 5)}%` }}
              />
            </div>
          </div>
        )}
        <ErrorText>{error}</ErrorText>
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)} disabled={busy}>
            {t("update.later")}
          </Button>
          <Button variant="primary" onClick={start} loading={busy}>
            {t("update.updateNow")}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

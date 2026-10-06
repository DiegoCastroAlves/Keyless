import { FileSpreadsheet, FileText, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Button, Combobox, Dialog, cx } from "../../components/ui";
import { api, errorCode, errorMessage, type ImportSummary } from "../../lib/api";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";

export function ImportPanel({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const vaults = useApp((s) => s.vaults);
  const [summary, setSummary] = useState<ImportSummary | null>(null);
  const [busy, setBusy] = useState<"pick" | "commit" | null>(null);
  const [mode, setMode] = useState<"new_vaults" | "vault">("new_vaults");
  const writable = vaults.filter((v) => v.canWrite);
  const [vaultId, setVaultId] = useState<string>(writable[0]?.id ?? "");

  const pick = async (format: "one_pux" | "csv") => {
    setBusy("pick");
    try {
      const result = await api.importPick(format);
      setSummary(result);
      setMode(result.vaults.length > 1 ? "new_vaults" : "vault");
    } catch (err) {
      if (errorCode(err) !== "cancelled") toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const commit = async () => {
    setBusy("commit");
    try {
      const count = await api.importCommit(mode === "new_vaults" ? { mode: "new_vaults" } : { mode: "vault", vaultId });
      toast.success(t("importer.done", { count }));
      setSummary(null);
      await useApp.getState().loadData();
      onDone();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  if (!summary) {
    return (
      <div>
        <div className="text-sm font-semibold">{t("settings.importTitle")}</div>
        <p className="mt-1 text-xs leading-relaxed text-muted">{t("settings.importBody")}</p>
        <div className="mt-5 grid gap-3">
          <SourceCard
            icon={<FileText className="size-5" />}
            title={t("importer.onePassword")}
            hint={t("importer.onePasswordHint")}
            onClick={() => pick("one_pux")}
            busy={busy === "pick"}
          />
          <SourceCard
            icon={<FileSpreadsheet className="size-5" />}
            title={t("importer.csv")}
            hint={t("importer.csvHint")}
            onClick={() => pick("csv")}
            busy={busy === "pick"}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div>
        <div className="text-sm font-semibold">{t("importer.found", { count: summary.total_items })}</div>
        <ul className="mt-2 space-y-1 text-[13px] text-muted">
          {summary.vaults.map(([name, count]) => (
            <li key={name}>{t("importer.vaultLine", { name, count })}</li>
          ))}
        </ul>
      </div>
      {summary.warnings.length > 0 && (
        <div className="rounded-lg bg-warning-soft p-3 text-xs text-warning">
          <div className="mb-1 flex items-center gap-1.5 font-semibold">
            <TriangleAlert className="size-3.5" /> {t("importer.warnings")}
          </div>
          <ul className="list-disc space-y-0.5 pl-5">
            {summary.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <div className="mb-2 text-[13px] font-medium">{t("importer.target")}</div>
        <div className="space-y-2">
          <label className="flex cursor-pointer items-center gap-2.5 text-sm">
            <input type="radio" checked={mode === "new_vaults"} onChange={() => setMode("new_vaults")} className="accent-[var(--accent)]" />
            {t("importer.newVaults")}
          </label>
          <label className="flex cursor-pointer items-center gap-2.5 text-sm">
            <input type="radio" checked={mode === "vault"} onChange={() => setMode("vault")} className="accent-[var(--accent)]" />
            {t("importer.existingVault")}
          </label>
          {mode === "vault" && (
            <div className="pl-6">
              <Combobox
                value={vaultId}
                onChange={setVaultId}
                options={writable.map((v) => ({ value: v.id, label: v.name }))}
                searchPlaceholder={t("common.searchPlaceholder")}
              />
            </div>
          )}
        </div>
      </div>
      <p className="text-xs text-muted">{t("importer.deleteExport")}</p>
      <div className="flex justify-end gap-2">
        <Button
          onClick={() => {
            void api.importCancel();
            setSummary(null);
          }}
        >
          {t("common.cancel")}
        </Button>
        <Button variant="primary" onClick={commit} loading={busy === "commit"} disabled={mode === "vault" && !vaultId}>
          {t("importer.run", { count: summary.total_items })}
        </Button>
      </div>
    </div>
  );
}

function SourceCard({ icon, title, hint, onClick, busy }: { icon: React.ReactNode; title: string; hint: string; onClick: () => void; busy: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="flex items-center gap-4 rounded-xl border border-line p-4">
      <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-accent-soft text-accent">{icon}</div>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{title}</div>
        <div className="mt-0.5 text-xs text-muted">{hint}</div>
      </div>
      <Button size="sm" onClick={onClick} disabled={busy} className={cx(busy && "opacity-60")}>
        {t("importer.choose")}
      </Button>
    </div>
  );
}

export function ImportDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) void api.importCancel();
        onOpenChange(o);
      }}
      title={t("importer.title")}
      width="max-w-lg"
    >
      <ImportPanel onDone={() => onOpenChange(false)} />
    </Dialog>
  );
}

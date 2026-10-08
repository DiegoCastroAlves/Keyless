import { Copy, DatabaseBackup, FileArchive, FileSpreadsheet, FileText, TriangleAlert } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { PasswordInput, StrengthMeter, useStrength } from "../../components/common";
import { Button, Combobox, Dialog, ErrorText, Input, Label, cx } from "../../components/ui";
import { api, errorCode, errorMessage, events, type ExportOutcome, type ImportFormat, type ImportSummary } from "../../lib/api";
import { formatBytes } from "../../lib/format";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { GeneratorButton } from "./Generator";

/** How far the attached files of an import or export are while `active`,
 * in percent; null until the first file starts. */
function useFilesProgress(active: boolean): number | null {
  const [percent, setPercent] = useState<number | null>(null);
  useEffect(() => {
    setPercent(null);
    if (!active) return;
    let stop: (() => void) | undefined;
    let cancelled = false;
    void events
      .onFilesProgress((p) => setPercent(p.total > 0 ? Math.floor((p.done / p.total) * 100) : null))
      .then((unlisten) => {
        if (cancelled) unlisten();
        else stop = unlisten;
      });
    return () => {
      cancelled = true;
      stop?.();
    };
  }, [active]);
  return percent;
}

function FilesProgressLine({ percent }: { percent: number | null }) {
  const { t } = useTranslation();
  if (percent === null) return null;
  return <p className="text-xs text-muted">{t("importer.filesProgress", { percent })}</p>;
}

/** Tells what an export wrote, and which attached files it could not. */
function exportedToast(outcome: ExportOutcome, t: (key: string, options?: Record<string, unknown>) => string) {
  const files = outcome.files > 0 ? ` · ${t("importer.filesIncluded", { count: outcome.files })}` : "";
  toast.success(t("importer.exported", { count: outcome.items }) + files);
  if (outcome.filesMissing > 0) toast.error(t("importer.filesMissing", { count: outcome.filesMissing }));
}

export function ImportPanel({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const vaults = useApp((s) => s.vaults);
  const [summary, setSummary] = useState<ImportSummary | null>(null);
  const [busy, setBusy] = useState<"pick" | "commit" | null>(null);
  const [mode, setMode] = useState<"new_vaults" | "new_vault" | "vault">("new_vaults");
  const [newVaultName, setNewVaultName] = useState("");
  const writable = vaults.filter((v) => v.canWrite);
  const [vaultId, setVaultId] = useState<string>(writable[0]?.id ?? "");
  const [backupPrompt, setBackupPrompt] = useState(false);
  const [backupPassword, setBackupPassword] = useState("");
  const [source, setSource] = useState<ImportFormat>("one_pux");
  const percent = useFilesProgress(busy === "commit");

  const pick = async (format: ImportFormat, password?: string) => {
    setBusy("pick");
    try {
      const result = await api.importPick(format, password);
      setSource(format);
      setBackupPrompt(false);
      setBackupPassword("");
      setSummary(result);
      setMode(result.vaults.length > 1 ? "new_vaults" : "vault");
      setNewVaultName(result.vaults.length === 1 ? result.vaults[0][0] : t("importer.newVaultDefault"));
    } catch (err) {
      if (errorCode(err) !== "cancelled") toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const commit = async () => {
    setBusy("commit");
    try {
      const outcome = await api.importCommit(
        mode === "new_vaults" ? { mode: "new_vaults" } : mode === "new_vault" ? { mode: "new_vault", name: newVaultName } : { mode: "vault", vaultId },
      );
      const files = outcome.files > 0 ? ` · ${t("importer.filesAdded", { count: outcome.files })}` : "";
      toast.success(t("importer.done", { count: outcome.items }) + files);
      if (outcome.filesFailed > 0) toast.error(t("importer.filesFailed", { count: outcome.filesFailed }));
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
          <SourceCard
            icon={<FileArchive className="size-5" />}
            title={t("importer.keylessExport")}
            hint={t("importer.keylessExportHint")}
            onClick={() => pick("keyless_export")}
            busy={busy === "pick"}
          />
          <SourceCard
            icon={<DatabaseBackup className="size-5" />}
            title={t("importer.backup")}
            hint={t("importer.backupHint")}
            onClick={() => setBackupPrompt(true)}
            busy={busy === "pick"}
          />
          {backupPrompt && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void pick("keyless_backup", backupPassword);
              }}
              className="flex items-end gap-2 rounded-xl border border-accent/40 p-3"
            >
              <div className="flex-1">
                <Label>{t("importer.backupPassword")}</Label>
                <PasswordInput value={backupPassword} onChange={(e) => setBackupPassword(e.target.value)} autoFocus />
              </div>
              <Button type="submit" variant="primary" disabled={!backupPassword} loading={busy === "pick"} className="h-10">
                {t("importer.choose")}
              </Button>
            </form>
          )}
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
          {summary.files > 0 && <li>{t("importer.filesLine", { count: summary.files, size: formatBytes(summary.file_bytes) })}</li>}
        </ul>
      </div>
      {summary.warnings.length > 0 && (
        <div className="rounded-lg bg-warning-soft p-3 text-xs text-warning">
          <div className="mb-1 flex items-center gap-1.5 font-semibold">
            <TriangleAlert className="size-3.5" /> {t("importer.warnings")}
          </div>
          <ul className="list-disc space-y-0.5 pl-5">
            {summary.warnings.map((w, i) => (
              <li key={i}>{t(`importer.warn_${w.code}`, { count: w.n })}</li>
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
            <input type="radio" checked={mode === "new_vault"} onChange={() => setMode("new_vault")} className="accent-[var(--accent)]" />
            {t("importer.newVault")}
          </label>
          {mode === "new_vault" && (
            <div className="pl-6">
              <Input value={newVaultName} onChange={(e) => setNewVaultName(e.target.value)} placeholder={t("vault.namePlaceholder")} autoFocus className="h-10" />
            </div>
          )}
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
      {source !== "keyless_backup" && <p className="text-xs text-warning">{t("importer.deleteExport")}</p>}
      <FilesProgressLine percent={percent} />
      <div className="flex justify-end gap-2">
        <Button
          onClick={() => {
            void api.importCancel();
            setSummary(null);
          }}
        >
          {t("common.cancel")}
        </Button>
        <Button
          variant="primary"
          onClick={commit}
          loading={busy === "commit"}
          disabled={(mode === "vault" && !vaultId) || (mode === "new_vault" && !newVaultName.trim())}
        >
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

/** Both exports, from the account menu. */
export function ExportDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("importer.exportDialogTitle")} width="max-w-lg">
      <div className="space-y-8 pb-1">
        <ExportPanel />
        <div className="border-t border-line pt-6">
          <PlainExportPanel />
        </div>
      </div>
    </Dialog>
  );
}

export function ExportPanel() {
  const { t } = useTranslation();
  const [masterPassword, setMasterPassword] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  // The password came from the generator (and is in both fields).
  const [generated, setGenerated] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const strength = useStrength(password);
  const percent = useFilesProgress(busy);
  // A backup has no Secret Key: its password must be the strongest kind.
  const strongEnough = (strength?.score ?? 0) >= 4;

  const copyPassword = async () => {
    try {
      const result = await api.copyText(password);
      toast.copied(t("importer.exportPassword"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const outcome = await api.exportBackup(masterPassword, password);
      setMasterPassword("");
      setPassword("");
      setConfirm("");
      setGenerated(false);
      exportedToast(outcome, t);
    } catch (err) {
      if (errorCode(err) !== "cancelled") setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-3">
      <div>
        <div className="text-sm font-semibold">{t("importer.exportTitle")}</div>
        <p className="mt-1 text-xs leading-relaxed text-muted">{t("importer.exportBody")}</p>
      </div>
      <div>
        <Label>{t("importer.exportMasterPassword")}</Label>
        <PasswordInput value={masterPassword} onChange={(e) => setMasterPassword(e.target.value)} />
      </div>
      <div>
        <Label>{t("importer.exportPassword")}</Label>
        <div className="flex items-center gap-1">
          <div className="min-w-0 flex-1">
            <PasswordInput
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                setGenerated(false);
              }}
            />
          </div>
          <GeneratorButton
            onUse={(value) => {
              setPassword(value);
              setConfirm(value);
              setGenerated(true);
            }}
          />
        </div>
        <StrengthMeter strength={strength} />
        {generated ? (
          <div className="mt-2 flex items-start gap-2 rounded-lg bg-accent-soft px-3 py-2 text-xs leading-relaxed">
            <span className="flex-1">{t("importer.exportPasswordGenerated")}</span>
            <Button type="button" size="sm" onClick={copyPassword}>
              <Copy className="size-3.5" /> {t("common.copy")}
            </Button>
          </div>
        ) : (
          <p className={cx("mt-1 text-xs leading-relaxed", password && !strongEnough ? "text-warning" : "text-subtle")}>{t("importer.exportPasswordHint")}</p>
        )}
      </div>
      <div>
        <Label>{t("importer.exportConfirm")}</Label>
        <PasswordInput value={confirm} onChange={(e) => setConfirm(e.target.value)} invalid={!!confirm && confirm !== password} />
      </div>
      <ErrorText>{error}</ErrorText>
      <FilesProgressLine percent={percent} />
      <Button type="submit" loading={busy} disabled={!masterPassword || !password || password !== confirm || !strongEnough}>
        {t("importer.exportRun")}
      </Button>
    </form>
  );
}

/** An export that is not encrypted, for moving to another password manager.
 * Every secret ends up in plain text in the file: hence the master password,
 * the warning and the explicit confirmation. */
export function PlainExportPanel() {
  const { t } = useTranslation();
  const [format, setFormat] = useState<"csv" | "json" | "zip">("csv");
  const [masterPassword, setMasterPassword] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const percent = useFilesProgress(busy && format === "zip");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const outcome = await api.exportPlain(masterPassword, format);
      setMasterPassword("");
      setUnderstood(false);
      exportedToast(outcome, t);
      toast.show(t("importer.plainDelete"));
    } catch (err) {
      if (errorCode(err) !== "cancelled") setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-3">
      <div className="text-sm font-semibold">{t("importer.plainTitle")}</div>
      <div className="flex gap-3 rounded-xl border border-danger/40 bg-danger-soft p-3">
        <TriangleAlert className="mt-0.5 size-4 shrink-0 text-danger" />
        <p className="text-xs leading-relaxed text-fg">{t("importer.plainWarning")}</p>
      </div>
      <div className="flex gap-2">
        {(["csv", "json", "zip"] as const).map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => setFormat(value)}
            className={cx(
              "flex-1 rounded-lg border px-3 py-2 text-left text-[13px]",
              format === value ? "border-accent bg-accent-soft" : "border-line hover:bg-panel-2",
            )}
          >
            <div className="font-medium">{t(`importer.plain_${value}`)}</div>
            <div className="text-xs text-muted">{t(`importer.plain_${value}Hint`)}</div>
          </button>
        ))}
      </div>
      <div>
        <Label>{t("importer.exportMasterPassword")}</Label>
        <PasswordInput value={masterPassword} onChange={(e) => setMasterPassword(e.target.value)} />
      </div>
      <label className="flex items-start gap-2 text-[13px]">
        <input type="checkbox" className="mt-0.5 accent-[var(--danger)]" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} />
        <span>{t("importer.plainUnderstood")}</span>
      </label>
      <ErrorText>{error}</ErrorText>
      <FilesProgressLine percent={percent} />
      <Button type="submit" variant="danger" loading={busy} disabled={!masterPassword || !understood}>
        {t("importer.plainRun")}
      </Button>
    </form>
  );
}

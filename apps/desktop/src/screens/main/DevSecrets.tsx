// Sentinel for developers: secrets left in files on this computer (.env
// files, credential files, SSH keys without a passphrase), each to save in
// Keyless, show in its folder, move to the trash or ignore; and SSH keys of
// an outdated type or too short, or already saved in Keyless.

import { Bell, BellOff, Check, FileKey2, FolderOpen, Save, Search, SquareArrowOutUpRight, Terminal, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button, Dialog, IconButton, Tooltip } from "../../components/ui";
import { api, errorMessage, type DevFinding, type DevScan } from "../../lib/api";
import { showLinkedItem } from "../../lib/itemLinks";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";

export function DevSecrets() {
  const { t } = useTranslation();
  const [scan, setScan] = useState<DevScan | null>(null);
  const [scanning, setScanning] = useState(false);
  const [showIgnored, setShowIgnored] = useState(false);
  const [saved, setSaved] = useState<Set<string>>(new Set());
  const [trashing, setTrashing] = useState<DevFinding | null>(null);

  const run = async () => {
    setScanning(true);
    try {
      setScan(await api.devScan());
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setScanning(false);
    }
  };

  const kindLabel = (f: DevFinding) => t(`devScan.kinds.${f.kind}`, { service: f.service, bits: f.bits, defaultValue: f.service || f.kind });
  // Key files whose key is already in Keyless: nothing to save there.
  const savedPaths = useMemo(() => new Set((scan?.findings ?? []).filter((f) => f.savedIn).map((f) => f.path)), [scan]);
  const isSaved = (f: DevFinding) => saved.has(f.id) || savedPaths.has(f.path);
  // What else to say under a finding: why an SSH key needs attention.
  const hintOf = (f: DevFinding) =>
    f.savedIn
      ? t("devScan.savedIn", { title: f.savedIn.title })
      : f.kind === "ssh_key_outdated" || f.kind === "ssh_key_short"
        ? t("devScan.weakKeyHint")
        : null;

  const copyCommand = async (f: DevFinding) => {
    if (!f.command) return;
    try {
      const result = await api.copyText(f.command);
      toast.copied(t("devScan.command"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const save = async (f: DevFinding) => {
    const { vaults, settings, loadData } = useApp.getState();
    const writable = vaults.filter((v) => v.canWrite);
    const vault = writable.find((v) => v.id === settings?.default_vault) ?? writable.find((v) => v.role === "owner") ?? writable[0];
    if (!vault) return;
    try {
      const notes = f.line ? t("devScan.foundAtLine", { path: f.path, line: f.line }) : t("devScan.foundAt", { path: f.path });
      await api.devSecretSave(f.id, vault.id, kindLabel(f), notes);
      setSaved((s) => new Set(s).add(f.id));
      await loadData();
      toast.success(t("devScan.saved", { vault: vault.name }));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const ignore = async (f: DevFinding, ignored: boolean) => {
    try {
      await api.devSecretIgnore(f.id, ignored);
      setScan((s) => s && { ...s, findings: s.findings.map((x) => (x.id === f.id ? { ...x, ignored } : x)) });
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const trash = async (f: DevFinding) => {
    try {
      await api.devSecretTrash(f.id);
      setScan((s) => s && { ...s, findings: s.findings.filter((x) => x.path !== f.path) });
      toast.success(t("devScan.trashed"));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setTrashing(null);
    }
  };

  const shown = useMemo(() => (scan?.findings ?? []).filter((f) => showIgnored || !f.ignored), [scan, showIgnored]);
  const ignoredCount = (scan?.findings ?? []).filter((f) => f.ignored).length;
  const byFile = useMemo(() => {
    const groups = new Map<string, DevFinding[]>();
    for (const f of shown) groups.set(f.path, [...(groups.get(f.path) ?? []), f]);
    return [...groups.entries()];
  }, [shown]);
  const active = (scan?.findings ?? []).filter((f) => !f.ignored);

  return (
    <div className="mt-4 rounded-xl border border-line">
      <div className="flex items-center gap-3 p-4">
        <FileKey2 className="size-5 shrink-0 text-accent" />
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold">{t("devScan.title")}</div>
          <p className="text-xs leading-relaxed text-muted">{t("devScan.hint")}</p>
        </div>
        <Button size="sm" onClick={() => void run()} loading={scanning}>
          <Search className="size-3.5" /> {scanning ? t("devScan.scanning") : scan ? t("devScan.again") : t("devScan.scan")}
        </Button>
      </div>
      {scan && (
        <div className="border-t border-line px-4 py-3">
          <p className="text-xs text-muted">
            {active.length
              ? t("devScan.summary", { count: active.length, files: t("devScan.files", { count: scan.files }) })
              : t("devScan.nothing", { files: t("devScan.files", { count: scan.files }), formats: scan.formats })}
            {scan.partial && <span className="text-warning"> {t("devScan.partial")}</span>}
          </p>
          {byFile.map(([path, findings]) => (
            <div key={path} className="mt-3">
              <div className="selectable truncate font-mono text-[11.5px] text-subtle" title={path}>
                {findings[0].shownPath}
              </div>
              <div className="mt-1 divide-y divide-line overflow-hidden rounded-lg border border-line">
                {findings.map((f) => {
                  const hint = hintOf(f);
                  // An SSH key's other findings (outdated, short, saved) have nothing to save.
                  const savable = !f.kind.startsWith("ssh_key_");
                  return (
                    <div key={f.id} className={f.ignored ? "flex items-center gap-3 px-3 py-2 opacity-60" : "flex items-center gap-3 px-3 py-2"}>
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[13px] font-medium">
                          {kindLabel(f)}
                          {f.key && <span className="ml-1.5 font-mono text-xs font-normal text-muted">{f.key}</span>}
                        </div>
                        <div className="truncate font-mono text-xs text-subtle">
                          {f.preview}
                          {f.line > 0 && <span className="ml-2 font-sans">{t("devScan.line", { line: f.line })}</span>}
                        </div>
                        {hint && <div className="text-xs leading-snug text-muted">{hint}</div>}
                      </div>
                      {f.savedIn && (
                        <Tooltip content={t("devScan.openItem")}>
                          <IconButton label={t("devScan.openItem")} onClick={() => showLinkedItem(f.savedIn!.itemId)} className="size-7">
                            <SquareArrowOutUpRight className="size-3.5" />
                          </IconButton>
                        </Tooltip>
                      )}
                      {f.command && (
                        <Tooltip content={t("devScan.copyCommand")}>
                          <IconButton label={t("devScan.copyCommand")} onClick={() => void copyCommand(f)} className="size-7">
                            <Terminal className="size-3.5" />
                          </IconButton>
                        </Tooltip>
                      )}
                      {savable &&
                        (isSaved(f) ? (
                          <span className="flex items-center gap-1 text-xs text-success">
                            <Check className="size-3.5" /> {t("devScan.savedShort")}
                          </span>
                        ) : (
                          <Tooltip content={t("devScan.save")}>
                            <IconButton label={t("devScan.save")} onClick={() => void save(f)} className="size-7">
                              <Save className="size-3.5" />
                            </IconButton>
                          </Tooltip>
                        ))}
                      <Tooltip content={t("devScan.reveal")}>
                        <IconButton
                          label={t("devScan.reveal")}
                          onClick={() => void api.devSecretReveal(f.id).catch((err) => toast.error(errorMessage(err)))}
                          className="size-7"
                        >
                          <FolderOpen className="size-3.5" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip content={t("devScan.trash")}>
                        <IconButton label={t("devScan.trash")} onClick={() => setTrashing(f)} className="size-7">
                          <Trash2 className="size-3.5" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip content={f.ignored ? t("devScan.unignore") : t("devScan.ignore")}>
                        <IconButton label={f.ignored ? t("devScan.unignore") : t("devScan.ignore")} onClick={() => void ignore(f, !f.ignored)} className="size-7">
                          {f.ignored ? <Bell className="size-3.5" /> : <BellOff className="size-3.5" />}
                        </IconButton>
                      </Tooltip>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
          {ignoredCount > 0 && (
            <button onClick={() => setShowIgnored((v) => !v)} className="mt-3 text-xs font-medium text-accent hover:underline">
              {showIgnored ? t("devScan.hideIgnored") : t("devScan.showIgnored", { count: ignoredCount })}
            </button>
          )}
        </div>
      )}
      <Dialog
        open={trashing !== null}
        onOpenChange={(open) => !open && setTrashing(null)}
        title={t("devScan.trashTitle")}
        description={t(trashing && isSaved(trashing) ? "devScan.trashBodySaved" : "devScan.trashBody", { path: trashing?.shownPath ?? "" })}
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setTrashing(null)}>{t("common.cancel")}</Button>
          <Button variant="danger" onClick={() => trashing && void trash(trashing)}>
            {t("devScan.trashAction")}
          </Button>
        </div>
      </Dialog>
    </div>
  );
}

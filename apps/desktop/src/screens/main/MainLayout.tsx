import { TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { PasswordInput } from "../../components/common";
import { Button, Dialog, ErrorText, Input } from "../../components/ui";
import { api, errorCode, errorMessage, type AccountInfo, type Category, type Vault } from "../../lib/api";
import { categoryInfo, templateFields } from "../../lib/categories";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { GeneratorDialog } from "./Generator";
import { ExportDialog, ImportDialog } from "./ImportDialog";
import { ItemDetail } from "./ItemDetail";
import { ItemEditor } from "./ItemEditor";
import { ItemList, TopBar, type ItemListControl } from "./ItemList";
import { ResizeHandle, usePaneWidths } from "./Panes";
import { RecoveryOffer } from "./RecoveryKey";
import { SettingsDialog } from "./SettingsDialog";
import { Sidebar } from "./Sidebar";
import { VaultDialog } from "./VaultDialog";
import { Sentinel } from "./Sentinel";

export function MainLayout() {
  const { t } = useTranslation();
  const view = useApp((s) => s.view);
  const editing = useApp((s) => s.editing);
  const syncStatus = useApp((s) => s.syncStatus);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [vaultDialog, setVaultDialog] = useState<{ open: boolean; vault: Vault | null }>({ open: false, vault: null });
  const [reauthOpen, setReauthOpen] = useState(false);
  const [accountInfo, setAccountInfo] = useState<AccountInfo | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const listControl = useRef<ItemListControl>(null);
  const panes = usePaneWidths();

  useEffect(() => {
    api.accountInfo().then(setAccountInfo).catch(() => setAccountInfo(null));
  }, [syncStatus?.last_synced_at]);

  const newItem = useCallback((category: Category) => {
    const { vaults, view: current, startEditing, select } = useApp.getState();
    const writable = vaults.filter((v) => v.canWrite);
    const preferred = current.kind === "vault" ? writable.find((v) => v.id === current.id) : undefined;
    const vault = preferred ?? writable.find((v) => v.role === "owner") ?? writable[0];
    if (!vault) return;
    if (current.kind === "sentinel" || current.kind === "trash" || current.kind === "archive") {
      useApp.getState().setView({ kind: "all" });
    }
    select(null);
    startEditing({
      isNew: true,
      draft: {
        id: null,
        vaultId: vault.id,
        title: "",
        category,
        urls: categoryInfo(category).hasWebsite ? [{ href: "" }] : [],
        tags: [],
        favorite: false,
        fields: templateFields(category),
        sections: [],
        notes: "",
      },
    });
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
      const key = e.key.toLowerCase();
      if (key === "f") {
        e.preventDefault();
        if (useApp.getState().view.kind === "sentinel") useApp.getState().setView({ kind: "all" });
        requestAnimationFrame(() => searchRef.current?.focus());
      } else if (key === "n" && !useApp.getState().editing) {
        e.preventDefault();
        newItem("login");
      } else if (key === "l") {
        e.preventDefault();
        void api.lock().then(() => useApp.getState().refreshStatus());
      } else if (key === ",") {
        e.preventDefault();
        setSettingsOpen(true);
      } else if (key === "g") {
        e.preventDefault();
        setGeneratorOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [newItem]);

  return (
    <div className="flex h-full flex-col">
      {syncStatus?.state === "signed_out" && <ReauthBanner onClick={() => setReauthOpen(true)} />}
      {accountInfo?.deleteAfter && (
        <DeletionBanner
          deleteAfter={accountInfo.deleteAfter}
          onCancelled={() => setAccountInfo({ ...accountInfo, deleteAfter: null })}
        />
      )}
      <div className="flex min-h-0 flex-1">
        <div className="relative h-full shrink-0" style={{ width: panes.sidebar }}>
          <Sidebar
            onOpenSettings={() => setSettingsOpen(true)}
            onOpenGenerator={() => setGeneratorOpen(true)}
            onOpenImport={() => setImportOpen(true)}
            onOpenExport={() => setExportOpen(true)}
            onEditVault={(vault) => setVaultDialog({ open: true, vault })}
          />
          <ResizeHandle
            value={panes.sidebar}
            min={panes.sidebarMin}
            max={panes.sidebarMax}
            label={t("panes.sidebar")}
            onResize={(sidebar) => panes.set({ sidebar })}
            onReset={() => panes.reset("sidebar")}
          />
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar searchRef={searchRef} onNewItem={newItem} onEnterList={() => listControl.current?.enter()} />
          <div className="flex min-h-0 flex-1">
            {view.kind === "sentinel" && !editing ? (
              <Sentinel />
            ) : (
              <>
                <div className="relative h-full shrink-0" style={{ width: panes.list }}>
                  <ItemList onNewItem={newItem} controlRef={listControl} />
                  <ResizeHandle
                    value={panes.list}
                    min={panes.listMin}
                    max={panes.listMax}
                    label={t("panes.list")}
                    onResize={(list) => panes.set({ list })}
                    onReset={() => panes.reset("list")}
                  />
                </div>
                {editing ? <ItemEditor key={editing.draft.id ?? "new"} /> : <ItemDetail />}
              </>
            )}
          </div>
        </div>
      </div>

      <SettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />
      <GeneratorDialog open={generatorOpen} onOpenChange={setGeneratorOpen} />
      <ImportDialog open={importOpen} onOpenChange={setImportOpen} />
      <ExportDialog open={exportOpen} onOpenChange={setExportOpen} />
      <VaultDialog open={vaultDialog.open} vault={vaultDialog.vault} onOpenChange={(open) => setVaultDialog((d) => ({ ...d, open }))} />
      <ReauthDialog open={reauthOpen} onOpenChange={setReauthOpen} />
      <RecoveryOffer />
    </div>
  );
}

function ReauthBanner({ onClick }: { onClick: () => void }) {
  const { t } = useTranslation();
  return (
    <button onClick={onClick} className="flex items-center justify-center gap-2 bg-warning-soft px-4 py-1.5 text-xs font-medium text-warning hover:underline">
      <TriangleAlert className="size-3.5" /> {t("sync.reauthTitle")}
    </button>
  );
}

function DeletionBanner({ deleteAfter, onCancelled }: { deleteAfter: string; onCancelled: () => void }) {
  const { t, i18n } = useTranslation();
  const date = new Date(deleteAfter).toLocaleDateString(i18n.language, { year: "numeric", month: "long", day: "numeric" });
  const cancel = async () => {
    try {
      await api.cancelAccountDeletion();
      onCancelled();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <div className="flex items-center justify-center gap-3 bg-danger-soft px-4 py-1.5 text-xs font-medium text-danger">
      <TriangleAlert className="size-3.5" /> {t("account.deletionScheduled", { date })}
      <button onClick={cancel} className="underline hover:no-underline">
        {t("account.cancelDeletion")}
      </button>
    </div>
  );
}

function ReauthDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  // The server refused a password this device accepts: the account's
  // credentials changed on another device.
  const [changed, setChanged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.reauthenticate(password, secretKey.trim() || undefined);
      setPassword("");
      setSecretKey("");
      setChanged(false);
      onOpenChange(false);
      useApp.getState().setSyncStatus(await api.syncStatus());
      await useApp.getState().loadData();
    } catch (err) {
      if (errorCode(err) === "credentials_changed") setChanged(true);
      else setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("sync.reauthTitle")} description={t("sync.reauthBody")}>
      <form onSubmit={submit} className="space-y-3">
        {changed && <p className="rounded-lg bg-warning-soft px-3 py-2.5 text-xs leading-relaxed text-warning">{t("sync.credentialsChanged")}</p>}
        <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} placeholder={t("common.masterPassword")} autoFocus />
        {changed && (
          <Input
            value={secretKey}
            onChange={(e) => setSecretKey(e.target.value.toUpperCase())}
            placeholder={t("sync.newSecretKey")}
            spellCheck={false}
            autoComplete="off"
            className="h-10 font-mono tracking-wide"
          />
        )}
        <ErrorText>{error}</ErrorText>
        <div className="flex justify-end gap-2">
          <Button type="button" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary" loading={busy} disabled={!password}>
            {t("signIn.submit")}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

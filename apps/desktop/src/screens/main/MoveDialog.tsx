import { LockKeyhole } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button, Combobox, Dialog, ErrorText, Label } from "../../components/ui";
import { api, errorMessage, type Vault } from "../../lib/api";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";

/** Vaults items can be moved to (writable, other than `except`). */
function useTargets(except: string | undefined) {
  const vaults = useApp((s) => s.vaults);
  return vaults
    .filter((v) => v.canWrite && !v.orphaned && v.id !== except)
    .map((v) => ({ value: v.id, label: v.name, icon: <LockKeyhole className="size-4" /> }));
}

/** Moves items to another vault. */
export function MoveItemsDialog({
  open,
  onOpenChange,
  itemIds,
  fromVaultId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  itemIds: string[];
  fromVaultId?: string;
}) {
  const { t } = useTranslation();
  const vaults = useApp((s) => s.vaults);
  const targets = useTargets(fromVaultId);
  const [target, setTarget] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setTarget(null);
      setError(null);
    }
  }, [open]);

  const move = async () => {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      const count = await api.moveItems(itemIds, target);
      toast.success(t("move.movedItems", { count, vault: vaults.find((v) => v.id === target)?.name ?? "" }));
      await useApp.getState().loadData();
      onOpenChange(false);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("move.itemsTitle", { count: itemIds.length })} description={t("move.itemsBody")}>
      <div className="space-y-4">
        <div>
          <Label>{t("move.to")}</Label>
          <Combobox
            value={target}
            onChange={setTarget}
            options={targets}
            placeholder={t("move.pickVault")}
            searchPlaceholder={t("common.searchPlaceholder")}
          />
          {targets.length === 0 && <p className="mt-1.5 text-xs text-muted">{t("move.noTargets")}</p>}
        </div>
        <ErrorText>{error}</ErrorText>
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button variant="primary" onClick={move} loading={busy} disabled={!target}>
            {t("move.move")}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

/** Moves every item of a vault to another one, optionally deleting it. */
export function MoveVaultDialog({ vault, onOpenChange }: { vault: Vault | null; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const vaults = useApp((s) => s.vaults);
  const targets = useTargets(vault?.id);
  const [target, setTarget] = useState<string | null>(null);
  const [deleteSource, setDeleteSource] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isOwner = vault?.role === "owner";
  const ownedVaults = vaults.filter((v) => v.role === "owner").length;

  useEffect(() => {
    setTarget(null);
    setDeleteSource(false);
    setError(null);
  }, [vault?.id]);

  const move = async () => {
    if (!vault || !target) return;
    setBusy(true);
    setError(null);
    try {
      const count = await api.moveVaultItems(vault.id, target, deleteSource);
      toast.success(t("move.movedItems", { count, vault: vaults.find((v) => v.id === target)?.name ?? "" }));
      const store = useApp.getState();
      if (deleteSource) store.setView({ kind: "vault", id: target });
      await store.loadData();
      onOpenChange(false);
    } catch (err) {
      setError(errorMessage(err));
      await useApp.getState().loadData();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={!!vault}
      onOpenChange={onOpenChange}
      title={t("move.vaultTitle", { name: vault?.name ?? "" })}
      description={t("move.vaultBody", { count: vault?.itemCount ?? 0 })}
    >
      <div className="space-y-4">
        <div>
          <Label>{t("move.to")}</Label>
          <Combobox
            value={target}
            onChange={setTarget}
            options={targets}
            placeholder={t("move.pickVault")}
            searchPlaceholder={t("common.searchPlaceholder")}
          />
        </div>
        {isOwner && ownedVaults > 1 && (
          <label className="flex cursor-pointer items-start gap-2.5 rounded-lg border border-line bg-panel-2 p-3 text-[13px] leading-relaxed">
            <input
              type="checkbox"
              checked={deleteSource}
              onChange={(e) => setDeleteSource(e.target.checked)}
              className="mt-0.5 size-4 accent-[var(--accent)]"
            />
            <span>
              {t("move.deleteSource", { name: vault?.name ?? "" })}
              <span className="block text-xs text-muted">{t("move.deleteSourceHint")}</span>
            </span>
          </label>
        )}
        <ErrorText>{error}</ErrorText>
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button variant="primary" onClick={move} loading={busy} disabled={!target}>
            {t("move.move")}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

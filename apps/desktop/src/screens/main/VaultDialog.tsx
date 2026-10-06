import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { Button, Dialog, Input, Label } from "../../components/ui";
import { api, errorMessage, type Vault } from "../../lib/api";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";

/** Creates a vault (`vault === null`) or renames an existing one. */
export function VaultDialog({ open, vault, onOpenChange }: { open: boolean; vault: Vault | null; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setName(vault?.name ?? "");
      setDescription(vault?.description ?? "");
    }
  }, [open, vault]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const meta = { name: name.trim(), description: description.trim(), icon: vault?.icon ?? "", color: vault?.color ?? "" };
      if (vault) {
        await api.updateVault(vault.id, meta);
        toast.success(t("vault.saved"));
      } else {
        const id = await api.createVault(meta);
        toast.success(t("vault.created"));
        useApp.getState().setView({ kind: "vault", id });
      }
      await useApp.getState().loadData();
      onOpenChange(false);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={vault ? t("vault.editTitle") : t("vault.newTitle")}>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <Label htmlFor="vault-name">{t("vault.name")}</Label>
          <Input id="vault-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder={t("vault.namePlaceholder")} maxLength={100} />
        </div>
        <div>
          <Label htmlFor="vault-description">{t("vault.description")}</Label>
          <Input
            id="vault-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder={t("vault.descriptionPlaceholder")}
            maxLength={500}
          />
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary" loading={busy} disabled={!name.trim()}>
            {vault ? t("common.save") : t("common.create")}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

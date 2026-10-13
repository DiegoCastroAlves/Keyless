import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { Button, Dialog, Input, Label, cx } from "../../components/ui";
import { api, errorMessage, type Vault } from "../../lib/api";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { VAULT_COLORS, VAULT_ICONS } from "../../lib/vaultLook";

/** Creates a vault (`vault === null`) or changes an existing one's name,
 * description, icon and color. */
export function VaultDialog({ open, vault, onOpenChange }: { open: boolean; vault: Vault | null; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [icon, setIcon] = useState("");
  const [color, setColor] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setName(vault?.name ?? "");
      setDescription(vault?.description ?? "");
      setIcon(vault?.icon ?? "");
      setColor(vault?.color ?? "");
    }
  }, [open, vault]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const meta = { name: name.trim(), description: description.trim(), icon, color };
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
        <div>
          <Label>{t("vault.icon")}</Label>
          <div className="grid grid-cols-9 gap-1.5" role="radiogroup" aria-label={t("vault.icon")}>
            {Object.entries(VAULT_ICONS).map(([key, Icon]) => {
              const chosen = (icon || "lock") === key;
              return (
                <button
                  key={key}
                  type="button"
                  role="radio"
                  aria-checked={chosen}
                  aria-label={t(`vault.icons.${key}`)}
                  title={t(`vault.icons.${key}`)}
                  onClick={() => setIcon(key === "lock" ? "" : key)}
                  className={cx(
                    "flex aspect-square items-center justify-center rounded-lg border transition-colors",
                    chosen ? cx("border-accent", VAULT_COLORS[color]?.soft ?? "bg-panel-3") : "border-line hover:bg-panel-2",
                  )}
                >
                  <Icon className={cx("size-[18px]", VAULT_COLORS[color]?.text)} />
                </button>
              );
            })}
          </div>
        </div>
        <div>
          <Label>{t("vault.color")}</Label>
          <div className="flex flex-wrap gap-2" role="radiogroup" aria-label={t("vault.color")}>
            {Object.entries(VAULT_COLORS).map(([key, look]) => {
              const chosen = (color || "default") === key;
              return (
                <button
                  key={key}
                  type="button"
                  role="radio"
                  aria-checked={chosen}
                  aria-label={t(`vault.colors.${key}`)}
                  title={t(`vault.colors.${key}`)}
                  onClick={() => setColor(key === "default" ? "" : key)}
                  className={cx(
                    "size-7 rounded-full ring-offset-2 ring-offset-panel transition-shadow",
                    look.swatch,
                    chosen ? "ring-2 ring-accent" : "hover:ring-2 hover:ring-line",
                  )}
                />
              );
            })}
          </div>
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

import { ChevronDown, ChevronRight, Eye, EyeOff, RotateCcw } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { PasswordText } from "../../components/common";
import { Button, Dialog, IconButton } from "../../components/ui";
import { fieldLabel } from "../../i18n";
import { api, errorMessage, type FieldView, type ItemVersion } from "../../lib/api";
import { isSecretKind } from "../../lib/categories";
import { formatDate, hostOf } from "../../lib/format";
import { toast } from "../../lib/toast";

/** Earlier versions of an item, kept encrypted on the server, which can be
 * looked at and restored. */
export function ItemVersionsDialog({
  itemId,
  canEdit,
  open,
  onOpenChange,
  onRestored,
}: {
  itemId: string;
  canEdit: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onRestored: () => void;
}) {
  const { t } = useTranslation();
  const [versions, setVersions] = useState<ItemVersion[] | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    if (!open) {
      setVersions(null);
      setExpanded(null);
      return;
    }
    api
      .itemVersions(itemId)
      .then(setVersions)
      .catch((err) => {
        toast.error(errorMessage(err));
        onOpenChange(false);
      });
  }, [open, itemId, onOpenChange]);

  const changedText = (changed: string[]) =>
    changed.map((name) => (name.startsWith(":") ? t(`itemHistory.changed.${name.slice(1)}`) : fieldLabel(name))).join(", ");

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("itemHistory.title")} width="max-w-lg">
      <p className="mb-3 text-[13px] text-muted">{t("itemHistory.note")}</p>
      {versions === null && <p className="text-sm text-subtle">{t("itemHistory.loading")}</p>}
      {versions?.length === 0 && <p className="text-sm text-subtle">{t("itemHistory.empty")}</p>}
      {versions && versions.length > 0 && (
        <div className="max-h-[60vh] divide-y divide-line overflow-y-auto rounded-xl border border-line">
          {versions.map((version) => (
            <div key={version.revision}>
              <button
                className="flex w-full items-start gap-2 px-3 py-2.5 text-left hover:bg-panel-2"
                onClick={() => setExpanded(expanded === version.revision ? null : version.revision)}
              >
                {expanded === version.revision ? (
                  <ChevronDown className="mt-0.5 size-4 shrink-0 text-subtle" />
                ) : (
                  <ChevronRight className="mt-0.5 size-4 shrink-0 text-subtle" />
                )}
                <span className="min-w-0 flex-1">
                  <span className="block text-sm">{formatDate(version.updatedAt)}</span>
                  {version.changed.length > 0 && (
                    <span className="block truncate text-xs text-subtle">{t("itemHistory.laterChanged", { list: changedText(version.changed) })}</span>
                  )}
                </span>
              </button>
              {expanded === version.revision && (
                <VersionContent
                  itemId={itemId}
                  version={version}
                  canEdit={canEdit}
                  onRestored={() => {
                    onOpenChange(false);
                    onRestored();
                  }}
                />
              )}
            </div>
          ))}
        </div>
      )}
    </Dialog>
  );
}

function VersionContent({ itemId, version, canEdit, onRestored }: { itemId: string; version: ItemVersion; canEdit: boolean; onRestored: () => void }) {
  const { t } = useTranslation();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const fields = [...version.fields, ...version.sections.flatMap((s) => s.fields)].filter((f) => f.hasValue);

  const restore = async () => {
    setBusy(true);
    try {
      await api.restoreItemVersion(itemId, version.revision);
      toast.success(t("itemHistory.restored"));
      onRestored();
    } catch (err) {
      toast.error(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <div className="space-y-2 bg-panel-2 px-4 pb-3 pt-1">
      <div className="text-sm font-medium">{version.title}</div>
      {fields.map((field) => (
        <VersionField key={field.id} itemId={itemId} revision={version.revision} field={field} />
      ))}
      {version.urlEntries.map((u, i) => (
        <div key={i} className="text-[13px]">
          <span className="text-subtle">{t("item.website")}: </span>
          {hostOf(u.href)}
        </div>
      ))}
      {version.notes && <p className="whitespace-pre-wrap break-words text-[13px] text-muted">{version.notes}</p>}
      {canEdit &&
        (confirming ? (
          <div className="flex items-center justify-end gap-2 pt-1">
            <span className="mr-auto text-[13px]">{t("itemHistory.restoreConfirm")}</span>
            <Button variant="ghost" size="sm" onClick={() => setConfirming(false)} disabled={busy}>
              {t("common.cancel")}
            </Button>
            <Button variant="primary" size="sm" onClick={restore} disabled={busy}>
              {t("itemHistory.restore")}
            </Button>
          </div>
        ) : (
          <Button variant="secondary" size="sm" onClick={() => setConfirming(true)}>
            <RotateCcw className="size-4" /> {t("itemHistory.restore")}
          </Button>
        ))}
    </div>
  );
}

function VersionField({ itemId, revision, field }: { itemId: string; revision: number; field: FieldView }) {
  const { t } = useTranslation();
  const [revealed, setRevealed] = useState<string | null>(null);
  const secret = field.value === null || field.value === undefined || isSecretKind(field);

  const toggle = async () => {
    if (revealed !== null) return setRevealed(null);
    try {
      setRevealed(await api.revealVersionField(itemId, revision, field.id));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <div className="flex items-center gap-2 text-[13px]">
      <span className="shrink-0 text-subtle">{fieldLabel(field.label)}:</span>
      <span className="min-w-0 flex-1 truncate">
        {!secret ? field.value : revealed !== null ? <PasswordText value={revealed} /> : <span className="tracking-[0.2em] text-muted">••••••••</span>}
      </span>
      {secret && (
        <IconButton label={revealed !== null ? t("item.conceal") : t("item.reveal")} onClick={toggle}>
          {revealed !== null ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
        </IconButton>
      )}
    </div>
  );
}

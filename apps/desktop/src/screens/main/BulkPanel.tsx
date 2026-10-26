import { Archive, ArchiveRestore, ArrowRightLeft, RotateCcw, Star, StarOff, Tag, Trash, X } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ItemIcon } from "../../components/common";
import { Button, Dialog, Input } from "../../components/ui";
import { api, errorMessage } from "../../lib/api";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { MoveItemsDialog } from "./MoveDialog";

/** What can be done to several items at once (shown instead of an item). */
export function BulkPanel() {
  const { t } = useTranslation();
  const selection = useApp((s) => s.selection);
  const items = useApp((s) => s.items);
  const vaults = useApp((s) => s.vaults);
  const view = useApp((s) => s.view);
  const [moveOpen, setMoveOpen] = useState(false);
  const [tagOpen, setTagOpen] = useState(false);
  const [tag, setTag] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [busy, setBusy] = useState(false);
  const chosen = items.filter((i) => selection.includes(i.id));
  const writable = chosen.filter((i) => vaults.find((v) => v.id === i.vaultId)?.canWrite);
  const trash = view.kind === "trash";

  const run = async (each: (id: string) => Promise<unknown>, done: string, ids = writable.map((i) => i.id)) => {
    setBusy(true);
    try {
      for (const id of ids) await each(id);
      toast.success(done);
      useApp.getState().setSelection([]);
      await useApp.getState().loadData();
    } catch (err) {
      toast.error(errorMessage(err));
      await useApp.getState().loadData();
    } finally {
      setBusy(false);
    }
  };
  const addTag = async () => {
    const name = tag.trim();
    if (!name) return;
    setTagOpen(false);
    setTag("");
    await run(async (id) => {
      const draft = await api.getItemDraft(id);
      if (!draft.tags.some((x) => x.toLowerCase() === name.toLowerCase())) await api.saveItem({ ...draft, tags: [...draft.tags, name] });
    }, t("bulk.tagged", { count: writable.length, tag: name }));
  };
  const allFavorite = writable.length > 0 && writable.every((i) => i.favorite);
  const allArchived = writable.length > 0 && writable.every((i) => i.archived);

  return (
    <section className="flex min-w-0 flex-1 flex-col items-center justify-center gap-6 bg-panel p-10">
      <div className="flex -space-x-3">
        {chosen.slice(0, 5).map((item) => (
          <div key={item.id} className="rounded-2xl ring-4 ring-panel">
            <ItemIcon title={item.title} category={item.category} url={item.iconUrl ?? undefined} size="lg" item={item} />
          </div>
        ))}
      </div>
      <div className="text-center">
        <h2 className="text-lg font-semibold">{t("bulk.selected", { count: chosen.length })}</h2>
        {writable.length < chosen.length && <p className="mt-1 text-xs text-muted">{t("bulk.readOnly", { count: chosen.length - writable.length })}</p>}
      </div>
      <div className="grid w-full max-w-sm gap-2">
        {trash ? (
          <>
            <Button disabled={busy} onClick={() => void run((id) => api.restoreItem(id), t("bulk.restored", { count: writable.length }))}>
              <RotateCcw className="size-4" /> {t("common.restore")}
            </Button>
            <Button variant="danger" disabled={busy} onClick={() => setConfirmDelete(true)}>
              <Trash className="size-4" /> {t("item.deletePermanently")}
            </Button>
          </>
        ) : (
          <>
            <Button disabled={busy || writable.length === 0} onClick={() => void run((id) => api.setFavorite(id, !allFavorite), t(allFavorite ? "bulk.unfavorited" : "bulk.favorited", { count: writable.length }))}>
              {allFavorite ? <StarOff className="size-4" /> : <Star className="size-4" />} {allFavorite ? t("item.unfavorite") : t("item.favorite")}
            </Button>
            <Button disabled={busy || writable.length === 0} onClick={() => setTagOpen(true)}>
              <Tag className="size-4" /> {t("bulk.addTag")}
            </Button>
            <Button disabled={busy || writable.length === 0} onClick={() => setMoveOpen(true)}>
              <ArrowRightLeft className="size-4" /> {t("move.toVaultAction")}
            </Button>
            <Button disabled={busy || writable.length === 0} onClick={() => void run((id) => api.setArchived(id, !allArchived), t(allArchived ? "bulk.unarchived" : "bulk.archived", { count: writable.length }))}>
              {allArchived ? <ArchiveRestore className="size-4" /> : <Archive className="size-4" />} {allArchived ? t("item.unarchive") : t("item.archive")}
            </Button>
            <Button variant="danger" disabled={busy || writable.length === 0} onClick={() => void run((id) => api.trashItem(id), t("bulk.trashed", { count: writable.length }))}>
              <Trash className="size-4" /> {t("item.moveToTrash")}
            </Button>
          </>
        )}
        <Button variant="ghost" onClick={() => useApp.getState().setSelection([])}>
          <X className="size-4" /> {t("bulk.clear")}
        </Button>
      </div>

      <MoveItemsDialog
        open={moveOpen}
        onOpenChange={(open) => {
          setMoveOpen(open);
          if (!open) useApp.getState().setSelection([]);
        }}
        itemIds={writable.map((i) => i.id)}
      />
      <Dialog open={tagOpen} onOpenChange={setTagOpen} title={t("bulk.addTagTitle", { count: writable.length })}>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void addTag();
          }}
        >
          <Input value={tag} onChange={(e) => setTag(e.target.value)} placeholder={t("editor.tagsPlaceholder")} autoFocus />
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={() => setTagOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant="primary" disabled={!tag.trim()}>
              {t("bulk.addTag")}
            </Button>
          </div>
        </form>
      </Dialog>
      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete} title={t("list.emptyTrashTitle", { count: writable.length })} description={t("list.emptyTrashBody")}>
        <div className="flex justify-end gap-2">
          <Button onClick={() => setConfirmDelete(false)}>{t("common.cancel")}</Button>
          <Button
            variant="danger"
            onClick={() => {
              setConfirmDelete(false);
              void run(() => api.deleteItemsPermanently(writable.map((i) => i.id)), t("bulk.deleted", { count: writable.length }), ["all"]);
            }}
          >
            {t("item.deletePermanently")}
          </Button>
        </div>
      </Dialog>
    </section>
  );
}

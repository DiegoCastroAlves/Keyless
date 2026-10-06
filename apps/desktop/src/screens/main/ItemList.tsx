import { Command } from "cmdk";
import { Archive, Copy, KeyRound, Pencil, Plus, RotateCcw, Search, Star, Trash, User } from "lucide-react";
import { ContextMenu, Popover } from "radix-ui";
import { forwardRef, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { ItemIcon } from "../../components/common";
import { Button, Dialog, Kbd, cx } from "../../components/ui";
import { api, errorMessage, type Category, type ItemSummary } from "../../lib/api";
import { CATEGORIES, categoryLabel } from "../../lib/categories";
import { filterItems, useApp, viewTitle } from "../../lib/store";
import { toast } from "../../lib/toast";

export interface ItemListHandle {
  focusSearch: () => void;
}

export function ItemList({ onNewItem, searchRef }: { onNewItem: (category: Category) => void; searchRef: React.RefObject<HTMLInputElement | null> }) {
  const { t } = useTranslation();
  const items = useApp((s) => s.items);
  const vaults = useApp((s) => s.vaults);
  const view = useApp((s) => s.view);
  const search = useApp((s) => s.search);
  const setSearch = useApp((s) => s.setSearch);
  const selectedId = useApp((s) => s.selectedId);
  const select = useApp((s) => s.select);
  const editing = useApp((s) => s.editing);
  const [emptyTrashOpen, setEmptyTrashOpen] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const visible = useMemo(() => filterItems(items, view, search), [items, view, search]);
  const title = viewTitle(view, vaults);
  const canCreate = view.kind !== "trash" && view.kind !== "archive";

  // Keep a valid selection: select the first item when nothing is selected.
  useEffect(() => {
    if (editing?.isNew) return;
    if (!selectedId || !visible.some((i) => i.id === selectedId)) {
      select(visible[0]?.id ?? null);
    }
  }, [visible, selectedId, select, editing]);

  const move = (delta: number) => {
    if (!visible.length) return;
    const index = visible.findIndex((i) => i.id === selectedId);
    const next = visible[Math.min(visible.length - 1, Math.max(0, index + delta))];
    select(next.id);
    listRef.current?.querySelector(`[data-id="${next.id}"]`)?.scrollIntoView({ block: "nearest" });
  };

  const emptyTrash = async () => {
    try {
      await api.deleteItemsPermanently(visible.map((i) => i.id));
      await useApp.getState().loadData();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setEmptyTrashOpen(false);
    }
  };

  return (
    <section className="flex h-full w-[340px] shrink-0 flex-col border-r border-line bg-panel">
      <div className="flex items-center gap-2 border-b border-line p-3">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-subtle" />
          <input
            ref={searchRef}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                listRef.current?.focus();
                move(1);
              } else if (e.key === "Escape") {
                setSearch("");
              }
            }}
            placeholder={t("list.searchIn", { view: title })}
            spellCheck={false}
            className="h-9 w-full rounded-lg border border-transparent bg-panel-3 pl-8 pr-14 text-sm outline-none placeholder:text-subtle focus:border-accent focus:bg-panel focus:ring-3 focus:ring-accent-soft"
          />
          <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2">
            <Kbd>Ctrl F</Kbd>
          </span>
        </div>
        {canCreate && <NewItemButton onPick={onNewItem} />}
      </div>

      <div className="flex h-10 items-center justify-between px-4">
        <span className="truncate text-[13px] font-semibold">{title}</span>
        <span className="text-xs text-subtle">{t("list.count", { count: visible.length })}</span>
      </div>

      {view.kind === "trash" && visible.length > 0 && (
        <div className="mx-3 mb-2 flex items-center justify-between gap-2 rounded-lg bg-panel-2 px-3 py-2 text-xs text-muted">
          <span>{t("list.trashHint")}</span>
          <button onClick={() => setEmptyTrashOpen(true)} className="shrink-0 font-medium text-danger hover:underline">
            {t("list.emptyTrash")}
          </button>
        </div>
      )}

      <div
        ref={listRef}
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            move(1);
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            move(-1);
          }
        }}
        className="flex-1 overflow-y-auto px-2 pb-3 outline-none"
      >
        {visible.length === 0 ? (
          <EmptyList query={search} canCreate={canCreate} onNewItem={() => onNewItem("login")} />
        ) : (
          visible.map((item) => <ItemRow key={item.id} item={item} selected={item.id === selectedId} onSelect={() => select(item.id)} />)
        )}
      </div>

      <Dialog
        open={emptyTrashOpen}
        onOpenChange={setEmptyTrashOpen}
        title={t("list.emptyTrashTitle", { count: visible.length })}
        description={t("list.emptyTrashBody")}
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setEmptyTrashOpen(false)}>{t("common.cancel")}</Button>
          <Button variant="danger" onClick={emptyTrash}>
            {t("item.deletePermanently")}
          </Button>
        </div>
      </Dialog>
    </section>
  );
}

function EmptyList({ query, canCreate, onNewItem }: { query: string; canCreate: boolean; onNewItem: () => void }) {
  const { t } = useTranslation();
  if (query.trim()) {
    return <p className="px-4 py-10 text-center text-sm text-subtle">{t("list.emptySearch", { query })}</p>;
  }
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <div className="flex size-12 items-center justify-center rounded-2xl bg-accent-soft text-accent">
        <KeyRound className="size-6" />
      </div>
      <p className="mt-4 text-sm font-medium">{t("list.emptyTitle")}</p>
      {canCreate && (
        <>
          <p className="mt-1 text-xs text-muted">{t("list.emptyBody")}</p>
          <Button variant="primary" size="sm" className="mt-4" onClick={onNewItem}>
            <Plus className="size-4" /> {t("list.newItem")}
          </Button>
        </>
      )}
    </div>
  );
}

const ItemRowButton = forwardRef<HTMLButtonElement, { item: ItemSummary; selected: boolean; onSelect: () => void }>(function ItemRowButton(
  { item, selected, onSelect, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      data-id={item.id}
      onClick={onSelect}
      onContextMenu={onSelect}
      className={cx(
        "group mb-0.5 flex w-full items-center gap-3 rounded-xl px-2.5 py-2 text-left transition-colors",
        selected ? "bg-accent-soft" : "hover:bg-panel-2",
      )}
      {...props}
    >
      <ItemIcon title={item.title} category={item.category} url={item.urls[0]} />
      <div className="min-w-0 flex-1">
        <div className={cx("truncate text-[13.5px] font-medium", selected && "text-fg")}>{item.title}</div>
        <div className="truncate text-xs text-muted">{item.subtitle || " "}</div>
      </div>
      {item.favorite && <Star className="size-3.5 shrink-0 fill-amber-400 text-amber-400" />}
    </button>
  );
});

function ItemRow({ item, selected, onSelect }: { item: ItemSummary; selected: boolean; onSelect: () => void }) {
  const { t } = useTranslation();
  const loadData = useApp((s) => s.loadData);
  const startEditing = useApp((s) => s.startEditing);
  const trashed = item.trashedAt !== null;

  const run = (fn: () => Promise<unknown>, success?: string) => async () => {
    try {
      await fn();
      if (success) toast.success(success);
      await loadData();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const copy = (purpose: "username" | "password" | "totp", what: string) => async () => {
    try {
      const result = await api.copyItemValue(item.id, purpose);
      toast.copied(what, result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <ContextMenu.Root>
      <ContextMenu.Trigger asChild>
        <ItemRowButton item={item} selected={selected} onSelect={onSelect} />
      </ContextMenu.Trigger>
      <ContextMenu.Portal>
        <ContextMenu.Content className="z-50 min-w-52 rounded-xl border border-line bg-panel p-1 shadow-xl animate-pop">
          {trashed ? (
            <CtxItem icon={<RotateCcw className="size-4" />} onSelect={run(() => api.restoreItem(item.id), t("item.restored"))}>
              {t("common.restore")}
            </CtxItem>
          ) : (
            <>
              <CtxItem icon={<User className="size-4" />} onSelect={copy("username", t("item.username"))}>
                {t("item.copyUsername")}
              </CtxItem>
              <CtxItem icon={<Copy className="size-4" />} onSelect={copy("password", t("item.password"))}>
                {t("item.copyPassword")}
              </CtxItem>
              <CtxItem icon={<KeyRound className="size-4" />} onSelect={copy("totp", t("item.code"))}>
                {t("item.copyCode")}
              </CtxItem>
              <ContextMenu.Separator className="my-1 h-px bg-line" />
              <CtxItem icon={<Star className="size-4" />} onSelect={run(() => api.setFavorite(item.id, !item.favorite))}>
                {item.favorite ? t("item.unfavorite") : t("item.favorite")}
              </CtxItem>
              <CtxItem
                icon={<Pencil className="size-4" />}
                onSelect={async () => {
                  onSelect();
                  try {
                    const draft = await api.getItemDraft(item.id);
                    startEditing({ draft, isNew: false });
                  } catch (err) {
                    toast.error(errorMessage(err));
                  }
                }}
              >
                {t("common.edit")}
              </CtxItem>
              <CtxItem icon={<Archive className="size-4" />} onSelect={run(() => api.setArchived(item.id, !item.archived), item.archived ? undefined : t("item.archived"))}>
                {item.archived ? t("item.unarchive") : t("item.archive")}
              </CtxItem>
              <ContextMenu.Separator className="my-1 h-px bg-line" />
              <CtxItem icon={<Trash className="size-4" />} danger onSelect={run(() => api.trashItem(item.id), t("item.movedToTrash"))}>
                {t("item.moveToTrash")}
              </CtxItem>
            </>
          )}
        </ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
  );
}

function CtxItem({ children, icon, onSelect, danger }: { children: ReactNode; icon: ReactNode; onSelect: () => void; danger?: boolean }) {
  return (
    <ContextMenu.Item
      onSelect={onSelect}
      className={cx(
        "flex cursor-default items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-sm outline-none",
        danger ? "text-danger data-[highlighted]:bg-danger-soft" : "data-[highlighted]:bg-panel-3",
      )}
    >
      <span className={danger ? "text-danger" : "text-muted"}>{icon}</span>
      {children}
    </ContextMenu.Item>
  );
}

/** "New Item" button with a searchable category picker. */
export function NewItemButton({ onPick }: { onPick: (category: Category) => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild>
        <Button variant="primary" className="h-9 px-3" title={`${t("list.newItem")} (Ctrl N)`}>
          <Plus className="size-4" />
          <span className="sr-only">{t("list.newItem")}</span>
        </Button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content align="end" sideOffset={6} className="z-50 w-72 overflow-hidden rounded-xl border border-line bg-panel shadow-xl animate-pop">
          <Command loop>
            <div className="border-b border-line px-3 pb-2 pt-3">
              <div className="mb-2 text-[13px] font-semibold">{t("list.chooseCategory")}</div>
              <Command.Input autoFocus placeholder={t("common.searchPlaceholder")} className="h-8 w-full rounded-md bg-panel-3 px-2.5 text-sm outline-none placeholder:text-subtle" />
            </div>
            <Command.List className="max-h-80 overflow-y-auto p-1">
              <Command.Empty className="px-3 py-6 text-center text-sm text-subtle">{t("common.noResults")}</Command.Empty>
              {CATEGORIES.filter((c) => !c.hidden).map((c) => (
                <Command.Item
                  key={c.id}
                  value={`${categoryLabel(c.id)} ${c.id}`}
                  onSelect={() => {
                    setOpen(false);
                    onPick(c.id);
                  }}
                  className="flex cursor-default items-center gap-3 rounded-lg px-2 py-1.5 text-sm data-[selected=true]:bg-panel-3"
                >
                  <span className={cx("flex size-7 items-center justify-center rounded-lg", c.tint)}>
                    <c.icon className="size-4" />
                  </span>
                  {categoryLabel(c.id)}
                </Command.Item>
              ))}
            </Command.List>
          </Command>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

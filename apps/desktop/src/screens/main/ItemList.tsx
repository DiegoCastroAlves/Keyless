import { Command } from "cmdk";
import {
  Archive,
  ArrowDownWideNarrow,
  ArrowLeft,
  ArrowRight,
  ArrowRightLeft,
  Copy,
  Filter,
  History,
  KeyRound,
  Pencil,
  Plus,
  RotateCcw,
  Search,
  Star,
  Trash,
  User,
  X,
} from "lucide-react";
import { ContextMenu, Popover } from "radix-ui";
import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { ItemIcon, LEVELS } from "../../components/common";
import {
  Button,
  Dialog,
  IconButton,
  Kbd,
  Menu,
  MenuContent,
  MenuItem,
  MenuLabel,
  MenuRadioGroup,
  MenuRadioItem,
  MenuSeparator,
  MenuTrigger,
  cx,
} from "../../components/ui";
import { api, errorMessage, type Category, type DeletedVault, type ItemSummary, type ListSort } from "../../lib/api";
import { CATEGORIES, categoryLabel } from "../../lib/categories";
import { firstWebsite } from "../../lib/format";
import { itemIdOfLink, showLinkedItem } from "../../lib/itemLinks";
import { isOff, isPending, useInScope, useScopedIssues, useSentinel } from "../../lib/sentinel";
import { filterItems, groupLabel, hasFilters, useApp, viewTitle, type ListOrder } from "../../lib/store";
import { toast } from "../../lib/toast";
import { MoveItemsDialog } from "./MoveDialog";
import { AlertPicker, SentinelSummary } from "./Sentinel";

/** What the search box (outside the list) can do with it. */
export interface ItemListControl {
  /** Moves into the list, to the next item. */
  enter: () => void;
}

export function ItemList({ onNewItem, controlRef }: { onNewItem: (category: Category) => void; controlRef: React.Ref<ItemListControl> }) {
  const { t } = useTranslation();
  const items = useApp((s) => s.items);
  const vaults = useApp((s) => s.vaults);
  const view = useApp((s) => s.view);
  const search = useApp((s) => s.search);
  const selectedId = useApp((s) => s.selectedId);
  const select = useApp((s) => s.select);
  const editing = useApp((s) => s.editing);
  const [emptyTrashOpen, setEmptyTrashOpen] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const settings = useApp((s) => s.settings);
  const order: ListOrder = useMemo(
    () => ({ sort: settings?.list_sort ?? "title", desc: settings?.list_sort_desc ?? false }),
    [settings?.list_sort, settings?.list_sort_desc],
  );
  // Sentinel's lists: the items with the chosen alert, in the vault it
  // looks at (or every vault).
  const issues = useScopedIssues();
  const inScope = useInScope();
  const sentinelReport = useSentinel((s) => s.report);
  const alert = view.kind === "sentinel" ? view.alert : undefined;
  const only = useMemo(() => {
    if (!alert) return undefined;
    if (alert === "ignored") return new Set((sentinelReport?.ignored ?? []).map(([id]) => id).filter((id) => !inScope || inScope(id)));
    return new Set(issues.get(alert)!.keys());
  }, [alert, issues, sentinelReport, inScope]);
  // In the ignored list: the items with an ignored alert that no longer applies.
  const staleItems = useMemo(
    () => (alert === "ignored" ? new Set((sentinelReport?.stale ?? []).map(([id]) => id)) : null),
    [alert, sentinelReport],
  );
  const filters = useApp((s) => s.filters);
  const detailMatches = useApp((s) => s.detailMatches);
  const passkeyItems = useApp((s) => s.passkeyItems);
  const selection = useApp((s) => s.selection);
  const levels = sentinelReport?.levels;
  const visible = useMemo(
    () => filterItems(items, view, search, order, only, { filters, detailMatches, passkeyItems, levels }),
    [items, view, search, order, only, filters, detailMatches, passkeyItems, levels],
  );

  // The search also looks in notes and other values (decrypted by the app
  // for it), a moment after typing stops; and is remembered for the session.
  useEffect(() => {
    const q = search.trim();
    if (q.length < 2) {
      useApp.setState({ detailMatches: null });
      return;
    }
    let current = true;
    const handle = setTimeout(() => {
      api
        .searchItemDetails(q)
        .then((ids) => current && useApp.setState({ detailMatches: new Set(ids) }))
        .catch(() => current && useApp.setState({ detailMatches: null }));
    }, 250);
    const remember = setTimeout(() => useApp.getState().rememberSearch(q), 1500);
    return () => {
      current = false;
      clearTimeout(handle);
      clearTimeout(remember);
    };
  }, [search]);
  const title = viewTitle(view, vaults);
  const canCreate = view.kind !== "trash" && view.kind !== "archive";

  // Keep a valid selection: select the first item when nothing is selected.
  useEffect(() => {
    if (editing?.isNew) return;
    if ((selectedId || visible.length) && (!selectedId || !visible.some((i) => i.id === selectedId))) {
      select(visible[0]?.id ?? null, true);
    }
    const kept = selection.filter((id) => visible.some((i) => i.id === id));
    if (kept.length !== selection.length) useApp.getState().setSelection(kept.length > 1 ? kept : []);
  }, [visible, selectedId, select, editing, selection]);

  const move = (delta: number, extend = false) => {
    if (!visible.length) return;
    const index = visible.findIndex((i) => i.id === selectedId);
    const next = visible[Math.min(visible.length - 1, Math.max(0, index + delta))];
    if (extend && selectedId) {
      // Shift+arrows grow the selection from where it started.
      const current = selection.length ? selection : [selectedId];
      useApp.setState({ selectedId: next.id, selection: current.includes(next.id) ? current.filter((id) => id !== selectedId) : [...current, next.id] });
    } else {
      // Moving with the arrow keys replaces the place rather than adding one
      // to go back to for each item passed.
      select(next.id, true);
    }
    listRef.current?.querySelector(`[data-id="${next.id}"]`)?.scrollIntoView({ block: "nearest" });
  };

  // Ctrl+click adds or removes an item, Shift+click takes the items between.
  const clickRow = (item: ItemSummary, e: React.MouseEvent) => {
    const { selection: current, selectedId: anchor } = useApp.getState();
    if (e.ctrlKey || e.metaKey) {
      const base = current.length ? current : anchor ? [anchor] : [];
      const next = base.includes(item.id) ? base.filter((id) => id !== item.id) : [...base, item.id];
      useApp.setState({ selectedId: item.id, selection: next.length > 1 ? next : [] });
    } else if (e.shiftKey && anchor) {
      const from = visible.findIndex((i) => i.id === anchor);
      const to = visible.findIndex((i) => i.id === item.id);
      const [a, b] = from < to ? [from, to] : [to, from];
      useApp.setState({ selection: visible.slice(a, b + 1).map((i) => i.id) });
    } else {
      select(item.id);
    }
  };

  useImperativeHandle(controlRef, () => ({
    enter: () => {
      listRef.current?.focus();
      move(1);
    },
  }));

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
    <section className="flex h-full w-full flex-col border-r border-line bg-panel">
      <div className="flex h-11 items-center justify-between gap-2 pl-4 pr-2">
        {alert ? <AlertPicker current={alert} /> : <span className="truncate text-[13px] font-semibold">{title}</span>}
        <div className="flex items-center gap-1">
          <span className="text-xs text-subtle">{t("list.count", { count: visible.length })}</span>
          <FilterMenu />
          <SortMenu count={visible.length} order={order} />
        </div>
      </div>
      <FilterChips />
      {detailMatches && detailMatches.size > 0 && search.trim() && (
        <div className="mx-3 mb-1 text-[11px] text-subtle">{t("list.searchingDetails")}</div>
      )}

      {view.kind === "trash" && visible.length > 0 && (
        <div className="mx-3 mb-2 space-y-1 rounded-lg bg-panel-2 px-3 py-2 text-xs text-muted">
          <p>{t("list.trashHint")}</p>
          <button onClick={() => setEmptyTrashOpen(true)} className="font-medium text-danger hover:underline">
            {t("list.emptyTrash")}
          </button>
        </div>
      )}
      {view.kind === "trash" && <DeletedVaults />}
      {view.kind === "all" && !search.trim() && <SentinelSummary />}
      {alert === "duplicate" && <DeleteDuplicates />}
      {alert === "ignored" && <RemoveStaleIgnores />}

      <div
        ref={listRef}
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            move(1, e.shiftKey);
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            move(-1, e.shiftKey);
          } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "a") {
            e.preventDefault();
            useApp.getState().setSelection(visible.map((i) => i.id));
          } else if (e.key === "Delete" && view.kind !== "trash") {
            e.preventDefault();
            const ids = selection.length ? selection : selectedId ? [selectedId] : [];
            void Promise.all(ids.map((id) => api.trashItem(id)))
              .then(async () => {
                toast.success(t("bulk.trashed", { count: ids.length }));
                useApp.getState().setSelection([]);
                await useApp.getState().loadData();
              })
              .catch((err) => toast.error(errorMessage(err)));
          }
        }}
        className="flex-1 overflow-y-auto px-2 pb-3 outline-none"
      >
        {visible.length === 0 ? (
          alert ? (
            <p className="px-6 py-14 text-center text-sm text-subtle">
              {alert !== "ignored" && isOff(sentinelReport, alert)
                ? t("sentinel.listOff")
                : alert !== "ignored" && isPending(sentinelReport, alert)
                  ? t("sentinel.listNotChecked")
                  : t(alert === "ignored" ? "sentinel.ignoredEmpty" : "sentinel.listEmpty")}
            </p>
          ) : (
            <EmptyList query={search} canCreate={canCreate} onNewItem={() => onNewItem("login")} />
          )
        ) : (
          visible.map((item, index) => {
            const label = groupLabel(item, order.sort);
            const showLabel = label !== null && (index === 0 || groupLabel(visible[index - 1], order.sort) !== label);
            return (
              <div key={item.id}>
                {showLabel && (
                  <div className="sticky top-0 z-10 bg-panel px-2.5 pb-1 pt-3 text-[11px] font-semibold uppercase tracking-wider text-subtle">
                    {label}
                  </div>
                )}
                <ItemRow
                  item={item}
                  selected={selection.length > 1 ? selection.includes(item.id) : item.id === selectedId}
                  onSelect={(e) => clickRow(item, e)}
                  note={staleItems?.has(item.id) ? t("sentinel.staleShort") : undefined}
                />
              </div>
            );
          })
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

const SORTS: ListSort[] = ["title", "created", "modified", "frequent", "recent", "strength"];
/** The direction a sort starts in when picked: A to Z, newest or most used first, weakest first. */
const STARTS_DESC: Record<ListSort, boolean> = { title: false, created: true, modified: true, frequent: true, recent: true, strength: false };

function SortMenu({ count, order }: { count: number; order: ListOrder }) {
  const { t } = useTranslation();
  const settings = useApp((s) => s.settings);
  const setSettings = useApp((s) => s.setSettings);
  if (!settings) return null;
  const save = (patch: Partial<typeof settings>) => setSettings({ ...settings, ...patch }).catch((err) => toast.error(errorMessage(err)));
  const direction = order.sort === "title" ? "title" : order.sort === "frequent" ? "frequent" : order.sort === "strength" ? "strength" : "date";
  return (
    <Menu>
      <MenuTrigger asChild>
        <button
          className="flex size-7 items-center justify-center rounded-md text-muted hover:bg-panel-3 hover:text-fg data-[state=open]:bg-panel-3 data-[state=open]:text-fg"
          aria-label={t("list.sortBy", { count })}
          title={t("list.sortBy", { count })}
        >
          <ArrowDownWideNarrow className="size-4" />
        </button>
      </MenuTrigger>
      <MenuContent>
        <MenuLabel>{t("list.sortBy", { count })}</MenuLabel>
        <MenuRadioGroup value={order.sort} onValueChange={(value) => save({ list_sort: value as ListSort, list_sort_desc: STARTS_DESC[value as ListSort] })}>
          {SORTS.map((sort) => (
            <MenuRadioItem key={sort} value={sort}>
              {t(`list.sort.${sort}`)}
            </MenuRadioItem>
          ))}
        </MenuRadioGroup>
        <MenuSeparator />
        <MenuRadioGroup value={order.desc ? "desc" : "asc"} onValueChange={(value) => save({ list_sort_desc: value === "desc" })}>
          {direction === "title" ? (
            <>
              <MenuRadioItem value="asc">{t("list.order.az")}</MenuRadioItem>
              <MenuRadioItem value="desc">{t("list.order.za")}</MenuRadioItem>
            </>
          ) : direction === "frequent" ? (
            <>
              <MenuRadioItem value="desc">{t("list.order.mostUsed")}</MenuRadioItem>
              <MenuRadioItem value="asc">{t("list.order.leastUsed")}</MenuRadioItem>
            </>
          ) : direction === "strength" ? (
            <>
              <MenuRadioItem value="asc">{t("list.order.weakest")}</MenuRadioItem>
              <MenuRadioItem value="desc">{t("list.order.strongest")}</MenuRadioItem>
            </>
          ) : (
            <>
              <MenuRadioItem value="desc">{t("list.order.newest")}</MenuRadioItem>
              <MenuRadioItem value="asc">{t("list.order.oldest")}</MenuRadioItem>
            </>
          )}
        </MenuRadioGroup>
      </MenuContent>
    </Menu>
  );
}

/** Narrows the list: a category, vault or tag, untagged items, items with a
 * passkey. */
function FilterMenu() {
  const { t } = useTranslation();
  const filters = useApp((s) => s.filters);
  const vaults = useApp((s) => s.vaults);
  const items = useApp((s) => s.items);
  const setFilters = useApp((s) => s.setFilters);
  const tags = useMemo(() => [...new Set(items.flatMap((i) => i.tags.map((tag) => tag.split("/")[0])))].sort((a, b) => a.localeCompare(b)), [items]);
  const active = hasFilters(filters);
  return (
    <Menu>
      <MenuTrigger asChild>
        <button
          className={cx(
            "flex size-7 items-center justify-center rounded-md hover:bg-panel-3 hover:text-fg data-[state=open]:bg-panel-3",
            active ? "text-accent" : "text-muted",
          )}
          aria-label={t("filters.title")}
          title={t("filters.title")}
        >
          <Filter className="size-4" />
        </button>
      </MenuTrigger>
      <MenuContent>
        <MenuLabel>{t("filters.category")}</MenuLabel>
        <MenuRadioGroup value={filters.category ?? ""} onValueChange={(v) => setFilters({ ...filters, category: (v || undefined) as Category | undefined })}>
          <MenuRadioItem value="">{t("filters.any")}</MenuRadioItem>
          {CATEGORIES.filter((c) => items.some((i) => i.category === c.id)).map((c) => (
            <MenuRadioItem key={c.id} value={c.id}>
              {categoryLabel(c.id)}
            </MenuRadioItem>
          ))}
        </MenuRadioGroup>
        {vaults.length > 1 && (
          <>
            <MenuSeparator />
            <MenuLabel>{t("filters.vault")}</MenuLabel>
            <MenuRadioGroup value={filters.vault ?? ""} onValueChange={(v) => setFilters({ ...filters, vault: v || undefined })}>
              <MenuRadioItem value="">{t("filters.any")}</MenuRadioItem>
              {vaults.map((v) => (
                <MenuRadioItem key={v.id} value={v.id}>
                  {v.name}
                </MenuRadioItem>
              ))}
            </MenuRadioGroup>
          </>
        )}
        {tags.length > 0 && (
          <>
            <MenuSeparator />
            <MenuLabel>{t("filters.tag")}</MenuLabel>
            <MenuRadioGroup value={filters.untagged ? ":none" : (filters.tag ?? "")} onValueChange={(v) => setFilters({ ...filters, tag: v && v !== ":none" ? v : undefined, untagged: v === ":none" || undefined })}>
              <MenuRadioItem value="">{t("filters.any")}</MenuRadioItem>
              <MenuRadioItem value=":none">{t("filters.untagged")}</MenuRadioItem>
              {tags.map((tag) => (
                <MenuRadioItem key={tag} value={tag}>
                  {tag}
                </MenuRadioItem>
              ))}
            </MenuRadioGroup>
          </>
        )}
        <MenuSeparator />
        <MenuLabel>{t("filters.strength")}</MenuLabel>
        <MenuRadioGroup
          value={filters.strength === undefined ? "" : String(filters.strength)}
          onValueChange={(v) => setFilters({ ...filters, strength: v === "" ? undefined : Number(v) })}
        >
          <MenuRadioItem value="">{t("filters.any")}</MenuRadioItem>
          {LEVELS.map((level) => (
            <MenuRadioItem key={level} value={String(level)}>
              {t(`strength.${level}`)}
            </MenuRadioItem>
          ))}
        </MenuRadioGroup>
        <MenuSeparator />
        <MenuItem onSelect={() => setFilters({ ...filters, passkey: !filters.passkey || undefined })}>
          <span className="flex w-full items-center justify-between gap-3">
            {t("filters.passkey")}
            {filters.passkey && <span className="text-accent">✓</span>}
          </span>
        </MenuItem>
        {active && (
          <>
            <MenuSeparator />
            <MenuItem icon={<X className="size-4" />} onSelect={() => setFilters({})}>
              {t("filters.clear")}
            </MenuItem>
          </>
        )}
      </MenuContent>
    </Menu>
  );
}

/** The filters in use, each removable. */
function FilterChips() {
  const { t } = useTranslation();
  const filters = useApp((s) => s.filters);
  const vaults = useApp((s) => s.vaults);
  const setFilters = useApp((s) => s.setFilters);
  const chips: { label: string; clear: () => void }[] = [];
  if (filters.category) chips.push({ label: categoryLabel(filters.category), clear: () => setFilters({ ...filters, category: undefined }) });
  if (filters.vault) chips.push({ label: vaults.find((v) => v.id === filters.vault)?.name ?? "", clear: () => setFilters({ ...filters, vault: undefined }) });
  if (filters.tag) chips.push({ label: `#${filters.tag}`, clear: () => setFilters({ ...filters, tag: undefined }) });
  if (filters.untagged) chips.push({ label: t("filters.untagged"), clear: () => setFilters({ ...filters, untagged: undefined }) });
  if (filters.passkey) chips.push({ label: t("filters.passkey"), clear: () => setFilters({ ...filters, passkey: undefined }) });
  if (filters.strength !== undefined) {
    chips.push({ label: t("filters.strengthChip", { level: t(`strength.${filters.strength}`) }), clear: () => setFilters({ ...filters, strength: undefined }) });
  }
  if (chips.length === 0) return null;
  return (
    <div className="mx-3 mb-2 flex flex-wrap gap-1.5">
      {chips.map((chip) => (
        <span key={chip.label} className="inline-flex items-center gap-1 rounded-full bg-accent-soft py-0.5 pl-2.5 pr-1 text-xs font-medium text-accent">
          {chip.label}
          <button onClick={chip.clear} className="rounded-full p-0.5 hover:bg-accent/15" aria-label={t("common.remove")}>
            <X className="size-3" />
          </button>
        </span>
      ))}
    </div>
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

const ItemRowButton = forwardRef<
  HTMLButtonElement,
  { item: ItemSummary; selected: boolean; note?: string; onSelect: (e: React.MouseEvent) => void; onContextMenu?: React.MouseEventHandler<HTMLButtonElement> }
>(function ItemRowButton({ item, selected, note, onSelect, onContextMenu, ...props }, ref) {
  return (
    <button
      ref={ref}
      data-id={item.id}
      onClick={onSelect}
      onContextMenu={(e) => {
        // A right click inside a selection keeps it.
        if (!selected) onSelect(e);
        onContextMenu?.(e);
      }}
      className={cx(
        "group mb-0.5 flex w-full items-center gap-3 rounded-xl px-2.5 py-2 text-left transition-colors compact:py-1",
        selected ? "bg-accent-soft" : "hover:bg-panel-2",
      )}
      {...props}
    >
      <ItemIcon title={item.title} category={item.category} url={firstWebsite(item.urls)} item={item} size={useApp.getState().settings?.density === "compact" ? "sm" : "md"} />
      <div className="min-w-0 flex-1">
        <div className={cx("truncate text-[13.5px] font-medium", selected && "text-fg")}>{item.title}</div>
        <div className="truncate text-xs text-muted">{item.subtitle || " "}</div>
      </div>
      {note && <span className="shrink-0 rounded-full bg-success/15 px-2 py-0.5 text-[11px] font-medium text-success">{note}</span>}
      {item.favorite && <Star className="size-3.5 shrink-0 fill-amber-400 text-amber-400" />}
    </button>
  );
});

function ItemRow({ item, selected, note, onSelect }: { item: ItemSummary; selected: boolean; note?: string; onSelect: (e: React.MouseEvent) => void }) {
  const { t } = useTranslation();
  const loadData = useApp((s) => s.loadData);
  const startEditing = useApp((s) => s.startEditing);
  const trashed = item.trashedAt !== null;
  const [moveOpen, setMoveOpen] = useState(false);

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
    <>
      <ContextMenu.Root>
        <ContextMenu.Trigger asChild>
          <ItemRowButton item={item} selected={selected} note={note} onSelect={onSelect} />
        </ContextMenu.Trigger>
        <ContextMenu.Portal>
          <ContextMenu.Content
            collisionPadding={8}
            className="z-50 max-h-[var(--radix-context-menu-content-available-height)] min-w-52 overflow-y-auto rounded-xl border border-line bg-panel p-1 shadow-xl animate-pop"
          >
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
                    useApp.getState().select(item.id);
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
                <CtxItem icon={<ArrowRightLeft className="size-4" />} onSelect={() => setMoveOpen(true)}>
                  {t("move.toVaultAction")}
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
      <MoveItemsDialog open={moveOpen} onOpenChange={setMoveOpen} itemIds={[item.id]} fromVaultId={item.vaultId} />
    </>
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
/** The search box and the new item button, above the list and the item. */
export function TopBar({
  searchRef,
  onNewItem,
  onEnterList,
}: {
  searchRef: React.RefObject<HTMLInputElement | null>;
  onNewItem: (category: Category) => void;
  onEnterList: () => void;
}) {
  const { t } = useTranslation();
  const view = useApp((s) => s.view);
  const vaults = useApp((s) => s.vaults);
  const search = useApp((s) => s.search);
  const setSearch = useApp((s) => s.setSearch);
  const history = useApp((s) => s.searchHistory);
  const [focused, setFocused] = useState(false);
  const title = viewTitle(view, vaults);
  return (
    <div className="flex h-14 shrink-0 items-center gap-3 border-b border-line bg-panel px-3">
      <HistoryButtons />
      <div className="relative min-w-0 flex-1">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-subtle" />
        <input
          ref={searchRef}
          value={search}
          onChange={(e) => {
            // A link to an item, pasted: that item.
            const linked = itemIdOfLink(e.target.value);
            if (linked) {
              showLinkedItem(linked);
              return;
            }
            // Sentinel's overview has no list to search: go to every item.
            if (view.kind === "sentinel" && !view.alert) useApp.getState().setView({ kind: "all" });
            setSearch(e.target.value);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              onEnterList();
            } else if (e.key === "Escape") {
              setSearch("");
            } else if (e.key === "Enter") {
              useApp.getState().rememberSearch(search);
            }
          }}
          onFocus={() => setFocused(true)}
          // After a click on a recent search.
          onBlur={() => setTimeout(() => setFocused(false), 150)}
          placeholder={t("list.searchIn", { view: title })}
          spellCheck={false}
          className="h-9 w-full rounded-lg border border-transparent bg-panel-3 pl-8 pr-14 text-sm outline-none placeholder:text-subtle focus:border-accent focus:bg-panel focus:ring-3 focus:ring-accent-soft"
        />
        <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2">
          <Kbd>Ctrl F</Kbd>
        </span>
        {focused && !search && history.length > 0 && (
          <div className="absolute inset-x-0 top-full z-30 mt-1.5 overflow-hidden rounded-xl border border-line bg-panel p-1 shadow-xl animate-pop">
            <div className="flex items-center justify-between px-2.5 pb-1 pt-1.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">
              {t("list.recentSearches")}
              <button onMouseDown={(e) => e.preventDefault()} onClick={() => useApp.setState({ searchHistory: [] })} className="normal-case tracking-normal text-accent hover:underline">
                {t("list.clearRecent")}
              </button>
            </div>
            {history.map((q) => (
              <button
                key={q}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => setSearch(q)}
                className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-sm hover:bg-panel-3"
              >
                <History className="size-3.5 text-subtle" />
                <span className="truncate">{q}</span>
              </button>
            ))}
          </div>
        )}
      </div>
      <NewItemButton onPick={onNewItem} />
    </div>
  );
}

/** Back and forward between the places visited (also Alt+arrows and the
 * mouse's side buttons). Not while an item is being edited. */
function HistoryButtons() {
  const { t } = useTranslation();
  const canGoBack = useApp((s) => s.past.length > 0 && !s.editing);
  const canGoForward = useApp((s) => s.future.length > 0 && !s.editing);
  return (
    <div className="flex shrink-0 items-center">
      <IconButton label={`${t("common.back")} (Alt+←)`} disabled={!canGoBack} onClick={() => useApp.getState().goBack()}>
        <ArrowLeft className="size-[18px]" />
      </IconButton>
      <IconButton label={`${t("common.forward")} (Alt+→)`} disabled={!canGoForward} onClick={() => useApp.getState().goForward()}>
        <ArrowRight className="size-[18px]" />
      </IconButton>
    </div>
  );
}

export function NewItemButton({ onPick }: { onPick: (category: Category) => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild>
        <Button variant="primary" className="h-9 shrink-0 px-3" title={`${t("list.newItem")} (Ctrl N)`}>
          <Plus className="size-4" />
          {t("list.newItem")}
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

/** Vaults deleted in the last 30 days, each with a button to bring it back
 * (only their owner sees them). */
function DeletedVaults() {
  const { t } = useTranslation();
  const [vaults, setVaults] = useState<DeletedVault[]>([]);
  const [restoring, setRestoring] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  useEffect(() => {
    // Offline, or the server cannot say: nothing is shown.
    api.deletedVaults().then(setVaults).catch(() => undefined);
  }, []);
  if (vaults.length === 0) return null;

  const restore = async (vault: DeletedVault) => {
    setRestoring(vault.id);
    try {
      await api.restoreVault(vault.id);
      setVaults((list) => list.filter((v) => v.id !== vault.id));
      await useApp.getState().loadData();
      toast.success(t("list.vaultRestored", { name: vault.name }));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setRestoring(null);
    }
  };

  return (
    <div className="mx-3 mb-2 rounded-lg border border-line">
      <div className="px-3 pt-2 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("list.deletedVaults")}</div>
      {(all ? vaults : vaults.slice(0, 3)).map((vault) => {
        const daysLeft = Math.max(0, 30 - Math.floor((Date.now() / 1000 - vault.deletedAt) / 86400));
        return (
          <div key={vault.id} className="flex items-center gap-2 px-3 py-2">
            <div className="min-w-0 flex-1">
              <div className="truncate text-[13px] font-medium">{vault.name}</div>
              <div className="text-xs text-subtle">{t("list.deletedVaultLeft", { count: daysLeft })}</div>
            </div>
            <Button size="sm" loading={restoring === vault.id} disabled={restoring !== null} onClick={() => void restore(vault)}>
              {t("list.restoreVault")}
            </Button>
          </div>
        );
      })}
      {!all && vaults.length > 3 && (
        <button onClick={() => setAll(true)} className="px-3 pb-2 text-xs font-medium text-accent hover:underline">
          {t("list.showMoreVaults", { count: vaults.length - 3 })}
        </button>
      )}
    </div>
  );
}

/** Sentinel's duplicates: keeps the most recently changed item of each
 * account and moves the others to Recently Deleted (with undo). */
function DeleteDuplicates() {
  const { t } = useTranslation();
  const report = useSentinel((s) => s.report);
  const issues = useScopedIssues();
  const items = useApp((s) => s.items);
  const vaults = useApp((s) => s.vaults);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);

  const byId = new Map(items.map((i) => [i.id, i]));
  const writable = new Set(vaults.filter((v) => v.canWrite).map((v) => v.id));
  const listed = issues.get("duplicate")!;
  const extra = (report?.duplicates ?? []).flatMap((group) => {
    const shown = group.filter((id) => listed.has(id) && byId.has(id));
    if (shown.length < 2) return [];
    const newest = [...shown].sort((a, b) => byId.get(b)!.updatedAt - byId.get(a)!.updatedAt);
    return newest.slice(1).filter((id) => writable.has(byId.get(id)!.vaultId));
  });
  if (extra.length === 0) return null;

  const remove = async () => {
    setBusy(true);
    try {
      await Promise.all(extra.map((id) => api.trashItem(id)));
      await useApp.getState().loadData();
      void useSentinel.getState().loadReport();
      toast.undoable(t("sentinel.duplicatesDeleted", { count: extra.length }), () =>
        void Promise.all(extra.map((id) => api.restoreItem(id)))
          .then(() => useApp.getState().loadData())
          .then(() => useSentinel.getState().loadReport())
          .catch((err) => toast.error(errorMessage(err))),
      );
      setConfirm(false);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-3 mb-2 space-y-1 rounded-lg bg-panel-2 px-3 py-2 text-xs text-muted">
      <p>{t("sentinel.duplicatesHint")}</p>
      <button onClick={() => setConfirm(true)} className="font-medium text-danger hover:underline">
        {t("sentinel.deleteDuplicates", { count: extra.length })}
      </button>
      <Dialog
        open={confirm}
        onOpenChange={setConfirm}
        title={t("sentinel.deleteDuplicatesTitle", { count: extra.length })}
        description={t("sentinel.deleteDuplicatesBody")}
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setConfirm(false)}>{t("common.cancel")}</Button>
          <Button variant="danger" loading={busy} onClick={() => void remove()}>
            {t("sentinel.deleteDuplicatesAction")}
          </Button>
        </div>
      </Dialog>
    </div>
  );
}

/** Sentinel's ignored alerts that no longer apply (fixed since they were
 * ignored), in the vault it looks at: removed all at once. */
function RemoveStaleIgnores() {
  const { t } = useTranslation();
  const report = useSentinel((s) => s.report);
  const inScope = useInScope();
  const items = useApp((s) => s.items);
  const vaults = useApp((s) => s.vaults);
  const [busy, setBusy] = useState(false);

  const writable = new Set(vaults.filter((v) => v.canWrite).map((v) => v.id));
  const vaultOf = new Map(items.map((i) => [i.id, i.vaultId]));
  const stale = (report?.stale ?? []).filter(([id]) => (!inScope || inScope(id)) && writable.has(vaultOf.get(id) ?? ""));
  if (stale.length === 0) return null;

  const remove = async () => {
    setBusy(true);
    try {
      await api.sentinelUnignore(stale);
      await useApp.getState().loadData();
      toast.success(t("sentinel.staleRemoved", { count: stale.length }));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-3 mb-2 space-y-1 rounded-lg bg-panel-2 px-3 py-2 text-xs text-muted">
      <p>{t("sentinel.staleHint", { count: stale.length })}</p>
      <button onClick={() => void remove()} disabled={busy} className="font-medium text-accent hover:underline disabled:opacity-50">
        {t("sentinel.removeStale", { count: stale.length })}
      </button>
    </div>
  );
}

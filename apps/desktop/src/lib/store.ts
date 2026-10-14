import { create } from "zustand";

import i18n from "../i18n";
import { categoryLabel } from "./categories";
import {
  api,
  errorMessage,
  type AppStatus,
  type ListSort,
  type Category,
  type ItemDraft,
  type ItemSummary,
  type InstallKind,
  type SentinelAlert,
  type Settings,
  type SyncStatus,
  type UpdateInfo,
  type Vault,
} from "./api";
import { ALERT_TITLE } from "./sentinel";

export type View =
  | { kind: "all" }
  | { kind: "favorites" }
  | { kind: "vault"; id: string }
  | { kind: "category"; category: Category }
  | { kind: "tag"; tag: string }
  | { kind: "archive" }
  | { kind: "trash" }
  /** Sentinel's overview, or the items with one alert (or ignored ones). */
  | { kind: "sentinel"; alert?: SentinelAlert | "ignored" };

/** Where the user was: back and forward go between these. */
export interface Place {
  view: View;
  selectedId: string | null;
}

/** How many places back is remembered. */
const HISTORY_LIMIT = 100;

function samePlace(a: Place, b: Place): boolean {
  return a.selectedId === b.selectedId && JSON.stringify(a.view) === JSON.stringify(b.view);
}

export interface Editing {
  draft: ItemDraft;
  isNew: boolean;
}

/** Narrows the list within its view. */
export interface ListFilters {
  category?: Category;
  vault?: string;
  tag?: string;
  untagged?: boolean;
  /** Only items that keep a passkey. */
  passkey?: boolean;
  /** Only items whose password is at this strength level (0 to 6). */
  strength?: number;
}

/** Some filter is in use (strength level 0 counts). */
export function hasFilters(filters: ListFilters): boolean {
  return Object.values(filters).some((v) => v !== undefined && v !== false && v !== "");
}

/** How many searches are remembered (for this session only: a search says
 * what the user looks for, so it is never written anywhere). */
const SEARCH_HISTORY = 10;

interface AppStore {
  status: AppStatus | null;
  settings: Settings | null;
  syncStatus: SyncStatus | null;
  /** Newer Keyless version, when the update check found one. */
  update: UpdateInfo | null;
  /** How this copy installs updates. */
  install: { kind: InstallKind; needsPassword: boolean } | null;
  vaults: Vault[];
  items: ItemSummary[];
  view: View;
  search: string;
  selectedId: string | null;
  editing: Editing | null;
  /** Bumped to make the detail pane reload after a change. */
  revision: number;
  /** Set when the lock screen sends the user to account recovery. */
  recoverEmail: string | null;
  /** This device was signed out from another one: the welcome screen says so. */
  deviceRevoked: boolean;
  /** The list of keyboard shortcuts is open. */
  shortcutsOpen: boolean;
  /** Items selected together (two or more: the bulk actions show). */
  selection: string[];
  filters: ListFilters;
  /** Items whose notes or other values match the search (decrypted by the
   * app for it); null while there is no such search. */
  detailMatches: Set<string> | null;
  /** Items with a passkey, while the list is filtered by them. */
  passkeyItems: Set<string> | null;
  /** Recent searches of this session. */
  searchHistory: string[];
  setSelection: (ids: string[]) => void;
  setFilters: (filters: ListFilters) => void;
  rememberSearch: (query: string) => void;

  refreshStatus: () => Promise<AppStatus>;
  loadData: () => Promise<void>;
  loadSettings: () => Promise<void>;
  setSettings: (settings: Settings) => Promise<void>;
  setSyncStatus: (s: SyncStatus) => void;
  setUpdate: (update: UpdateInfo | null) => void;
  setInstall: (install: { kind: InstallKind; needsPassword: boolean }) => void;
  /** Places before the current one (latest last), and after it when the
   * user went back. */
  past: Place[];
  future: Place[];
  setView: (view: View) => void;
  setSearch: (search: string) => void;
  /** Selects an item; `auto` when the app chose it (it then replaces the
   * current place instead of adding one to go back to). */
  select: (id: string | null, auto?: boolean) => void;
  goBack: () => void;
  goForward: () => void;
  startEditing: (editing: Editing) => void;
  stopEditing: () => void;
  bump: () => void;
  reset: () => void;
}

export const useApp = create<AppStore>((set, get) => ({
  status: null,
  settings: null,
  syncStatus: null,
  update: null,
  install: null,
  vaults: [],
  items: [],
  view: { kind: "all" },
  search: "",
  selectedId: null,
  editing: null,
  revision: 0,
  recoverEmail: null,
  deviceRevoked: false,
  shortcutsOpen: false,
  selection: [],
  filters: {},
  detailMatches: null,
  passkeyItems: null,
  searchHistory: [],
  setSelection: (selection) => set({ selection }),
  setFilters: (filters) => {
    set({ filters, selection: [] });
    if (filters.passkey && !get().passkeyItems) {
      api
        .itemsWithPasskeys()
        .then((ids) => set({ passkeyItems: new Set(ids) }))
        .catch(() => set({ passkeyItems: new Set() }));
    }
  },
  rememberSearch: (query) => {
    const q = query.trim();
    if (q.length < 2) return;
    set({ searchHistory: [q, ...get().searchHistory.filter((h) => h.toLowerCase() !== q.toLowerCase())].slice(0, SEARCH_HISTORY) });
  },

  refreshStatus: async () => {
    const status = await api.status();
    set({ status });
    return status;
  },
  loadData: async () => {
    try {
      const [vaults, items] = await Promise.all([api.listVaults(), api.listItems()]);
      const { selectedId } = get();
      set({
        vaults,
        items,
        selectedId: selectedId && items.some((i) => i.id === selectedId) ? selectedId : get().selectedId,
        revision: get().revision + 1,
      });
    } catch (err) {
      console.warn("loadData", errorMessage(err));
    }
  },
  loadSettings: async () => {
    set({ settings: await api.getSettings() });
  },
  setSettings: async (settings) => {
    set({ settings: await api.updateSettings(settings) });
  },
  setSyncStatus: (syncStatus) => set({ syncStatus }),
  setUpdate: (update) => set({ update }),
  setInstall: (install) => set({ install }),
  past: [],
  future: [],
  setView: (view) => {
    const { view: current, selectedId, past } = get();
    const here = { view: current, selectedId };
    if (JSON.stringify(view) === JSON.stringify(current)) return set({ view, editing: null });
    set({ view, selectedId: null, selection: [], editing: null, past: [...past, here].slice(-HISTORY_LIMIT), future: [] });
  },
  setSearch: (search) => set({ search }),
  select: (selectedId, auto = false) => {
    const { view, selectedId: current, past, selection } = get();
    // A new array only when there was a selection, or every select would
    // look like a change.
    const cleared = selection.length ? [] : selection;
    if (auto || selectedId === current || current === null) return set({ selectedId, selection: cleared });
    set({ selectedId, selection: cleared, past: [...past, { view, selectedId: current }].slice(-HISTORY_LIMIT), future: [] });
  },
  goBack: () => {
    const { view, selectedId, past, future, editing } = get();
    const to = past[past.length - 1];
    if (!to || editing) return;
    const here = { view, selectedId };
    set({ ...to, past: past.slice(0, -1), future: samePlace(to, here) ? future : [here, ...future] });
  },
  goForward: () => {
    const { view, selectedId, past, future, editing } = get();
    const to = future[0];
    if (!to || editing) return;
    set({ ...to, past: [...past, { view, selectedId }].slice(-HISTORY_LIMIT), future: future.slice(1) });
  },
  startEditing: (editing) => set({ editing }),
  stopEditing: () => set({ editing: null }),
  bump: () => set({ revision: get().revision + 1 }),
  reset: () =>
    set({
      vaults: [],
      items: [],
      view: { kind: "all" },
      search: "",
      selectedId: null,
      editing: null,
      past: [],
      future: [],
      selection: [],
      filters: {},
      detailMatches: null,
      passkeyItems: null,
      searchHistory: [],
    }),
}));

export function viewTitle(view: View, vaults: Vault[]): string {
  switch (view.kind) {
    case "all":
      return i18n.t("sidebar.allItems");
    case "favorites":
      return i18n.t("sidebar.favorites");
    case "vault":
      return vaults.find((v) => v.id === view.id)?.name ?? "";
    case "category":
      return categoryLabel(view.category, true);
    case "tag":
      return view.tag;
    case "archive":
      return i18n.t("sidebar.archive");
    case "trash":
      return i18n.t("sidebar.trash");
    case "sentinel":
      if (!view.alert) return i18n.t("sidebar.sentinel");
      return i18n.t(view.alert === "ignored" ? "sentinel.ignoredTitle" : ALERT_TITLE[view.alert]);
  }
}

export interface ListOrder {
  sort: ListSort;
  desc: boolean;
}

const byTitle = (a: ItemSummary, b: ItemSummary) => a.title.localeCompare(b.title, undefined, { sensitivity: "base" });

function sortKey(item: ItemSummary, sort: ListSort, levels?: Record<string, number>): number {
  switch (sort) {
    case "strength":
      // Items without a password (or not checked yet) after the others.
      return levels?.[item.id] ?? 99;
    case "created":
      return item.createdAt;
    case "modified":
      return item.updatedAt;
    case "frequent":
      return item.uses;
    case "recent":
      return item.lastUsedAt ?? 0;
    default:
      return 0;
  }
}

export function sortItems(items: ItemSummary[], { sort, desc }: ListOrder, levels?: Record<string, number>): ItemSummary[] {
  return [...items].sort((a, b) => {
    if (sort === "title") return desc ? byTitle(b, a) : byTitle(a, b);
    // Items never used stay at the end, whatever the direction.
    if (sort === "recent" && (a.lastUsedAt === null) !== (b.lastUsedAt === null)) return a.lastUsedAt === null ? 1 : -1;
    if (sort === "strength" && (levels?.[a.id] === undefined) !== (levels?.[b.id] === undefined)) return levels?.[a.id] === undefined ? 1 : -1;
    const diff = sortKey(a, sort, levels) - sortKey(b, sort, levels);
    if (diff !== 0) return desc ? -diff : diff;
    return byTitle(a, b);
  });
}

function monthLabel(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleDateString(i18n.language, { month: "long", year: "numeric" });
}

/** Header of the group an item falls in for this order (none when sorted by use). */
export function groupLabel(item: ItemSummary, sort: ListSort): string | null {
  switch (sort) {
    case "title": {
      const first = item.title.trim().normalize("NFD").replace(/\p{M}/gu, "").charAt(0).toLocaleUpperCase();
      return /\p{L}/u.test(first) ? first : "#";
    }
    case "created":
      return monthLabel(item.createdAt);
    case "modified":
      return monthLabel(item.updatedAt);
    case "recent":
      return item.lastUsedAt ? monthLabel(item.lastUsedAt) : i18n.t("list.neverUsed");
    default:
      return null;
  }
}

/** What else narrows or orders the list. */
export interface ListExtras {
  filters?: ListFilters;
  /** Items whose details match the search. */
  detailMatches?: Set<string> | null;
  passkeyItems?: Set<string> | null;
  /** Password strength per item (Sentinel), for sorting and filtering by it. */
  levels?: Record<string, number>;
}

/** The items `view` shows, matching `search`; `only`, when given, limits
 * them to those ids (Sentinel's lists). */
export function filterItems(
  items: ItemSummary[],
  view: View,
  search: string,
  order: ListOrder = { sort: "title", desc: false },
  only?: Set<string>,
  extras: ListExtras = {},
): ItemSummary[] {
  const f = extras.filters ?? {};
  const q = search.trim().toLowerCase();
  const filtered = items.filter((item) => {
    if (only && !only.has(item.id)) return false;
    if (view.kind === "trash") {
      if (item.trashedAt === null) return false;
    } else {
      if (item.trashedAt !== null) return false;
      if (view.kind === "archive") {
        if (!item.archived) return false;
      } else if (item.archived) {
        return false;
      }
    }
    switch (view.kind) {
      case "favorites":
        if (!item.favorite) return false;
        break;
      case "vault":
        if (item.vaultId !== view.id) return false;
        break;
      case "category":
        if (item.category !== view.category) return false;
        break;
      case "tag":
        if (!item.tags.some((t) => t === view.tag || t.startsWith(`${view.tag}/`))) return false;
        break;
    }
    if (f.category && item.category !== f.category) return false;
    if (f.vault && item.vaultId !== f.vault) return false;
    if (f.tag && !item.tags.some((t) => t === f.tag || t.startsWith(`${f.tag}/`))) return false;
    if (f.untagged && item.tags.length > 0) return false;
    if (f.passkey && !extras.passkeyItems?.has(item.id)) return false;
    if (f.strength !== undefined && extras.levels?.[item.id] !== f.strength) return false;
    if (!q) return true;
    return (
      item.title.toLowerCase().includes(q) ||
      item.subtitle.toLowerCase().includes(q) ||
      item.urls.some((u) => u.toLowerCase().includes(q)) ||
      item.tags.some((t) => t.toLowerCase().includes(q)) ||
      !!extras.detailMatches?.has(item.id)
    );
  });
  return sortItems(filtered, order, extras.levels);
}

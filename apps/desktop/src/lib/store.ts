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
    set({ view, selectedId: null, editing: null, past: [...past, here].slice(-HISTORY_LIMIT), future: [] });
  },
  setSearch: (search) => set({ search }),
  select: (selectedId, auto = false) => {
    const { view, selectedId: current, past } = get();
    if (auto || selectedId === current || current === null) return set({ selectedId });
    set({ selectedId, past: [...past, { view, selectedId: current }].slice(-HISTORY_LIMIT), future: [] });
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

function sortKey(item: ItemSummary, sort: ListSort): number {
  switch (sort) {
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

export function sortItems(items: ItemSummary[], { sort, desc }: ListOrder): ItemSummary[] {
  return [...items].sort((a, b) => {
    if (sort === "title") return desc ? byTitle(b, a) : byTitle(a, b);
    // Items never used stay at the end, whatever the direction.
    if (sort === "recent" && (a.lastUsedAt === null) !== (b.lastUsedAt === null)) return a.lastUsedAt === null ? 1 : -1;
    const diff = sortKey(a, sort) - sortKey(b, sort);
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

/** The items `view` shows, matching `search`; `only`, when given, limits
 * them to those ids (Sentinel's lists). */
export function filterItems(
  items: ItemSummary[],
  view: View,
  search: string,
  order: ListOrder = { sort: "title", desc: false },
  only?: Set<string>,
): ItemSummary[] {
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
    if (!q) return true;
    return (
      item.title.toLowerCase().includes(q) ||
      item.subtitle.toLowerCase().includes(q) ||
      item.urls.some((u) => u.toLowerCase().includes(q)) ||
      item.tags.some((t) => t.toLowerCase().includes(q))
    );
  });
  return sortItems(filtered, order);
}

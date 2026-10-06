import { create } from "zustand";

import i18n from "../i18n";
import { categoryLabel } from "./categories";
import { api, errorMessage, type AppStatus, type Category, type ItemDraft, type ItemSummary, type Settings, type SyncStatus, type Vault } from "./api";

export type View =
  | { kind: "all" }
  | { kind: "favorites" }
  | { kind: "vault"; id: string }
  | { kind: "category"; category: Category }
  | { kind: "tag"; tag: string }
  | { kind: "archive" }
  | { kind: "trash" }
  | { kind: "watchtower" };

export interface Editing {
  draft: ItemDraft;
  isNew: boolean;
}

interface AppStore {
  status: AppStatus | null;
  settings: Settings | null;
  syncStatus: SyncStatus | null;
  vaults: Vault[];
  items: ItemSummary[];
  view: View;
  search: string;
  selectedId: string | null;
  editing: Editing | null;
  /** Bumped to make the detail pane reload after a change. */
  revision: number;

  refreshStatus: () => Promise<AppStatus>;
  loadData: () => Promise<void>;
  loadSettings: () => Promise<void>;
  setSettings: (settings: Settings) => Promise<void>;
  setSyncStatus: (s: SyncStatus) => void;
  setView: (view: View) => void;
  setSearch: (search: string) => void;
  select: (id: string | null) => void;
  startEditing: (editing: Editing) => void;
  stopEditing: () => void;
  bump: () => void;
  reset: () => void;
}

export const useApp = create<AppStore>((set, get) => ({
  status: null,
  settings: null,
  syncStatus: null,
  vaults: [],
  items: [],
  view: { kind: "all" },
  search: "",
  selectedId: null,
  editing: null,
  revision: 0,

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
  setView: (view) => set({ view, selectedId: null, editing: null }),
  setSearch: (search) => set({ search }),
  select: (selectedId) => set({ selectedId }),
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
    case "watchtower":
      return i18n.t("sidebar.watchtower");
  }
}

export function filterItems(items: ItemSummary[], view: View, search: string): ItemSummary[] {
  const q = search.trim().toLowerCase();
  const filtered = items.filter((item) => {
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
  return filtered.sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: "base" }));
}

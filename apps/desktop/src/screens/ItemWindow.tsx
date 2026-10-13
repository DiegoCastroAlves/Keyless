// An item in a window of its own, kept above the others. Keyless closes
// these windows when it locks.

import { useEffect } from "react";

import { useActivityHeartbeat } from "../App";
import { Toaster } from "../components/common";
import { TooltipProvider } from "../components/ui";
import { applyLanguage } from "../i18n";
import { events } from "../lib/api";
import { useApp } from "../lib/store";
import { useDensity, useTheme } from "../lib/theme";
import { ItemDetail } from "./main/ItemDetail";
import { ItemEditor } from "./main/ItemEditor";

export function ItemWindow({ itemId }: { itemId: string }) {
  const settings = useApp((s) => s.settings);
  const editing = useApp((s) => s.editing);

  useTheme(settings?.theme);
  useDensity(settings?.density);
  useActivityHeartbeat(true);

  useEffect(() => {
    applyLanguage(settings?.language);
  }, [settings?.language]);

  useEffect(() => {
    const { loadSettings, loadData } = useApp.getState();
    void loadSettings();
    void loadData().then(() => useApp.getState().select(itemId, true));
    const subscriptions = [events.onItemsChanged(() => void useApp.getState().loadData())];
    return () => {
      subscriptions.forEach((p) => void p.then((unlisten) => unlisten()));
    };
  }, [itemId]);

  // No browser context menu outside text fields.
  useEffect(() => {
    const onContextMenu = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest("input, textarea, .selectable")) e.preventDefault();
    };
    window.addEventListener("contextmenu", onContextMenu);
    return () => window.removeEventListener("contextmenu", onContextMenu);
  }, []);

  return (
    <TooltipProvider>
      <div className="flex h-full bg-panel">{editing ? <ItemEditor key={editing.draft.id ?? "new"} /> : <ItemDetail />}</div>
      <Toaster />
    </TooltipProvider>
  );
}

import { useEffect } from "react";

import { Logo, Toaster } from "./components/common";
import { PairRequestDialog } from "./components/PairRequestDialog";
import { TooltipProvider } from "./components/ui";
import { applyLanguage } from "./i18n";
import { api, events } from "./lib/api";
import { useApp } from "./lib/store";
import { LockScreen } from "./screens/LockScreen";
import { MainLayout } from "./screens/main/MainLayout";
import { Onboarding } from "./screens/Onboarding";

function useTheme(theme: string | undefined) {
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      const dark = theme === "dark" || ((theme ?? "system") === "system" && media.matches);
      document.documentElement.classList.toggle("dark", dark);
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);
}

/** Tells the Rust side the user is active, for the auto-lock timer. */
function useActivityHeartbeat(enabled: boolean) {
  useEffect(() => {
    if (!enabled) return;
    let last = 0;
    const onActivity = () => {
      const now = Date.now();
      if (now - last > 15_000) {
        last = now;
        void api.heartbeat().catch(() => {});
      }
    };
    const kinds = ["keydown", "mousedown", "mousemove", "wheel"] as const;
    kinds.forEach((k) => window.addEventListener(k, onActivity, { passive: true }));
    return () => kinds.forEach((k) => window.removeEventListener(k, onActivity));
  }, [enabled]);
}

export function App() {
  const status = useApp((s) => s.status);
  const settings = useApp((s) => s.settings);
  const unlocked = status?.state === "unlocked";

  useTheme(settings?.theme);
  useActivityHeartbeat(unlocked);

  useEffect(() => {
    applyLanguage(settings?.language);
  }, [settings?.language]);

  useEffect(() => {
    const { refreshStatus, loadSettings, loadData, setSyncStatus, reset } = useApp.getState();
    void refreshStatus();
    void loadSettings();
    const subscriptions = [
      events.onLocked(() => {
        reset();
        void refreshStatus();
      }),
      events.onItemsChanged(() => void loadData()),
      events.onSyncStatus(setSyncStatus),
    ];
    return () => {
      subscriptions.forEach((p) => void p.then((unlisten) => unlisten()));
    };
  }, []);

  useEffect(() => {
    if (unlocked) {
      void useApp.getState().loadData();
      void api.syncStatus().then(useApp.getState().setSyncStatus);
    }
  }, [unlocked]);

  // No browser context menu outside text fields (it only offers reload/back).
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
      {!status ? (
        <div className="flex h-full items-center justify-center">
          <Logo className="size-14 animate-pulse" />
        </div>
      ) : status.state === "no_account" ? (
        <Onboarding key={status.pendingEmail ?? "new"} status={status} />
      ) : status.state === "locked" ? (
        <LockScreen status={status} />
      ) : (
        <MainLayout />
      )}
      <PairRequestDialog />
      <Toaster />
    </TooltipProvider>
  );
}

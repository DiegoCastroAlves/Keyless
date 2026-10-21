import { useEffect } from "react";
import { useTranslation } from "react-i18next";

import { Logo, Toaster } from "./components/common";
import { BrowserRequestDialog } from "./components/BrowserRequestDialog";
import { DeviceApprovalDialog } from "./components/DeviceApprovalDialog";
import { PairRequestDialog } from "./components/PairRequestDialog";
import { TooltipProvider } from "./components/ui";
import { applyLanguage } from "./i18n";
import { api, events } from "./lib/api";
import { showLinkedItem } from "./lib/itemLinks";
import { useApp } from "./lib/store";
import { useDensity, useTheme } from "./lib/theme";
import { LockScreen } from "./screens/LockScreen";
import { MainLayout } from "./screens/main/MainLayout";
import { Onboarding } from "./screens/Onboarding";

/** Tells the Rust side the user is active, for the auto-lock timer. */
export function useActivityHeartbeat(enabled: boolean) {
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

/** Shows the item a keyless:// link asked for, if any. */
async function takeItemRequest() {
  const request = await api.takeItemRequest().catch(() => null);
  if (request) showLinkedItem(request.id, request.edit);
}

export function App() {
  const status = useApp((s) => s.status);
  const settings = useApp((s) => s.settings);
  const unlocked = status?.state === "unlocked";

  useTheme(settings?.theme);
  useDensity(settings?.density);
  useActivityHeartbeat(unlocked);

  useEffect(() => {
    applyLanguage(settings?.language);
  }, [settings?.language]);

  // The tray menu is built in Rust with these translated texts.
  const { t, i18n } = useTranslation();
  useEffect(() => {
    void api.configureTray({ open: t("tray.open"), quickAccess: t("tray.quickAccess"), lock: t("common.lock"), quit: t("tray.quit") });
    void api.configureNotifications({
      sentinelTitle: t("sentinel.title"),
      // Plural forms with the number left for Rust to fill in.
      newAlertsOne: t("sentinel.newAlerts", { count: 1, n: "{count}" }),
      newAlertsOther: t("sentinel.newAlerts", { count: 2, n: "{count}" }),
      deviceSetupTitle: t("approve.notificationTitle"),
      deviceSetupBody: t("approve.notificationBody"),
    });
  }, [t, i18n.language]);

  useEffect(() => {
    const { refreshStatus, loadSettings, loadData, setSyncStatus, setUpdate, setInstall, reset } = useApp.getState();
    void refreshStatus();
    void loadSettings();
    void api.versionInfo().then((info) => {
      setUpdate(info.update);
      setInstall({ kind: info.install, needsPassword: info.needsPassword });
    });
    const subscriptions = [
      events.onLocked(() => {
        reset();
        void refreshStatus();
      }),
      events.onItemsChanged(() => void loadData()),
      events.onSyncStatus(setSyncStatus),
      events.onUpdateAvailable(setUpdate),
      // Unlocked from Quick Access.
      events.onUnlocked(() => void refreshStatus()),
      // "Open in Keyless" from Quick Access.
      // A notification from Sentinel was clicked.
      events.onOpenSentinel(() => {
        if (useApp.getState().status?.state === "unlocked") useApp.getState().setView({ kind: "sentinel" });
      }),
      // A keyless:// link: shown now, or once unlocked.
      events.onItemRequested(() => {
        if (useApp.getState().status?.state === "unlocked") void takeItemRequest();
      }),
      // Signed out from another device: the account's data is gone.
      events.onDeviceRevoked(() => {
        reset();
        useApp.setState({ deviceRevoked: true });
        void refreshStatus();
      }),
      // A keyless://setup link: the sign-in form takes it.
      events.onSetupReceived(() => void refreshStatus()),
      events.onAccountChanged(() => void refreshStatus()),
      events.onSelectItem((id) => {
        const store = useApp.getState();
        store.setSearch("");
        store.setView({ kind: "all" });
        store.select(id);
      }),
      // Kept for the vault to take (see MainLayout) and the pairing prompt.
      events.onNewItem((request) => useApp.setState({ newItemRequest: request })),
      events.onPairRequest((request) => useApp.setState({ pairRequest: request })),
      events.onBrowserRequest((request) => useApp.setState({ browserRequest: request })),
    ];
    // Listening: what waited for this window (made when shown) comes now.
    void Promise.all(subscriptions).then(() => api.mainReady());
    return () => {
      subscriptions.forEach((p) => void p.then((unlisten) => unlisten()));
    };
  }, []);

  useEffect(() => {
    if (unlocked) {
      void useApp
        .getState()
        .loadData()
        .then(() => takeItemRequest());
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
      <BrowserRequestDialog />
      {unlocked && <DeviceApprovalDialog />}
      <Toaster />
    </TooltipProvider>
  );
}

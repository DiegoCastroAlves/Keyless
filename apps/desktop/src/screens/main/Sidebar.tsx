import {
  Archive,
  ArrowRightLeft,
  ChevronDown,
  CircleArrowUp,
  Cloud,
  CloudOff,
  Download,
  Ellipsis,
  LayoutGrid,
  Lock,
  LogOut,
  Pencil,
  Plus,
  RefreshCw,
  Settings as SettingsIcon,
  Share2,
  ShieldCheck,
  Star,
  Tag,
  Trash,
  TriangleAlert,
  Upload,
  LockKeyhole as VaultIcon,
  WandSparkles,
} from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { Logo } from "../../components/common";
import { Button, Dialog, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger, cx } from "../../components/ui";
import { api, errorMessage, type Vault } from "../../lib/api";
import { CATEGORIES, categoryLabel } from "../../lib/categories";
import { relativeTime } from "../../lib/format";
import { useApp, type View } from "../../lib/store";
import { toast } from "../../lib/toast";
import { MoveVaultDialog } from "./MoveDialog";
import { SharesDialog } from "./SharesDialog";
import { UpdateDialog, useUpdateAction } from "./UpdateDialog";

function sameView(a: View, b: View): boolean {
  if (a.kind !== b.kind) return false;
  switch (a.kind) {
    case "vault":
      return a.id === (b as typeof a).id;
    case "category":
      return a.category === (b as typeof a).category;
    case "tag":
      return a.tag === (b as typeof a).tag;
    default:
      return true;
  }
}

function NavItem({
  icon,
  label,
  count,
  view,
  actions,
}: {
  icon: ReactNode;
  label: string;
  count?: number;
  view: View;
  actions?: ReactNode;
}) {
  const current = useApp((s) => s.view);
  const setView = useApp((s) => s.setView);
  const active = sameView(current, view);
  return (
    <div className="group relative">
      <button
        onClick={() => setView(view)}
        className={cx(
          "flex h-8 w-full items-center gap-2.5 rounded-lg px-2.5 text-left text-[13px] transition-colors",
          active ? "bg-accent-soft font-medium text-accent" : "text-fg/85 hover:bg-panel-3",
        )}
      >
        <span className={cx("flex size-4 items-center justify-center", active ? "text-accent" : "text-muted")}>{icon}</span>
        <span className="flex-1 truncate">{label}</span>
        {count !== undefined && count > 0 && (
          <span className={cx("text-xs tabular-nums", active ? "text-accent" : "text-subtle", actions && "group-hover:invisible group-focus-within:invisible group-has-[[data-state=open]]:invisible")}>{count}</span>
        )}
      </button>
      {/* Hidden with opacity, not display: the open menu stays anchored to its button. */}
      {actions && (
        <div className="pointer-events-none absolute right-1 top-1/2 -translate-y-1/2 opacity-0 group-hover:pointer-events-auto group-hover:opacity-100 group-focus-within:pointer-events-auto group-focus-within:opacity-100 has-[[data-state=open]]:pointer-events-auto has-[[data-state=open]]:opacity-100">
          {actions}
        </div>
      )}
    </div>
  );
}

function SectionHeader({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-1 mt-5 flex h-6 items-center justify-between px-2.5">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-subtle">{children}</span>
      {action}
    </div>
  );
}

export function Sidebar({
  onOpenSettings,
  onOpenGenerator,
  onOpenImport,
  onOpenExport,
  onEditVault,
}: {
  onOpenSettings: () => void;
  onOpenGenerator: () => void;
  onOpenImport: () => void;
  onOpenExport: () => void;
  onEditVault: (vault: Vault | null) => void;
}) {
  const status = useApp((s) => s.status);
  const vaults = useApp((s) => s.vaults);
  const items = useApp((s) => s.items);
  const refreshStatus = useApp((s) => s.refreshStatus);
  const loadData = useApp((s) => s.loadData);
  const [deleting, setDeleting] = useState<Vault | null>(null);
  const [sharesOpen, setSharesOpen] = useState(false);
  const [moving, setMoving] = useState<Vault | null>(null);
  const { t } = useTranslation();

  const active = useMemo(() => items.filter((i) => i.trashedAt === null && !i.archived), [items]);
  const counts = useMemo(() => {
    const byCategory = new Map<string, number>();
    const byTag = new Map<string, number>();
    for (const item of active) {
      byCategory.set(item.category, (byCategory.get(item.category) ?? 0) + 1);
      for (const tag of item.tags) {
        const top = tag.split("/")[0];
        byTag.set(top, (byTag.get(top) ?? 0) + 1);
      }
    }
    return { byCategory, byTag };
  }, [active]);
  const archived = items.filter((i) => i.archived && i.trashedAt === null).length;
  const trashed = items.filter((i) => i.trashedAt !== null).length;
  const favorites = active.filter((i) => i.favorite).length;

  const lock = async () => {
    await api.lock();
    await refreshStatus();
  };

  const signOut = async () => {
    await api.signOut();
    await refreshStatus();
  };

  const deleteVault = async () => {
    if (!deleting) return;
    try {
      await api.deleteVault(deleting.id);
      toast.success(t("sidebar.vaultDeleted", { name: deleting.name }));
      useApp.getState().setView({ kind: "all" });
      await loadData();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setDeleting(null);
    }
  };

  const syncNow = async () => {
    try {
      await api.syncNow();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const email = status?.email ?? "";

  return (
    <aside className="flex h-full w-full flex-col border-r border-line bg-app">
      <div className="p-3 pb-1">
        <Menu>
          <MenuTrigger asChild>
            <button className="flex w-full items-center gap-2.5 rounded-xl p-2 text-left hover:bg-panel-3">
              <Logo className="size-8" />
              <div className="min-w-0 flex-1">
                <div className="text-[13px] font-semibold leading-tight">Keyless</div>
                <div className="truncate text-xs text-muted">{email}</div>
              </div>
              <ChevronDown className="size-4 text-subtle" />
            </button>
          </MenuTrigger>
          <MenuContent align="start">
            <MenuItem icon={<SettingsIcon className="size-4" />} onSelect={onOpenSettings} shortcut="Ctrl ,">
              {t("common.settings")}
            </MenuItem>
            <MenuItem icon={<WandSparkles className="size-4" />} onSelect={onOpenGenerator} shortcut="Ctrl G">
              {t("sidebar.generator")}
            </MenuItem>
            <MenuItem icon={<Download className="size-4" />} onSelect={onOpenImport}>
              {t("sidebar.import")}
            </MenuItem>
            <MenuItem icon={<Upload className="size-4" />} onSelect={onOpenExport}>
              {t("sidebar.export")}
            </MenuItem>
            <MenuItem icon={<Share2 className="size-4" />} onSelect={() => setSharesOpen(true)}>
              {t("share.listTitle")}
            </MenuItem>
            <MenuSeparator />
            <MenuItem icon={<Lock className="size-4" />} onSelect={lock} shortcut="Ctrl L">
              {t("common.lock")}
            </MenuItem>
            <MenuItem icon={<LogOut className="size-4" />} onSelect={signOut} danger>
              {t("common.signOutDevice")}
            </MenuItem>
          </MenuContent>
        </Menu>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 pb-3">
        <div className="space-y-0.5">
          <NavItem icon={<LayoutGrid className="size-4" />} label={t("sidebar.allItems")} count={active.length} view={{ kind: "all" }} />
          <NavItem icon={<Star className="size-4" />} label={t("sidebar.favorites")} count={favorites} view={{ kind: "favorites" }} />
          <NavItem icon={<ShieldCheck className="size-4" />} label={t("sidebar.watchtower")} view={{ kind: "watchtower" }} />
        </div>

        <SectionHeader
          action={
            <button
              onClick={() => onEditVault(null)}
              className="flex size-5 items-center justify-center rounded text-subtle hover:bg-panel-3 hover:text-fg"
              aria-label={t("sidebar.newVault")}
              title={t("sidebar.newVault")}
            >
              <Plus className="size-3.5" />
            </button>
          }
        >
          {t("sidebar.vaults")}
        </SectionHeader>
        <div className="space-y-0.5">
          {vaults.map((vault) => (
            <NavItem
              key={vault.id}
              icon={vault.orphaned ? <TriangleAlert className="size-4 text-warning" /> : <VaultIcon className="size-4" />}
              label={vault.orphaned ? `${vault.name} · ${t("sidebar.orphaned")}` : vault.name}
              count={vault.itemCount}
              view={{ kind: "vault", id: vault.id }}
              actions={
                vault.role === "owner" ? (
                  <Menu>
                    <MenuTrigger asChild>
                      <button className="flex size-6 items-center justify-center rounded text-muted hover:bg-panel hover:text-fg" aria-label={t("sidebar.vaultOptions")}>
                        <Ellipsis className="size-4" />
                      </button>
                    </MenuTrigger>
                    <MenuContent>
                      <MenuItem icon={<Pencil className="size-4" />} onSelect={() => onEditVault(vault)}>
                        {t("sidebar.renameVault")}
                      </MenuItem>
                      <MenuItem icon={<ArrowRightLeft className="size-4" />} onSelect={() => setMoving(vault)} disabled={vault.itemCount === 0}>
                        {t("move.vaultAction")}
                      </MenuItem>
                      <MenuItem icon={<Trash className="size-4" />} onSelect={() => setDeleting(vault)} danger disabled={vaults.length <= 1}>
                        {t("sidebar.deleteVault")}
                      </MenuItem>
                    </MenuContent>
                  </Menu>
                ) : undefined
              }
            />
          ))}
        </div>

        {counts.byCategory.size > 0 && (
          <>
            <SectionHeader>{t("sidebar.categories")}</SectionHeader>
            <div className="space-y-0.5">
              {CATEGORIES.filter((c) => counts.byCategory.has(c.id)).map((c) => (
                <NavItem
                  key={c.id}
                  icon={<c.icon className="size-4" />}
                  label={categoryLabel(c.id, true)}
                  count={counts.byCategory.get(c.id)}
                  view={{ kind: "category", category: c.id }}
                />
              ))}
            </div>
          </>
        )}

        {counts.byTag.size > 0 && (
          <>
            <SectionHeader>{t("sidebar.tags")}</SectionHeader>
            <div className="space-y-0.5">
              {[...counts.byTag.entries()]
                .sort((a, b) => a[0].localeCompare(b[0]))
                .map(([tag, count]) => (
                  <NavItem key={tag} icon={<Tag className="size-4" />} label={tag} count={count} view={{ kind: "tag", tag }} />
                ))}
            </div>
          </>
        )}

        <div className="mt-5 space-y-0.5 border-t border-line pt-3">
          <NavItem icon={<Archive className="size-4" />} label={t("sidebar.archive")} count={archived} view={{ kind: "archive" }} />
          <NavItem icon={<Trash className="size-4" />} label={t("sidebar.trash")} count={trashed} view={{ kind: "trash" }} />
        </div>
      </nav>

      <div className="flex items-center border-t border-line">
        <button
          onClick={syncNow}
          className="flex min-w-0 flex-1 items-center gap-2 px-5 py-2.5 text-left text-xs text-muted hover:text-fg"
          title={t("sync.syncNow")}
        >
          <SyncIndicator />
        </button>
        <UpdateBadge />
      </div>

      <MoveVaultDialog vault={moving} onOpenChange={(open) => !open && setMoving(null)} />
      <SharesDialog open={sharesOpen} onOpenChange={setSharesOpen} />

      <Dialog
        open={!!deleting}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={t("sidebar.deleteVaultTitle", { name: deleting?.name })}
        description={t("sidebar.deleteVaultBody")}
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setDeleting(null)}>{t("common.cancel")}</Button>
          <Button variant="danger" onClick={deleteVault}>
            {t("sidebar.deleteVault")}
          </Button>
        </div>
      </Dialog>
    </aside>
  );
}

function UpdateBadge() {
  const update = useApp((s) => s.update);
  const enabled = useApp((s) => s.settings?.check_updates ?? true);
  const action = useUpdateAction();
  const { t } = useTranslation();
  if (!update || !enabled) return null;
  return (
    <>
      <button
        onClick={action.start}
        title={t("update.tooltip", { version: update.version })}
        className="mr-3 flex shrink-0 items-center gap-1 rounded-full bg-accent-soft px-2 py-0.5 text-[11px] font-medium text-accent hover:opacity-80"
      >
        <CircleArrowUp className="size-3" />
        {t("update.available")}
      </button>
      <UpdateDialog open={action.open} onOpenChange={action.setOpen} />
    </>
  );
}

function SyncIndicator() {
  const syncStatus = useApp((s) => s.syncStatus);
  const { t } = useTranslation();
  const state = syncStatus?.state || "idle";
  if (state === "syncing") {
    return (
      <>
        <RefreshCw className="size-3.5 animate-spin text-accent" /> {t("sync.syncing")}
      </>
    );
  }
  if (state === "offline") {
    return (
      <>
        <CloudOff className="size-3.5 text-warning" /> {t("sync.offline")}
      </>
    );
  }
  if (state === "error" || state === "signed_out") {
    return (
      <>
        <TriangleAlert className="size-3.5 text-danger" /> {state === "signed_out" ? t("sync.signedOut") : t("sync.failed")}
      </>
    );
  }
  return (
    <>
      <Cloud className="size-3.5 text-success" /> {t("sync.synced", { when: relativeTime(syncStatus?.last_synced_at ?? null) })}
    </>
  );
}

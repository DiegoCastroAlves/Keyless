import { Archive, ArrowRightLeft, Copy, Ellipsis, ExternalLink, Eye, EyeOff, History, Pencil, RotateCcw, Star, Trash } from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { ItemIcon, PasswordText } from "../../components/common";
import { Button, Dialog, IconButton, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger, Tooltip, cx } from "../../components/ui";
import { fieldLabel } from "../../i18n";
import { api, errorMessage, type FieldView, type HistoryEntry, type ItemDetail as Detail, type TotpCode, type UrlFill } from "../../lib/api";
import { categoryLabel, isSecretKind } from "../../lib/categories";
import { formatDate, formatTotp, hostOf } from "../../lib/format";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { ItemVersionsDialog } from "./ItemVersions";
import { MoveItemsDialog } from "./MoveDialog";

export function ItemDetail() {
  const { t } = useTranslation();
  const selectedId = useApp((s) => s.selectedId);
  const revision = useApp((s) => s.revision);
  const vaults = useApp((s) => s.vaults);
  const loadData = useApp((s) => s.loadData);
  const startEditing = useApp((s) => s.startEditing);
  const [item, setItem] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [versionsOpen, setVersionsOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    if (!selectedId) {
      setItem(null);
      return;
    }
    api
      .getItem(selectedId)
      .then((detail) => !cancelled && setItem(detail))
      .catch((err) => !cancelled && setError(errorMessage(err)));
    return () => {
      cancelled = true;
    };
  }, [selectedId, revision]);

  const edit = useCallback(async () => {
    if (!item?.canEdit) return;
    try {
      const draft = await api.getItemDraft(item.id);
      startEditing({ draft, isNew: false });
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }, [item, startEditing]);

  // Ctrl+E edits the selected item.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "e" && item && item.trashedAt === null) {
        e.preventDefault();
        void edit();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [edit, item]);

  if (!selectedId || (!item && !error)) {
    return <EmptyDetail />;
  }
  if (error || !item) {
    return <div className="flex flex-1 items-center justify-center p-10 text-sm text-danger">{error}</div>;
  }

  const vault = vaults.find((v) => v.id === item.vaultId);
  const trashed = item.trashedAt !== null;

  const run = async (fn: () => Promise<unknown>, success?: string) => {
    try {
      await fn();
      if (success) toast.success(success);
      await loadData();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <section className="flex min-w-0 flex-1 flex-col bg-panel">
      <header className="flex items-start gap-4 border-b border-line px-8 pb-5 pt-7">
        <ItemIcon title={item.title} category={item.category} url={item.urls[0]} size="lg" />
        <div className="min-w-0 flex-1 pt-1">
          <h2 className="selectable truncate text-xl font-semibold tracking-tight">{item.title}</h2>
          <div className="mt-1 flex flex-wrap items-center gap-x-1.5 text-[13px] text-muted">
            <span>{categoryLabel(item.category)}</span>
            {vault && (
              <>
                <span className="text-subtle">·</span>
                <span>{t("item.inVault", { vault: vault.name })}</span>
              </>
            )}
            {!item.canEdit && <span className="ml-1 rounded bg-panel-3 px-1.5 text-[11px]">{t("item.readOnly")}</span>}
          </div>
        </div>
        <div className="flex items-center gap-1">
          {trashed ? (
            <>
              <Button size="sm" onClick={() => run(() => api.restoreItem(item.id), t("item.restored"))}>
                <RotateCcw className="size-3.5" /> {t("common.restore")}
              </Button>
              <Button size="sm" variant="danger" onClick={() => setConfirmDelete(true)} title={t("item.deletePermanently")}>
                <Trash className="size-3.5" /> {t("common.delete")}
              </Button>
            </>
          ) : (
            <>
              <IconButton
                label={item.favorite ? t("item.unfavorite") : t("item.favorite")}
                onClick={() => run(() => api.setFavorite(item.id, !item.favorite))}
                disabled={!item.canEdit}
              >
                <Star className={cx("size-[18px]", item.favorite && "fill-amber-400 text-amber-400")} />
              </IconButton>
              {item.canEdit && (
                <Button size="sm" onClick={edit} title="Ctrl E">
                  <Pencil className="size-3.5" /> {t("common.edit")}
                </Button>
              )}
              <Menu>
                <MenuTrigger asChild>
                  <IconButton label={t("common.more")}>
                    <Ellipsis className="size-[18px]" />
                  </IconButton>
                </MenuTrigger>
                <MenuContent>
                  <MenuItem
                    icon={<Archive className="size-4" />}
                    disabled={!item.canEdit}
                    onSelect={() => run(() => api.setArchived(item.id, !item.archived), item.archived ? undefined : t("item.archived"))}
                  >
                    {item.archived ? t("item.unarchive") : t("item.archive")}
                  </MenuItem>
                  <MenuItem icon={<ArrowRightLeft className="size-4" />} disabled={!item.canEdit} onSelect={() => setMoveOpen(true)}>
                    {t("move.toVaultAction")}
                  </MenuItem>
                  <MenuItem icon={<History className="size-4" />} onSelect={() => setVersionsOpen(true)}>
                    {t("itemHistory.title")}
                  </MenuItem>
                  <MenuSeparator />
                  <MenuItem
                    icon={<Trash className="size-4" />}
                    danger
                    disabled={!item.canEdit}
                    onSelect={() => run(() => api.trashItem(item.id), t("item.movedToTrash"))}
                  >
                    {t("item.moveToTrash")}
                  </MenuItem>
                </MenuContent>
              </Menu>
            </>
          )}
        </div>
      </header>

      <MoveItemsDialog open={moveOpen} onOpenChange={setMoveOpen} itemIds={[item.id]} fromVaultId={item.vaultId} />
      <ItemVersionsDialog itemId={item.id} canEdit={item.canEdit} open={versionsOpen} onOpenChange={setVersionsOpen} onRestored={() => void loadData()} />

      <div className="flex-1 overflow-y-auto px-8 py-6">
        <div className="mx-auto max-w-2xl space-y-5">
          {item.fields.some((f) => f.hasValue) && (
            <FieldCard>
              {item.fields.map((f) => (
                <FieldRow key={f.id} itemId={item.id} field={f} />
              ))}
            </FieldCard>
          )}

          {item.sections.map((section) =>
            !section.fields.some((f) => f.hasValue) ? null : (
              <div key={section.id}>
                {section.title && <h3 className="mb-2 px-1 text-xs font-semibold uppercase tracking-wider text-subtle">{section.title}</h3>}
                <FieldCard>
                  {section.fields.map((f) => (
                    <FieldRow key={f.id} itemId={item.id} field={f} />
                  ))}
                </FieldCard>
              </div>
            ),
          )}

          {item.urlEntries.length > 0 && (
            <FieldCard>
              {item.urlEntries.map((u, index) => (
                <WebsiteRow key={`${u.href}-${index}`} itemId={item.id} index={index} href={u.href} label={u.label} fill={u.fill} />
              ))}
            </FieldCard>
          )}

          {item.notes && (
            <FieldCard>
              <div className="px-4 py-3">
                <div className="text-xs font-medium text-subtle">{t("item.notes")}</div>
                <p className="selectable mt-1 whitespace-pre-wrap break-words text-sm leading-relaxed">{item.notes}</p>
              </div>
            </FieldCard>
          )}

          {item.tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5 px-1">
              {item.tags.map((tag) => (
                <button
                  key={tag}
                  onClick={() => useApp.getState().setView({ kind: "tag", tag: tag.split("/")[0] })}
                  className="rounded-full bg-panel-3 px-2.5 py-0.5 text-xs font-medium text-muted hover:text-fg"
                >
                  {tag}
                </button>
              ))}
            </div>
          )}

          <div className="space-y-0.5 px-1 pt-2 text-xs text-subtle">
            {item.passwordHistoryCount > 0 && (
              <button onClick={() => setHistoryOpen(true)} className="mb-2 block font-medium text-accent hover:underline">
                {t("item.history", { count: item.passwordHistoryCount })}
              </button>
            )}
            <div>{t("item.modified", { date: formatDate(item.updatedAt) })}</div>
            <div>{t("item.created", { date: formatDate(item.createdAt) })}</div>
          </div>
        </div>
      </div>

      <PasswordHistoryDialog itemId={item.id} open={historyOpen} onOpenChange={setHistoryOpen} />

      <Dialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={t("item.deleteTitle", { title: item.title })}
        description={t("item.deleteBody")}
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setConfirmDelete(false)}>{t("common.cancel")}</Button>
          <Button
            variant="danger"
            onClick={() => {
              setConfirmDelete(false);
              void run(() => api.deleteItemsPermanently([item.id]));
            }}
          >
            {t("item.deletePermanently")}
          </Button>
        </div>
      </Dialog>
    </section>
  );
}

function EmptyDetail() {
  const { t } = useTranslation();
  return (
    <section className="flex flex-1 flex-col items-center justify-center bg-panel text-center">
      <div className="text-sm text-subtle">{t("item.selectPrompt")}</div>
    </section>
  );
}

function FieldCard({ children }: { children: ReactNode }) {
  return <div className="divide-y divide-line overflow-hidden rounded-xl border border-line">{children}</div>;
}

function FieldRow({ itemId, field }: { itemId: string; field: FieldView }) {
  const { t } = useTranslation();
  const [revealed, setRevealed] = useState<string | null>(null);
  const secret = isSecretKind(field);
  const label = fieldLabel(field.label) || t("item.value");

  // Hide revealed values again after a while or when switching items.
  useEffect(() => {
    if (revealed === null) return;
    const handle = setTimeout(() => setRevealed(null), 30_000);
    return () => clearTimeout(handle);
  }, [revealed]);
  useEffect(() => setRevealed(null), [itemId, field.id]);

  if (!field.hasValue) return null;

  const copy = async () => {
    try {
      const result = await api.copyField(itemId, field.id);
      toast.copied(label, result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const toggleReveal = async () => {
    if (revealed !== null) {
      setRevealed(null);
      return;
    }
    try {
      setRevealed(await api.revealField(itemId, field.id));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  let value: ReactNode;
  if (field.kind === "totp") {
    value = <TotpValue itemId={itemId} fieldId={field.id} />;
  } else if (secret) {
    value =
      revealed !== null ? (
        field.purpose === "password" || field.kind === "concealed" ? (
          <PasswordText value={revealed} className="text-[15px]" />
        ) : (
          <span className="selectable whitespace-pre-wrap break-all font-mono text-[15px]">{revealed}</span>
        )
      ) : (
        <span className="text-[15px] tracking-[0.2em] text-muted">••••••••••••</span>
      );
  } else {
    value = (
      <span className={cx("selectable break-words text-[15px]", field.kind === "multiline" && "whitespace-pre-wrap")}>{field.value}</span>
    );
  }

  return (
    <div className="group flex items-center gap-3 px-4 py-2.5 hover:bg-panel-2">
      <button onClick={copy} className="min-w-0 flex-1 text-left" title={t("item.clickToCopy")}>
        <div className="text-xs font-medium text-subtle">{label}</div>
        <div className="mt-0.5 min-h-6">{value}</div>
      </button>
      <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
        {secret && field.kind !== "totp" && (
          <Tooltip content={revealed !== null ? t("item.conceal") : t("item.reveal")}>
            <IconButton label={revealed !== null ? t("item.conceal") : t("item.reveal")} onClick={toggleReveal}>
              {revealed !== null ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
            </IconButton>
          </Tooltip>
        )}
        <Tooltip content={t("common.copy")}>
          <IconButton label={t("common.copy")} onClick={copy}>
            <Copy className="size-4" />
          </IconButton>
        </Tooltip>
      </div>
    </div>
  );
}

function TotpValue({ itemId, fieldId }: { itemId: string; fieldId: string }) {
  const { t } = useTranslation();
  const [totp, setTotp] = useState<TotpCode | null>(null);
  const [remaining, setRemaining] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const load = async () => {
      try {
        const code = await api.getTotp(itemId, fieldId);
        if (cancelled) return;
        setTotp(code);
        setRemaining(code.remaining);
        timer = setTimeout(load, code.remaining * 1000 + 50);
      } catch {
        if (!cancelled) setTotp(null);
      }
    };
    void load();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [itemId, fieldId]);

  useEffect(() => {
    const tick = setInterval(() => setRemaining((r) => Math.max(0, r - 1)), 1000);
    return () => clearInterval(tick);
  }, []);

  if (!totp) return <span className="text-muted">—</span>;
  const fraction = totp.period ? remaining / totp.period : 0;
  const urgent = remaining <= 5;
  return (
    <span className="flex items-center gap-3">
      <span className={cx("selectable font-mono text-[17px] font-semibold tracking-wider", urgent ? "text-danger" : "text-accent")}>
        {formatTotp(totp.code)}
      </span>
      <span className="relative size-5" title={t("item.expiresIn", { seconds: remaining })}>
        <svg viewBox="0 0 20 20" className="size-5 -rotate-90">
          <circle cx="10" cy="10" r="8" fill="none" stroke="var(--border)" strokeWidth="2.5" />
          <circle
            cx="10"
            cy="10"
            r="8"
            fill="none"
            stroke={urgent ? "var(--danger)" : "var(--accent)"}
            strokeWidth="2.5"
            strokeDasharray={`${fraction * 50.27} 50.27`}
            strokeLinecap="round"
            style={{ transition: "stroke-dasharray 1s linear" }}
          />
        </svg>
      </span>
      <span className="text-xs tabular-nums text-subtle">{remaining}s</span>
    </span>
  );
}

function WebsiteRow({ itemId, index, href, label, fill }: { itemId: string; index: number; href: string; label?: string; fill?: UrlFill }) {
  const { t } = useTranslation();
  const open = async () => {
    try {
      await api.openItemUrl(itemId, index);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  const copy = async () => {
    try {
      const result = await api.copyText(href);
      toast.copied(t("item.website"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <div className="group flex items-center gap-3 px-4 py-2.5 hover:bg-panel-2">
      <button onClick={open} className="min-w-0 flex-1 text-left">
        <div className="text-xs font-medium text-subtle">{label || t("item.website")}</div>
        <div className="mt-0.5 truncate text-[15px] text-accent">{hostOf(href)}</div>
        {fill && fill !== "domain" && <div className="mt-0.5 text-xs text-subtle">{t(`editor.fill.${fill}`)}</div>}
      </button>
      <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
        <Tooltip content={t("item.openWebsite")}>
          <IconButton label={t("item.openWebsite")} onClick={open}>
            <ExternalLink className="size-4" />
          </IconButton>
        </Tooltip>
        <Tooltip content={t("common.copy")}>
          <IconButton label={t("common.copy")} onClick={copy}>
            <Copy className="size-4" />
          </IconButton>
        </Tooltip>
      </div>
    </div>
  );
}

function PasswordHistoryDialog({ itemId, open, onOpenChange }: { itemId: string; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [visible, setVisible] = useState<number | null>(null);

  useEffect(() => {
    if (!open) {
      setEntries(null);
      setVisible(null);
      return;
    }
    api.passwordHistory(itemId).then(setEntries).catch((err) => toast.error(errorMessage(err)));
  }, [open, itemId]);

  const copy = async (value: string) => {
    try {
      const result = await api.copyText(value);
      toast.copied(t("item.password"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("item.historyTitle")}>
      {entries && entries.length === 0 && <p className="text-sm text-muted">{t("item.historyEmpty")}</p>}
      <div className="divide-y divide-line overflow-hidden rounded-xl border border-line">
        {entries?.map((entry, i) => (
          <div key={i} className="flex items-center gap-2 px-3 py-2">
            <div className="min-w-0 flex-1">
              {visible === i ? (
                <PasswordText value={entry.value} className="text-sm" />
              ) : (
                <span className="tracking-[0.2em] text-muted">••••••••••</span>
              )}
              <div className="text-xs text-subtle">{t("item.changedOn", { date: formatDate(entry.changedAt) })}</div>
            </div>
            <IconButton label={visible === i ? t("item.conceal") : t("item.reveal")} onClick={() => setVisible(visible === i ? null : i)}>
              {visible === i ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
            </IconButton>
            <IconButton label={t("common.copy")} onClick={() => copy(entry.value)}>
              <Copy className="size-4" />
            </IconButton>
          </div>
        ))}
      </div>
    </Dialog>
  );
}

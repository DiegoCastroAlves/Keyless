import {
  Archive,
  ArrowRightLeft,
  Braces,
  Copy,
  CopyPlus,
  Download,
  Ellipsis,
  ExternalLink,
  Eye,
  EyeOff,
  FileText,
  Fingerprint,
  FolderInput,
  History,
  Link2,
  Maximize2,
  Paperclip,
  Pencil,
  PictureInPicture2,
  Pin,
  Printer,
  QrCode,
  RotateCcw,
  Share2,
  Star,
  TextCursorInput,
  Trash,
} from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { ItemIcon, PasswordText, StrengthBadge } from "../../components/common";
import { Button, Dialog, IconButton, Input, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger, Tooltip, cx } from "../../components/ui";
import { fieldLabel } from "../../i18n";
import {
  api,
  errorCode,
  errorMessage,
  events,
  type AttachmentProgress,
  type AttachmentSpace,
  type AttachmentView,
  type FieldView,
  type HistoryEntry,
  type ItemDetail as Detail,
  type PasskeyView,
  type TotpCode,
  type UrlFill,
} from "../../lib/api";
import { categoryLabel, isSecretKind } from "../../lib/categories";
import { appOf, firstWebsite, formatBytes, formatDate, formatTotp, hostOf } from "../../lib/format";
import { useFileDrop } from "../../lib/fileDrop";
import { itemIdOfLink, itemLink, showLinkedItem } from "../../lib/itemLinks";
import { Markdown } from "../../lib/markdown";
import { useSentinel } from "../../lib/sentinel";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { itemWindowId } from "../../lib/windows";
import { AlertNote, SpecialActions, SpecialValue } from "./FieldKinds";
import { AttachmentPreviewDialog, CopyToVaultDialog, JwtDialog, LargeTypeDialog, NoteImage, PrintDialog, isJwt } from "./ItemExtras";
import { ItemVersionsDialog } from "./ItemVersions";
import { MoveItemsDialog } from "./MoveDialog";
import { ShareDialog } from "./ShareDialog";
import { SentinelBanners } from "./Sentinel";

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
  const [shareOpen, setShareOpen] = useState(false);
  const [copyOpen, setCopyOpen] = useState(false);
  const [printOpen, setPrintOpen] = useState(false);
  const [wifiOpen, setWifiOpen] = useState(false);
  const [preview, setPreview] = useState<AttachmentView | null>(null);

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

  const duplicate = useCallback(async () => {
    if (!item?.canEdit) return;
    try {
      const copy = await api.duplicateItem(item.id, t("item.copyTitle", { title: item.title }));
      await loadData();
      useApp.getState().select(copy.id);
      toast.success(t("item.duplicated"));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }, [item, loadData, t]);

  // Ctrl+E edits the selected item, Ctrl+D duplicates it; Ctrl+C copies its
  // password (with Shift its username, with Alt its code) when no text is
  // selected and no field has the focus.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || !item || item.trashedAt !== null) return;
      const key = e.key.toLowerCase();
      if (key === "e" && !e.shiftKey && !e.altKey) {
        e.preventDefault();
        void edit();
      } else if (key === "d" && !e.shiftKey && !e.altKey) {
        e.preventDefault();
        void duplicate();
      } else if (key === "c") {
        const target = e.target as HTMLElement | null;
        const typing = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
        if (typing || (window.getSelection()?.toString() ?? "") !== "" || document.querySelector("[role=dialog]")) return;
        e.preventDefault();
        const purpose = e.altKey ? "totp" : e.shiftKey ? "username" : "password";
        api
          .copyItemValue(item.id, purpose)
          .then((result) => toast.copied(t(purpose === "totp" ? "item.code" : `item.${purpose}`), result.clearAfterSeconds))
          .catch((err) => toast.error(errorMessage(err)));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [edit, duplicate, item, t]);

  // Files dropped on an item it can change are attached to it.
  const dragging = useFileDrop(!!item && item.canEdit && item.trashedAt === null, (files) => {
    if (!item) return;
    void api
      .attachmentAddPaths(
        item.id,
        files.map((f) => f.path),
      )
      .then(async () => {
        toast.success(t("item.attachmentsAdded", { count: files.length }));
        await loadData();
      })
      .catch((err) => toast.error(errorMessage(err)));
  });

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
      // Closing a file dialog is not an error.
      if (errorCode(err) !== "cancelled") toast.error(errorMessage(err));
    }
  };
  const attach = () =>
    run(async () => {
      const files = await api.attachmentPick();
      if (!files.length) return;
      await api.attachmentAddPaths(
        item.id,
        files.map((f) => f.path),
      );
      toast.success(t("item.attachmentsAdded", { count: files.length }));
    });

  return (
    <section className="relative flex min-w-0 flex-1 flex-col bg-panel">
      {dragging && (
        <div className="pointer-events-none absolute inset-3 z-20 flex items-center justify-center rounded-2xl border-2 border-dashed border-accent bg-panel/90">
          <div className="flex items-center gap-2.5 text-sm font-medium text-accent">
            <Paperclip className="size-5" /> {t("item.dropToAttach", { title: item.title })}
          </div>
        </div>
      )}
      <header className="flex items-start gap-4 border-b border-line px-8 pb-5 pt-7">
        <ItemIcon title={item.title} category={item.category} url={firstWebsite(item.urls)} size="lg" item={item} />
        <div className="min-w-0 flex-1 pt-1">
          <h2 className="selectable line-clamp-2 break-words text-xl font-semibold tracking-tight">{item.title}</h2>
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
                  {!itemWindowId && (
                    <MenuItem
                      icon={<PictureInPicture2 className="size-4" />}
                      onSelect={() => void api.openItemWindow(item.id).catch((err) => toast.error(errorMessage(err)))}
                    >
                      {t("item.openWindow")}
                    </MenuItem>
                  )}
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
                  <MenuItem icon={<CopyPlus className="size-4" />} disabled={!item.canEdit} onSelect={() => void duplicate()}>
                    {t("item.duplicate")}
                  </MenuItem>
                  <MenuItem icon={<FolderInput className="size-4" />} onSelect={() => setCopyOpen(true)}>
                    {t("copyToVault.menu")}
                  </MenuItem>
                  {item.category === "wireless_router" && (
                    <MenuItem icon={<QrCode className="size-4" />} onSelect={() => setWifiOpen(true)}>
                      {t("item.wifiQr")}
                    </MenuItem>
                  )}
                  <MenuItem
                    icon={<Link2 className="size-4" />}
                    onSelect={() =>
                      void api
                        .copyText(itemLink(item.id))
                        .then((result) => toast.copied(t("item.link"), result.clearAfterSeconds))
                        .catch((err) => toast.error(errorMessage(err)))
                    }
                  >
                    {t("item.copyLink")}
                  </MenuItem>
                  <MenuItem icon={<Printer className="size-4" />} onSelect={() => setPrintOpen(true)}>
                    {t("print.menu")}
                  </MenuItem>
                  <MenuItem icon={<Share2 className="size-4" />} onSelect={() => setShareOpen(true)}>
                    {t("share.action")}
                  </MenuItem>
                  <MenuItem icon={<Paperclip className="size-4" />} disabled={!item.canEdit} onSelect={() => void attach()}>
                    {t("item.attach")}
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
      <ShareDialog open={shareOpen} onOpenChange={setShareOpen} itemId={item.id} title={item.title} />
      <CopyToVaultDialog item={item} open={copyOpen} onOpenChange={setCopyOpen} />
      <PrintDialog item={item} open={printOpen} onOpenChange={setPrintOpen} />
      <LargeTypeDialog open={wifiOpen} onOpenChange={setWifiOpen} title={t("item.wifiQr")} value={null} qr={() => api.wifiQr(item.id)} />
      <AttachmentPreviewDialog itemId={item.id} attachment={preview} onClose={() => setPreview(null)} />
      <ItemVersionsDialog itemId={item.id} canEdit={item.canEdit} open={versionsOpen} onOpenChange={setVersionsOpen} onRestored={() => void loadData()} />

      <div className="flex-1 overflow-y-auto px-8 py-6">
        <div className="mx-auto max-w-2xl space-y-5">
          {!trashed && <SentinelBanners itemId={item.id} hasUrl={!!firstWebsite(item.urls)} canEdit={item.canEdit} />}
          {item.fields.some((f) => f.hasValue) && (
            <FieldCard>
              {item.fields.map((f) => (
                <FieldRow key={f.id} item={item} field={f} onPreview={setPreview} />
              ))}
            </FieldCard>
          )}

          {item.sections.map((section) =>
            !section.fields.some((f) => f.hasValue) ? null : (
              <div key={section.id}>
                {section.title && <h3 className="mb-2 px-1 text-xs font-semibold uppercase tracking-wider text-subtle">{section.title}</h3>}
                <FieldCard>
                  {section.fields.map((f) => (
                    <FieldRow key={f.id} item={item} field={f} onPreview={setPreview} />
                  ))}
                </FieldCard>
              </div>
            ),
          )}

          {item.urlEntries.some((u) => !appOf(u.href)) && (
            <FieldCard>
              {item.urlEntries.map((u, index) =>
                appOf(u.href) ? null : <WebsiteRow key={`${u.href}-${index}`} itemId={item.id} index={index} href={u.href} label={u.label} fill={u.fill} />,
              )}
            </FieldCard>
          )}

          {item.urlEntries.some((u) => appOf(u.href)) && (
            <FieldCard>
              {item.urlEntries.map((u, index) => {
                const app = appOf(u.href);
                return app ? <AppRow key={`${u.href}-${index}`} packageName={app} label={u.label} /> : null;
              })}
            </FieldCard>
          )}

          {(item.passkeys ?? []).length > 0 && (
            <FieldCard>
              {item.passkeys.map((passkey) => (
                <PasskeyRow key={passkey.credentialId} itemId={item.id} passkey={passkey} canEdit={item.canEdit} onDeleted={() => void loadData()} />
              ))}
            </FieldCard>
          )}

          <Attachments item={item} trashed={trashed} onAttach={attach} onChanged={() => void loadData()} onPreview={setPreview} />

          {item.notes && (
            <FieldCard>
              <div className="px-4 py-3">
                <div className="mb-1 text-xs font-medium text-subtle">{t("item.notes")}</div>
                <div className="selectable">
                  <Markdown
                    text={item.notes}
                    options={{
                      onLink: (url) => {
                        const linked = itemIdOfLink(url);
                        if (linked) showLinkedItem(linked);
                        else void api.openLink(url).catch((err) => toast.error(errorMessage(err)));
                      },
                      image: (name, alt) => {
                        const attachment = (item.attachments ?? []).find((a) => a.name === name || a.id === name);
                        return attachment ? <NoteImage itemId={item.id} attachment={attachment} alt={alt} /> : null;
                      },
                    }}
                  />
                </div>
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

function FieldRow({ item, field, onPreview }: { item: Detail; field: FieldView; onPreview: (attachment: AttachmentView) => void }) {
  const { t } = useTranslation();
  const itemId = item.id;
  const [revealed, setRevealed] = useState<string | null>(null);
  const [large, setLarge] = useState<string | null>(null);
  const [jwt, setJwt] = useState<string | null>(null);
  const secret = isSecretKind(field);
  const label = fieldLabel(field.label) || t("item.value");
  const level = useSentinel((s) => (field.purpose === "password" ? s.report?.levels[itemId] : undefined));

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

  // The value as text, when the page may have it: shown, or revealed.
  const plain = secret ? revealed : field.kind === "file" || field.kind === "reference" || field.kind === "sign_in_with" ? null : field.value;
  const showLarge = async () => {
    try {
      setLarge(secret ? (revealed ?? (await api.revealField(itemId, field.id))) : (field.value ?? ""));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  const tokenToDecode = item.category === "api_credential" || isJwt(plain) ? plain : null;

  let value: ReactNode = <SpecialValue field={field} attachments={item.attachments ?? []} onPreview={onPreview} />;
  if (["address", "sign_in_with", "location", "reference", "file"].includes(field.kind)) {
    // Shown by SpecialValue.
  } else if (field.kind === "totp") {
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
    <div className="group flex items-center gap-3 px-4 py-2.5 hover:bg-panel-2 compact:py-1.5">
      <button
        onClick={copy}
        className="min-w-0 flex-1 text-left"
        title={t("item.clickToCopy")}
        // A value on the page can be dragged into another app.
        draggable={plain !== null && plain !== ""}
        onDragStart={(e) => {
          if (plain) e.dataTransfer.setData("text/plain", plain);
        }}
      >
        <div className="flex items-center gap-2 text-xs font-medium text-subtle">
          {label}
          {level !== undefined && <StrengthBadge level={level} className="text-[11px]" />}
        </div>
        <div className="mt-0.5 min-h-6">{value}</div>
        {(field.kind === "date" || field.kind === "month_year") && <AlertNote field={field} />}
      </button>
      <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100">
        <SpecialActions itemId={itemId} field={field} attachments={item.attachments ?? []} />
        {tokenToDecode && isJwt(tokenToDecode) && (
          <Tooltip content={t("jwt.decode")}>
            <IconButton label={t("jwt.decode")} onClick={() => setJwt(tokenToDecode)}>
              <Braces className="size-4" />
            </IconButton>
          </Tooltip>
        )}
        {field.kind !== "totp" && field.kind !== "file" && field.kind !== "reference" && (
          <Tooltip content={t("largeType.show")}>
            <IconButton label={t("largeType.show")} onClick={() => void showLarge()}>
              <Maximize2 className="size-4" />
            </IconButton>
          </Tooltip>
        )}
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
      <LargeTypeDialog
        open={large !== null}
        onOpenChange={(open) => !open && setLarge(null)}
        title={label}
        value={large}
        qr={() => api.fieldQr(itemId, field.id)}
      />
      <JwtDialog token={jwt} onClose={() => setJwt(null)} />
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

/** The item's files, with what is uploading or downloading for it now and
 * how much space the account uses. */
function Attachments({
  item,
  trashed,
  onAttach,
  onChanged,
  onPreview,
}: {
  item: Detail;
  trashed: boolean;
  onAttach: () => Promise<void>;
  onChanged: () => void;
  onPreview: (attachment: AttachmentView) => void;
}) {
  const { t } = useTranslation();
  const [progress, setProgress] = useState<AttachmentProgress | null>(null);
  const [space, setSpace] = useState<AttachmentSpace | null>(null);
  const attachments = item.attachments ?? [];

  useEffect(() => {
    setProgress(null);
    const stop = events.onAttachmentProgress((p) => {
      if (p.itemId !== item.id) return;
      setProgress(p.done >= p.total ? null : p);
    });
    return () => void stop.then((f) => f());
  }, [item.id]);

  useEffect(() => {
    if (attachments.length === 0) return;
    api
      .attachmentSpace()
      .then(setSpace)
      .catch(() => setSpace(null));
  }, [attachments.length]);

  if (attachments.length === 0 && !progress) return null;
  const percent = progress && progress.total > 0 ? Math.floor((progress.done / progress.total) * 100) : 0;
  return (
    <FieldCard>
      <div className="flex items-center gap-2 px-4 pb-1 pt-3">
        <span className="flex-1 text-xs font-medium text-subtle">{t("item.attachments")}</span>
        {space && <span className="text-[11px] text-subtle">{t("item.attachmentSpace", { used: formatBytes(space.used), quota: formatBytes(space.quota) })}</span>}
      </div>
      {attachments.map((attachment) => (
        <AttachmentRow key={attachment.id} itemId={item.id} attachment={attachment} canEdit={item.canEdit && !trashed} onDeleted={onChanged} onPreview={() => onPreview(attachment)} />
      ))}
      {progress && (
        <div className="px-4 py-2.5">
          <div className="text-xs text-muted">
            {t(progress.direction === "upload" ? "item.attachmentUploading" : "item.attachmentDownloading", { name: progress.name, percent })}
          </div>
          <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-panel-3">
            <div className="h-full bg-accent transition-[width]" style={{ width: `${percent}%` }} />
          </div>
        </div>
      )}
      {item.canEdit && !trashed && !progress && (
        <div className="px-3 pb-2 pt-1">
          <Button size="sm" variant="ghost" onClick={() => void onAttach()}>
            <Paperclip className="size-3.5" /> {t("item.attach")}
          </Button>
        </div>
      )}
    </FieldCard>
  );
}

function AttachmentRow({
  itemId,
  attachment,
  canEdit,
  onDeleted,
  onPreview,
}: {
  itemId: string;
  attachment: AttachmentView;
  canEdit: boolean;
  onDeleted: () => void;
  onPreview: () => void;
}) {
  const { t } = useTranslation();
  const [confirming, setConfirming] = useState(false);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try {
      await api.attachmentSave(itemId, attachment.id);
      toast.success(t("item.attachmentSaved"));
    } catch (err) {
      if (errorCode(err) !== "cancelled") toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    try {
      await api.attachmentDelete(itemId, attachment.id);
      toast.success(t("item.attachmentDeleted"));
      onDeleted();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  const rename = async () => {
    if (renaming === null || !renaming.trim() || renaming === attachment.name) {
      setRenaming(null);
      return;
    }
    try {
      await api.attachmentRename(itemId, attachment.id, renaming);
      setRenaming(null);
      onDeleted();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <div className="group px-4 py-2.5">
      <div className="flex items-center gap-3">
        <FileText className="size-5 shrink-0 text-accent" />
        <div className="min-w-0 flex-1">
          {renaming !== null ? (
            <Input
              value={renaming}
              autoFocus
              onChange={(e) => setRenaming(e.target.value)}
              onBlur={() => void rename()}
              onKeyDown={(e) => {
                if (e.key === "Enter") void rename();
                else if (e.key === "Escape") {
                  e.preventDefault();
                  setRenaming(null);
                }
              }}
              className="h-8"
            />
          ) : (
            <button onClick={onPreview} className="selectable block max-w-full truncate text-left text-[15px] hover:text-accent">
              {attachment.name}
            </button>
          )}
          <div className="text-xs text-subtle">
            {formatBytes(attachment.size)}
            {attachment.createdAt > 0 && ` · ${formatDate(attachment.createdAt)}`}
          </div>
        </div>
        <IconButton label={t("item.attachmentPreview")} onClick={onPreview}>
          <Eye className="size-4" />
        </IconButton>
        <IconButton label={t("item.attachmentSave")} onClick={save} disabled={busy}>
          <Download className="size-4" />
        </IconButton>
        {canEdit && !confirming && renaming === null && (
          <>
            <IconButton label={t("item.attachmentRename")} onClick={() => setRenaming(attachment.name)} className="opacity-0 group-hover:opacity-100 focus:opacity-100">
              <TextCursorInput className="size-4" />
            </IconButton>
            <IconButton label={t("common.delete")} onClick={() => setConfirming(true)} className="opacity-0 group-hover:opacity-100 focus:opacity-100">
              <Trash className="size-4" />
            </IconButton>
          </>
        )}
      </div>
      {confirming && (
        <div className="mt-2 flex items-center gap-2 pl-8">
          <span className="flex-1 text-xs text-muted">{t("item.attachmentDeleteConfirm")}</span>
          <Button size="sm" variant="ghost" onClick={() => setConfirming(false)}>
            {t("common.cancel")}
          </Button>
          <Button size="sm" variant="danger" onClick={remove}>
            {t("common.delete")}
          </Button>
        </div>
      )}
    </div>
  );
}

/** A passkey kept in the item: the site and account, and a way to delete it. */
function PasskeyRow({ itemId, passkey, canEdit, onDeleted }: { itemId: string; passkey: PasskeyView; canEdit: boolean; onDeleted: () => void }) {
  const { t } = useTranslation();
  const [confirming, setConfirming] = useState(false);
  const remove = async () => {
    try {
      await api.deletePasskey(itemId, passkey.credentialId);
      toast.success(t("item.passkeyDeleted"));
      onDeleted();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <div className="group px-4 py-2.5">
      <div className="flex items-center gap-3">
        <Fingerprint className="size-5 shrink-0 text-accent" />
        <div className="min-w-0 flex-1">
          <div className="text-xs font-medium text-subtle">{t("item.passkey")}</div>
          <div className="mt-0.5 truncate text-[15px]">
            {passkey.rpId}
            {passkey.userName && <span className="text-muted"> · {passkey.userName}</span>}
          </div>
          {passkey.createdAt > 0 && <div className="text-xs text-subtle">{t("item.passkeyCreated", { date: formatDate(passkey.createdAt) })}</div>}
        </div>
        {canEdit && !confirming && (
          <IconButton label={t("common.delete")} onClick={() => setConfirming(true)} className="opacity-0 group-hover:opacity-100 focus:opacity-100">
            <Trash className="size-4" />
          </IconButton>
        )}
      </div>
      {confirming && (
        <div className="mt-2 flex items-center gap-2 pl-8">
          <span className="flex-1 text-xs text-muted">{t("item.passkeyDeleteConfirm")}</span>
          <Button size="sm" variant="ghost" onClick={() => setConfirming(false)}>
            {t("common.cancel")}
          </Button>
          <Button size="sm" variant="danger" onClick={remove}>
            {t("common.delete")}
          </Button>
        </div>
      )}
    </div>
  );
}

function WebsiteRow({ itemId, index, href, label, fill }: { itemId: string; index: number; href: string; label?: string; fill?: UrlFill }) {
  const { t } = useTranslation();
  // First on this website in the browser, whatever else is used more.
  const [pinned, setPinned] = useState(false);
  useEffect(() => {
    let current = true;
    api
      .itemPinned(itemId, href)
      .then((on) => current && setPinned(on))
      .catch(() => undefined);
    return () => {
      current = false;
    };
  }, [itemId, href]);
  const pin = async () => {
    try {
      await api.pinItem(itemId, href, !pinned);
      setPinned(!pinned);
      toast.success(t(pinned ? "item.unpinnedFromSite" : "item.pinnedToSite", { site: hostOf(href) }));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
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
      {pinned && (
        <Tooltip content={t("item.pinnedHint")}>
          <Pin className="size-3.5 shrink-0 fill-current text-accent group-hover:hidden" aria-label={t("item.pinnedHint")} />
        </Tooltip>
      )}
      <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
        <Tooltip content={t(pinned ? "item.unpinFromSite" : "item.pinToSite")}>
          <IconButton label={t(pinned ? "item.unpinFromSite" : "item.pinToSite")} onClick={pin} active={pinned}>
            <Pin className={cx("size-4", pinned && "fill-current")} />
          </IconButton>
        </Tooltip>
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

/** An Android app the login is linked to (on the phone): its name, when the phone gave one, and its package. */
function AppRow({ packageName, label }: { packageName: string; label?: string }) {
  const { t } = useTranslation();
  const copy = async () => {
    try {
      const result = await api.copyText(packageName);
      toast.copied(t("item.androidApp"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <div className="group flex items-center gap-3 px-4 py-2.5 hover:bg-panel-2">
      <div className="min-w-0 flex-1">
        <div className="text-xs font-medium text-subtle">{t("item.androidApp")}</div>
        <div className="selectable mt-0.5 truncate text-[15px]">{label || packageName}</div>
        {label && <div className="selectable mt-0.5 truncate text-xs text-subtle">{packageName}</div>}
      </div>
      <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
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

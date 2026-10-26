import {
  Ban,
  ChevronDown,
  CircleMinus,
  ClipboardPaste,
  Crosshair,
  Eye,
  EyeOff,
  FileText,
  Fingerprint,
  Globe,
  GripVertical,
  ImageIcon,
  Monitor,
  Paperclip,
  Plus,
  Rows3,
  ScanQrCode,
  Smartphone,
  Trash,
  UserRound,
  WandSparkles,
  X,
} from "lucide-react";
import { Fragment, forwardRef, useCallback, useEffect, useMemo, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { ItemIcon, PasswordInput, StrengthBadge } from "../../components/common";
import {
  Button,
  Combobox,
  Dialog,
  IconButton,
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
import { fieldLabel, isFieldLabel } from "../../i18n";
import {
  api,
  errorCode,
  errorMessage,
  type AttachmentView,
  type Category,
  type Field,
  type FieldKind,
  type FileInfo,
  type ItemDraft,
  type PasskeyView,
  type PasswordCheck,
  type Section,
  type SshKeyFields,
  type UrlFill,
} from "../../lib/api";
import {
  CATEGORIES,
  FIELD_KINDS,
  categoryInfo,
  categoryLabel,
  defaultFieldLabel,
  fieldKindLabel,
  frequentUsernames,
  isSecretKind,
  newFieldId,
  templateFields,
} from "../../lib/categories";
import { useFileDrop } from "../../lib/fileDrop";
import { Markdown } from "../../lib/markdown";
import { appOf, firstWebsite, formatBytes, formatDate } from "../../lib/format";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { AddressEditor, AlertButton, FileFieldEditor, LocationEditor, ReferenceEditor, SignInWithEditor } from "./FieldKinds";
import { GeneratorButton } from "./Generator";

export function ItemEditor() {
  const { t } = useTranslation();
  const editing = useApp((s) => s.editing)!;
  const vaults = useApp((s) => s.vaults);
  const stopEditing = useApp((s) => s.stopEditing);
  const [draft, setDraft] = useState<ItemDraft>(editing.draft);
  // A linked app's site (worked out when saved) while the draft has no website but apps.
  const savedIconUrl = useApp((s) => s.items.find((i) => i.id === editing.draft.id)?.iconUrl);
  const website = firstWebsite(draft.urls.map((u) => u.href));
  const iconUrl = website ?? (draft.urls.some((u) => appOf(u.href)) ? (savedIconUrl ?? undefined) : undefined);
  const [saving, setSaving] = useState(false);
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  // What was just added gets the focus, so typing can go on.
  const [focusField, setFocusField] = useState<string | null>(null);
  const [focusUrl, setFocusUrl] = useState<number | null>(null);
  const [focusSection, setFocusSection] = useState<string | null>(null);
  const [notesPreview, setNotesPreview] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);
  const initial = useRef(JSON.stringify(editing.draft));
  const titleRef = useRef<HTMLInputElement>(null);
  const info = categoryInfo(draft.category);
  // A password is weaker when it holds the item's own words.
  const username = draft.fields.find((f) => f.purpose === "username")?.value ?? "";
  const passwordContext = useMemo(() => ({ itemId: draft.id, inputs: [username, draft.title] }), [draft.id, username, draft.title]);

  useEffect(() => {
    titleRef.current?.focus();
  }, []);

  // Attachments and passkeys change when the item is saved: files to add,
  // and the item's files and passkeys to delete.
  const [attachments, setAttachments] = useState<AttachmentView[]>([]);
  const [passkeys, setPasskeys] = useState<PasskeyView[]>([]);
  const [removingPasskeys, setRemovingPasskeys] = useState<string[]>([]);
  const [newFiles, setNewFiles] = useState<FileInfo[]>([]);
  const [removing, setRemoving] = useState<string[]>([]);
  // File fields that point to a file chosen now (field id -> path).
  const [fileLinks, setFileLinks] = useState<Record<string, string>>({});
  useEffect(() => {
    if (!editing.draft.id) return;
    api
      .getItem(editing.draft.id)
      .then((item) => {
        setAttachments(item.attachments ?? []);
        setPasskeys(item.passkeys ?? []);
      })
      .catch(() => setAttachments([]));
  }, [editing.draft.id]);
  const addFiles = useCallback((files: FileInfo[]) => setNewFiles((current) => [...current, ...files.filter((f) => !current.some((c) => c.path === f.path))]), []);
  const dragging = useFileDrop(true, addFiles);
  const pickFiles = async () => {
    try {
      addFiles(await api.attachmentPick());
    } catch (err) {
      if (errorCode(err) !== "cancelled") toast.error(errorMessage(err));
    }
  };
  const pickFileFor = async (fieldId: string) => {
    try {
      const [file] = await api.attachmentPick();
      if (!file) return;
      addFiles([file]);
      setFileLinks((links) => ({ ...links, [fieldId]: file.path }));
    } catch (err) {
      if (errorCode(err) !== "cancelled") toast.error(errorMessage(err));
    }
  };

  const dirty = JSON.stringify(draft) !== initial.current || newFiles.length > 0 || removing.length > 0 || removingPasskeys.length > 0;
  const update = (patch: Partial<ItemDraft>) => setDraft((d) => ({ ...d, ...patch }));

  const save = useCallback(async () => {
    setSaving(true);
    try {
      const saved = await api.saveItem(draft);
      for (const credentialId of removingPasskeys) {
        await api.deletePasskey(saved.id, credentialId).catch((err) => toast.error(errorMessage(err)));
      }
      toast.success(t("editor.saved"));
      stopEditing();
      await useApp.getState().loadData();
      useApp.getState().select(saved.id);
      // The files go after the item, with their progress on the item.
      if (newFiles.length || removing.length) {
        const links = Object.entries(fileLinks)
          .filter(([, path]) => newFiles.some((f) => f.path === path))
          .map(([fieldId, path]) => [path, fieldId] as [string, string]);
        void applyAttachments(saved.id, newFiles, removing, links, t);
      }
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }, [draft, newFiles, removing, removingPasskeys, fileLinks, stopEditing, t]);

  const cancel = useCallback(() => {
    if (dirty) setConfirmDiscard(true);
    else stopEditing();
  }, [dirty, stopEditing]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        if (!saving) void save();
      } else if (e.key === "Escape" && !e.defaultPrevented && !document.querySelector("[data-radix-popper-content-wrapper], [role=dialog]")) {
        // Not when it closed a popover or menu (which marks it handled).
        e.preventDefault();
        cancel();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [save, cancel, saving]);

  const vaultOptions = useMemo(
    () => vaults.filter((v) => v.canWrite).map((v) => ({ value: v.id, label: v.name })),
    [vaults],
  );
  const categoryOptions = useMemo(
    () => CATEGORIES.filter((c) => !c.hidden || c.id === draft.category).map((c) => ({ value: c.id, label: categoryLabel(c.id), icon: <c.icon className="size-4" /> })),
    [draft.category],
  );

  // Another category keeps every field and adds the new one's that are missing.
  const changeCategory = (category: Category) => {
    if (category === draft.category) return;
    const existing = [...draft.fields, ...draft.sections.flatMap((s) => s.fields)];
    const missing = templateFields(category).filter(
      (f) => !existing.some((e) => (f.purpose && e.purpose === f.purpose) || fieldLabel(e.label).toLowerCase() === fieldLabel(f.label).toLowerCase()),
    );
    const urls = categoryInfo(category).hasWebsite && draft.urls.every((u) => appOf(u.href)) ? [...draft.urls, { href: "" }] : draft.urls;
    update({ category, fields: [...draft.fields, ...missing], urls });
  };

  const chooseIcon = async () => {
    try {
      update({ icon: await api.pickItemIcon() });
    } catch (err) {
      if (errorCode(err) !== "cancelled") toast.error(errorMessage(err));
    }
  };

  const setField = (index: number, field: Field) => update({ fields: draft.fields.map((f, i) => (i === index ? field : f)) });
  const removeField = (index: number) => update({ fields: draft.fields.filter((_, i) => i !== index) });
  const addField = (kind: FieldKind, sectionIndex?: number) => {
    // Named after its kind ("password"), which can be changed.
    const field: Field = { id: newFieldId(), label: defaultFieldLabel(kind), kind, value: "", purpose: null };
    setFocusField(field.id);
    if (sectionIndex === undefined) update({ fields: [...draft.fields, field] });
    else
      update({
        sections: draft.sections.map((s, i) => (i === sectionIndex ? { ...s, fields: [...s.fields, field] } : s)),
      });
  };
  // An item still without a title takes one from its website ("Google").
  const nameFromWebsite = (href: string) => {
    if (draft.title.trim() || !href.trim()) return;
    api
      .suggestTitle(href)
      .then((title) => title && setDraft((d) => (d.title.trim() ? d : { ...d, title })))
      .catch(() => undefined);
  };
  const setSection = (index: number, section: Section) =>
    update({ sections: draft.sections.map((s, i) => (i === index ? section : s)) });

  const fieldEditor = (field: Field, onChange: (f: Field) => void, onRemove: () => void, handle: ReactNode) => (
    <FieldEditor
      key={field.id}
      field={field}
      itemId={draft.id}
      autoFocus={field.id === focusField}
      passwordContext={passwordContext}
      attachments={attachments}
      pendingFile={newFiles.find((f) => f.path === fileLinks[field.id])}
      onPickFile={() => void pickFileFor(field.id)}
      handle={handle}
      onChange={onChange}
      onRemove={onRemove}
    />
  );

  return (
    <section className="flex min-w-0 flex-1 flex-col bg-panel">
      <header className="flex items-center gap-4 border-b border-line px-8 pb-5 pt-7">
        <Menu>
          <MenuTrigger asChild>
            <button className="rounded-2xl outline-none ring-accent/40 focus-visible:ring-3" aria-label={t("editor.icon")} tabIndex={-1}>
              <ItemIcon title={draft.title || categoryLabel(draft.category)} category={draft.category} url={iconUrl} size="lg" icon={draft.icon || undefined} />
            </button>
          </MenuTrigger>
          <MenuContent align="start">
            <MenuItem icon={<ImageIcon className="size-4" />} onSelect={() => void chooseIcon()}>
              {t("editor.chooseIcon")}
            </MenuItem>
            {draft.icon && (
              <MenuItem icon={<X className="size-4" />} onSelect={() => update({ icon: "" })}>
                {t("editor.removeIcon")}
              </MenuItem>
            )}
          </MenuContent>
        </Menu>
        <div className="min-w-0 flex-1">
          <input
            ref={titleRef}
            value={draft.title}
            onChange={(e) => update({ title: e.target.value })}
            onKeyDown={(e) => {
              // Enter goes on to the first field, like Tab.
              if (e.key === "Enter") {
                e.preventDefault();
                bodyRef.current?.querySelector<HTMLElement>("[data-field-value]")?.focus();
              }
            }}
            placeholder={editing.isNew ? t("editor.newTitle", { category: categoryLabel(draft.category) }) : t("editor.titlePlaceholder")}
            spellCheck={false}
            className="w-full rounded-lg bg-transparent px-1 text-xl font-semibold tracking-tight outline-none placeholder:text-subtle focus:bg-panel-2"
          />
          <div className="mt-1.5 flex items-center gap-2 px-1">
            <div className="w-44">
              <Combobox
                value={draft.category}
                onChange={(category) => changeCategory(category as Category)}
                options={categoryOptions}
                searchPlaceholder={t("common.searchPlaceholder")}
                triggerClassName="h-7 text-[13px]"
                tabIndex={-1}
              />
            </div>
            <span className="text-subtle">·</span>
            <div className="w-48">
              <Combobox
                value={draft.vaultId}
                onChange={(vaultId) => update({ vaultId })}
                options={vaultOptions}
                searchPlaceholder={t("common.searchPlaceholder")}
                triggerClassName="h-7 text-[13px]"
                tabIndex={-1}
              />
            </div>
          </div>
        </div>
      </header>

      <div ref={bodyRef} className="flex-1 overflow-y-auto px-8 py-6">
        <div className="mx-auto max-w-2xl space-y-4">
          {draft.category === "ssh_key" && <SshKeyTools draft={draft} onFields={(fields) => setDraft((d) => ({ ...d, fields }))} />}
          {(draft.fields.length > 0 || passkeys.length > 0) && (
            <EditCard>
              <Reorderable
                items={draft.fields}
                keyOf={(f) => f.id}
                gap="divide-y divide-line"
                onMove={(from, to) => update({ fields: moveItem(draft.fields, from, to) })}
                render={(field, i, handle) => fieldEditor(field, (f) => setField(i, f), () => removeField(i), handle)}
                // The passkeys come after the username, as in the item.
                extra={
                  passkeys.length > 0
                    ? {
                        after: draft.fields.findIndex((f) => f.purpose === "username"),
                        node: passkeys.map((passkey) => (
                          <PasskeyEditRow
                            key={passkey.credentialId}
                            passkey={passkey}
                            removing={removingPasskeys.includes(passkey.credentialId)}
                            onToggle={() =>
                              setRemovingPasskeys((ids) =>
                                ids.includes(passkey.credentialId) ? ids.filter((id) => id !== passkey.credentialId) : [...ids, passkey.credentialId],
                              )
                            }
                          />
                        )),
                      }
                    : undefined
                }
              />
            </EditCard>
          )}

          <Reorderable
            items={draft.sections}
            keyOf={(s) => s.id}
            gap="space-y-4"
            onMove={(from, to) => update({ sections: moveItem(draft.sections, from, to) })}
            render={(section, si, handle) => (
              <div className="space-y-1.5">
                <div className="group/section flex items-center gap-1.5 pl-0.5 pr-1">
                  {handle}
                  <input
                    value={section.title}
                    onChange={(e) => setSection(si, { ...section, title: e.target.value })}
                    placeholder={t("editor.sectionTitle")}
                    autoFocus={section.id === focusSection}
                    spellCheck={false}
                    className="h-7 min-w-0 flex-1 rounded bg-transparent px-1 text-xs font-semibold uppercase tracking-wider text-subtle outline-none placeholder:normal-case placeholder:tracking-normal placeholder:text-subtle/70 focus:bg-panel-2 focus:text-fg"
                  />
                  <IconButton
                    label={t("editor.deleteSection")}
                    tabIndex={-1}
                    onClick={() => update({ sections: draft.sections.filter((_, i) => i !== si) })}
                    className="opacity-0 group-hover/section:opacity-100 focus:opacity-100"
                  >
                    <Trash className="size-4" />
                  </IconButton>
                </div>
                <EditCard>
                  {section.fields.length > 0 && (
                    <Reorderable
                      items={section.fields}
                      keyOf={(f) => f.id}
                      gap="divide-y divide-line"
                      onMove={(from, to) => setSection(si, { ...section, fields: moveItem(section.fields, from, to) })}
                      render={(field, fi, fieldHandle) =>
                        fieldEditor(
                          field,
                          (f) => setSection(si, { ...section, fields: section.fields.map((x, i) => (i === fi ? f : x)) }),
                          () => setSection(si, { ...section, fields: section.fields.filter((_, i) => i !== fi) }),
                          fieldHandle,
                        )
                      }
                    />
                  )}
                  <AddFieldRow onAdd={(kind) => addField(kind, si)} />
                </EditCard>
              </div>
            )}
          />

          {(info.hasWebsite || draft.urls.some((u) => !appOf(u.href))) && (
            <EditCard>
              {draft.urls.map((url, i) =>
                appOf(url.href) ? null : (
                  <div key={i} className="flex items-center gap-2 py-2 pl-5 pr-3 focus-within:bg-panel-2">
                    <div className="min-w-0 flex-1">
                      <input
                        value={url.label ?? ""}
                        onChange={(e) => update({ urls: draft.urls.map((u, j) => (j === i ? { ...u, label: e.target.value } : u)) })}
                        placeholder={t("item.website")}
                        spellCheck={false}
                        tabIndex={-1}
                        className={cx(LABEL, "text-subtle placeholder:text-subtle")}
                      />
                      <input
                        value={url.href}
                        onChange={(e) => update({ urls: draft.urls.map((u, j) => (j === i ? { ...u, href: e.target.value } : u)) })}
                        onBlur={(e) => nameFromWebsite(e.target.value)}
                        placeholder={t("editor.websitePlaceholder")}
                        autoFocus={i === focusUrl}
                        spellCheck={false}
                        autoComplete="off"
                        inputMode="url"
                        className={cx(BARE, "h-7")}
                      />
                    </div>
                    <FillRuleButton
                      value={url.fill ?? "domain"}
                      submit={url.submit ?? null}
                      onChange={(fill) => update({ urls: draft.urls.map((u, j) => (j === i ? { ...u, fill } : u)) })}
                      onSubmitChange={(submit) => update({ urls: draft.urls.map((u, j) => (j === i ? { ...u, submit } : u)) })}
                    />
                    <RemoveButton label={t("common.remove")} onClick={() => update({ urls: draft.urls.filter((_, j) => j !== i) })} />
                  </div>
                ),
              )}
              <AddRow
                label={t("editor.addWebsite")}
                onClick={() => {
                  setFocusUrl(draft.urls.length);
                  update({ urls: [...draft.urls, { href: "" }] });
                }}
              />
            </EditCard>
          )}

          {draft.urls.some((u) => appOf(u.href)) && (
            <EditCard>
              <div className="px-5 pb-2 pt-2.5">
                <div className="text-xs font-semibold uppercase tracking-wider text-subtle">{t("item.apps")}</div>
                <p className="mt-0.5 text-xs text-subtle">{t("editor.appsHint")}</p>
              </div>
              {draft.urls.map((url, i) => {
                const app = appOf(url.href);
                return app ? (
                  <div key={i} className="flex items-center gap-3 py-2 pl-5 pr-3">
                    <Smartphone className="size-4 shrink-0 text-muted" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[15px]">{url.label || app}</div>
                      {url.label && <div className="truncate text-xs text-subtle">{app}</div>}
                    </div>
                    <RemoveButton label={t("common.remove")} onClick={() => update({ urls: draft.urls.filter((_, j) => j !== i) })} />
                  </div>
                ) : null;
              })}
            </EditCard>
          )}

          <AttachmentsEditor
            attachments={attachments}
            newFiles={newFiles}
            removing={removing}
            dragging={dragging}
            onDropNew={(path) => setNewFiles((files) => files.filter((f) => f.path !== path))}
            onToggleRemove={(id) => setRemoving((ids) => (ids.includes(id) ? ids.filter((i) => i !== id) : [...ids, id]))}
          />

          <AddMoreMenu
            onField={(kind) => addField(kind)}
            onSection={() => {
              const section = { id: newFieldId(), title: "", fields: [] };
              setFocusSection(section.id);
              update({ sections: [...draft.sections, section] });
            }}
            onFile={() => void pickFiles()}
          />

          <div className="overflow-hidden rounded-xl border border-line focus-within:border-accent/50">
            <div className="flex items-center gap-2 pl-5 pr-2 pt-2">
              <span className="flex-1 text-xs font-medium text-subtle">{t("item.notes")}</span>
              <div className="flex rounded-md bg-panel-2 p-0.5 text-[11px]">
                {[false, true].map((preview) => (
                  <button
                    key={String(preview)}
                    tabIndex={-1}
                    onClick={() => setNotesPreview(preview)}
                    className={cx("rounded px-2 py-0.5", notesPreview === preview ? "bg-panel font-medium text-fg shadow-xs" : "text-muted hover:text-fg")}
                  >
                    {preview ? t("editor.notesPreview") : t("editor.notesWrite")}
                  </button>
                ))}
              </div>
            </div>
            {notesPreview ? (
              <div className="min-h-24 px-5 pb-3 pt-1">
                {draft.notes.trim() ? (
                  <Markdown text={draft.notes} options={{ onLink: (url) => void api.openLink(url).catch(() => undefined) }} />
                ) : (
                  <p className="text-sm text-subtle">{t("editor.notesEmpty")}</p>
                )}
              </div>
            ) : (
              <textarea
                value={draft.notes}
                onChange={(e) => update({ notes: e.target.value })}
                placeholder={t("editor.notesPlaceholder")}
                rows={4}
                spellCheck={false}
                className={cx(BARE, "block min-h-24 resize-y px-5 pb-3 pt-1 text-sm leading-relaxed")}
              />
            )}
            <p className="border-t border-line px-5 py-1.5 text-[11px] text-subtle">{t("editor.notesMarkdownHint")}</p>
          </div>

          <TagsEditor tags={draft.tags} onChange={(tags) => update({ tags })} />
        </div>
      </div>

      <footer className="flex items-center justify-end gap-2 border-t border-line px-8 py-3">
        <Button onClick={cancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save} loading={saving} title="Ctrl S">
          {t("common.save")}
        </Button>
      </footer>

      <Dialog open={confirmDiscard} onOpenChange={setConfirmDiscard} title={t("editor.discardTitle")} description={t("editor.discardBody")}>
        <div className="flex justify-end gap-2">
          <Button onClick={() => setConfirmDiscard(false)}>{t("editor.keepEditing")}</Button>
          <Button
            variant="danger"
            onClick={() => {
              setConfirmDiscard(false);
              stopEditing();
            }}
          >
            {t("editor.discard")}
          </Button>
        </div>
      </Dialog>
    </section>
  );
}

function moveItem<T>(list: T[], from: number, to: number): T[] {
  const next = [...list];
  const [moved] = next.splice(from, 1);
  next.splice(to, 0, moved);
  return next;
}

/** A list whose rows move by dragging their handle (with the pointer, which
 * works the same on every webview) or with the arrow keys on it, and with
 * Alt+↑/↓ from anywhere in a row. */
function Reorderable<T>({
  items,
  keyOf,
  onMove,
  render,
  gap = "space-y-2",
  extra,
}: {
  items: T[];
  keyOf: (item: T) => string;
  onMove: (from: number, to: number) => void;
  render: (item: T, index: number, handle: ReactNode) => ReactNode;
  gap?: string;
  /** Rows that do not move, after the item at `after` (first, at -1). */
  extra?: { after: number; node: ReactNode };
}) {
  const { t } = useTranslation();
  const listRef = useRef<HTMLDivElement>(null);
  const [drag, setDrag] = useState<{ from: number; over: number } | null>(null);

  const startDrag = (index: number, e: React.PointerEvent) => {
    if (e.button !== 0) return;
    e.preventDefault();
    let over = index;
    setDrag({ from: index, over });
    const rows = () => Array.from(listRef.current?.children ?? []).filter((el) => (el as HTMLElement).dataset.row !== undefined) as HTMLElement[];
    const onMovePointer = (ev: PointerEvent) => {
      const found = rows().findIndex((row) => {
        const rect = row.getBoundingClientRect();
        return ev.clientY < rect.top + rect.height / 2;
      });
      over = found === -1 ? items.length - 1 : found > index ? found - 1 : found;
      setDrag({ from: index, over });
    };
    const onUp = () => {
      window.removeEventListener("pointermove", onMovePointer);
      window.removeEventListener("pointerup", onUp);
      setDrag(null);
      if (over !== index) onMove(index, over);
    };
    window.addEventListener("pointermove", onMovePointer);
    window.addEventListener("pointerup", onUp);
  };

  const keyMove = (index: number, e: React.KeyboardEvent) => {
    const up = e.key === "ArrowUp";
    if (!up && e.key !== "ArrowDown") return;
    const to = index + (up ? -1 : 1);
    if (to < 0 || to >= items.length) return;
    e.preventDefault();
    e.stopPropagation();
    onMove(index, to);
  };

  return (
    <div ref={listRef} className={gap}>
      {extra && extra.after < 0 && extra.node}
      {items.map((item, index) => {
        const handle = (
          <button
            type="button"
            tabIndex={-1}
            aria-label={t("editor.reorder")}
            title={t("editor.reorder")}
            onPointerDown={(e) => startDrag(index, e)}
            onKeyDown={(e) => keyMove(index, e)}
            className="shrink-0 cursor-grab touch-none rounded text-subtle/60 hover:text-muted active:cursor-grabbing"
          >
            <GripVertical className="size-4" />
          </button>
        );
        const target = drag && drag.over === index && drag.from !== index;
        const row = (
          <div
            key={keyOf(item)}
            data-row=""
            onKeyDown={(e) => e.altKey && keyMove(index, e)}
            className={cx(
              "transition-opacity",
              drag?.from === index && "opacity-50",
              target && (drag.from < index ? "border-b-2 border-b-accent" : "border-t-2 border-t-accent"),
            )}
          >
            {render(item, index, handle)}
          </div>
        );
        return extra && extra.after === index ? (
          <Fragment key={keyOf(item)}>
            {row}
            {extra.node}
          </Fragment>
        ) : (
          row
        );
      })}
    </div>
  );
}

/** Deletes and adds the files chosen while editing, once the item is saved. */
async function applyAttachments(
  itemId: string,
  files: FileInfo[],
  removing: string[],
  links: [string, string][],
  t: (key: string, options?: Record<string, unknown>) => string,
) {
  try {
    for (const id of removing) await api.attachmentDelete(itemId, id);
    if (files.length) {
      await api.attachmentAddPaths(
        itemId,
        files.map((f) => f.path),
        links,
      );
      toast.success(t("item.attachmentsAdded", { count: files.length }));
    }
  } catch (err) {
    toast.error(errorMessage(err));
  } finally {
    await useApp.getState().loadData();
  }
}

/** A group of rows, like a card of the item's view. */
function EditCard({ children }: { children: ReactNode }) {
  return <div className="divide-y divide-line overflow-hidden rounded-xl border border-line bg-panel">{children}</div>;
}

/** A field's label, small above its value (its colour apart). */
const LABEL = "block w-full rounded bg-transparent text-xs font-medium outline-none focus:text-fg";
/** A value typed straight in its row, without a box (like the item's view). */
const BARE = "w-full bg-transparent text-[15px] text-fg outline-none placeholder:text-subtle";

function RemoveButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      tabIndex={-1}
      aria-label={label}
      title={label}
      onClick={onClick}
      className="flex size-7 shrink-0 items-center justify-center self-center rounded-full text-danger/70 transition-colors hover:bg-danger-soft hover:text-danger"
    >
      <CircleMinus className="size-[18px]" />
    </button>
  );
}

/** "+ Add website" and the like, as the card's last row (also a menu's
 * trigger). */
const AddRow = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { label: string }>(function AddRow({ label, ...props }, ref) {
  return (
    <button
      ref={ref}
      type="button"
      {...props}
      className="flex w-full items-center gap-2 px-5 py-2 text-left text-[13px] font-medium text-accent transition-colors hover:bg-panel-2 data-[state=open]:bg-panel-2"
    >
      <Plus className="size-4" /> {label}
    </button>
  );
});

/** "+ Add field" at the end of a section: a field of the kind picked. */
function AddFieldRow({ onAdd }: { onAdd: (kind: FieldKind) => void }) {
  const { t } = useTranslation();
  return (
    <Menu>
      <MenuTrigger asChild>
        <AddRow label={t("editor.addField")} />
      </MenuTrigger>
      <MenuContent align="start">
        {FIELD_KINDS.map((kind) => (
          <MenuItem key={kind} onSelect={() => onAdd(kind)}>
            {fieldKindLabel(kind)}
          </MenuItem>
        ))}
      </MenuContent>
    </Menu>
  );
}

/** Under the item's cards: a field (to the first card), a section or a file. */
function AddMoreMenu({ onField, onSection, onFile }: { onField: (kind: FieldKind) => void; onSection: () => void; onFile: () => void }) {
  const { t } = useTranslation();
  return (
    <Menu>
      <MenuTrigger asChild>
        <button
          type="button"
          className="flex w-full items-center gap-2 rounded-xl border border-line px-5 py-2 text-left text-[13px] font-medium text-accent transition-colors hover:bg-panel-2 data-[state=open]:bg-panel-2"
        >
          <Plus className="size-4" />
          <span className="flex-1">{t("editor.addMore")}</span>
          <ChevronDown className="size-4 text-subtle" />
        </button>
      </MenuTrigger>
      <MenuContent align="start">
        {FIELD_KINDS.map((kind) => (
          <MenuItem key={kind} onSelect={() => onField(kind)}>
            {fieldKindLabel(kind)}
          </MenuItem>
        ))}
        <MenuSeparator />
        <MenuItem icon={<Rows3 className="size-4" />} onSelect={onSection}>
          {t("editor.section")}
        </MenuItem>
        <MenuSeparator />
        <MenuItem icon={<Paperclip className="size-4" />} onSelect={onFile}>
          <span>
            {t("editor.attachFile")}
            <span className="block text-xs text-subtle">{t("editor.attachFileHint")}</span>
          </span>
        </MenuItem>
      </MenuContent>
    </Menu>
  );
}

/** A passkey of the item while editing: deleted when the item is saved. */
function PasskeyEditRow({ passkey, removing, onToggle }: { passkey: PasskeyView; removing: boolean; onToggle: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="flex items-center gap-2 py-2 pl-5 pr-3">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5 text-xs font-medium text-subtle">
          <Fingerprint className="size-3.5 text-accent" /> {t("item.passkey")}
        </div>
        <div className={cx("truncate text-[15px]", removing && "text-subtle line-through")}>
          {passkey.rpId}
          {passkey.userName && <span className="text-muted"> · {passkey.userName}</span>}
        </div>
        <div className="text-xs text-subtle">
          {removing ? t("editor.deleteOnSave") : passkey.createdAt > 0 ? t("item.passkeyCreated", { date: formatDate(passkey.createdAt) }) : null}
        </div>
      </div>
      {removing ? (
        <Button size="sm" variant="ghost" onClick={onToggle}>
          {t("editor.keepFile")}
        </Button>
      ) : (
        <RemoveButton label={t("common.delete")} onClick={onToggle} />
      )}
    </div>
  );
}

/** A secret typed in its row, hidden until shown. */
function BareSecret(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const { t } = useTranslation();
  const [visible, setVisible] = useState(false);
  return (
    <div className="flex items-center gap-1">
      <input
        {...props}
        type={visible ? "text" : "password"}
        spellCheck={false}
        autoComplete="off"
        className={cx(BARE, "h-7 min-w-0 font-mono", !visible && "tracking-[0.15em]")}
      />
      <IconButton label={visible ? t("common.hide") : t("common.show")} tabIndex={-1} onClick={() => setVisible((v) => !v)}>
        {visible ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
      </IconButton>
    </div>
  );
}

/** The item's files while editing, the ones it has (to keep or delete) and
 * the new ones; where files dropped on the window go, while dragging. */
function AttachmentsEditor({
  attachments,
  newFiles,
  removing,
  dragging,
  onDropNew,
  onToggleRemove,
}: {
  attachments: AttachmentView[];
  newFiles: FileInfo[];
  removing: string[];
  dragging: boolean;
  onDropNew: (path: string) => void;
  onToggleRemove: (id: string) => void;
}) {
  const { t } = useTranslation();
  if (!dragging && attachments.length === 0 && newFiles.length === 0) return null;
  return (
    <div className="space-y-2">
      {(attachments.length > 0 || newFiles.length > 0) && (
        <EditCard>
          {attachments.map((a) => {
            const gone = removing.includes(a.id);
            return (
              <div key={a.id} className="flex items-center gap-3 py-2 pl-5 pr-3">
                <FileText className={cx("size-4 shrink-0", gone ? "text-subtle" : "text-accent")} />
                <div className="min-w-0 flex-1">
                  <div className={cx("truncate text-[15px]", gone && "text-subtle line-through")}>{a.name}</div>
                  <div className="text-xs text-subtle">{gone ? t("editor.deleteOnSave") : formatBytes(a.size)}</div>
                </div>
                {gone ? (
                  <Button size="sm" variant="ghost" onClick={() => onToggleRemove(a.id)}>
                    {t("editor.keepFile")}
                  </Button>
                ) : (
                  <RemoveButton label={t("common.delete")} onClick={() => onToggleRemove(a.id)} />
                )}
              </div>
            );
          })}
          {newFiles.map((f) => (
            <div key={f.path} className="flex items-center gap-3 py-2 pl-5 pr-3">
              <Paperclip className="size-4 shrink-0 text-accent" />
              <div className="min-w-0 flex-1">
                <div className="truncate text-[15px]">{f.name}</div>
                <div className="text-xs text-subtle">
                  {formatBytes(f.size)} · {t("editor.addOnSave")}
                </div>
              </div>
              <RemoveButton label={t("common.remove")} onClick={() => onDropNew(f.path)} />
            </div>
          ))}
        </EditCard>
      )}
      {dragging && (
        <div className="flex items-center justify-center gap-1.5 rounded-xl border border-dashed border-accent bg-accent-soft px-4 py-4 text-[13px] text-accent">
          <Paperclip className="size-4" />
          <span>{t("editor.dropHere")}</span>
        </div>
      )}
    </div>
  );
}

function kindOptions() {
  return FIELD_KINDS.map((kind) => ({ value: kind, label: fieldKindLabel(kind) }));
}

interface PasswordContext {
  itemId: string | null;
  /** The item's own words, which make a password weaker. */
  inputs: string[];
}

function FieldEditor({
  field,
  itemId,
  autoFocus,
  passwordContext,
  attachments,
  pendingFile,
  onPickFile,
  handle,
  onChange,
  onRemove,
}: {
  field: Field;
  itemId: string | null;
  /** Just added: focus its value. */
  autoFocus?: boolean;
  passwordContext?: PasswordContext;
  /** The item's files, for file fields. */
  attachments: AttachmentView[];
  /** The file chosen for a file field, attached on save. */
  pendingFile?: FileInfo;
  onPickFile: () => void;
  /** The drag handle that moves the field. */
  handle: ReactNode;
  onChange: (f: Field) => void;
  onRemove: () => void;
}) {
  const { t } = useTranslation();
  const secret = isSecretKind(field);
  // Not for an SSH private key: it is generated as a key, not a password.
  const canGenerate =
    (field.kind === "concealed" || field.kind === "security_question" || field.purpose === "password") && !isFieldLabel(field.label, "private key");

  const valueInput = (() => {
    const common = {
      value: field.value,
      onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => onChange({ ...field, value: e.target.value }),
      // A new field without a label starts at its label.
      autoFocus: autoFocus && !!field.label,
      // Where Enter in the title goes.
      "data-field-value": "",
    };
    switch (field.kind) {
      case "address":
        return <AddressEditor field={field} onChange={onChange} />;
      case "sign_in_with":
        return <SignInWithEditor field={field} itemId={itemId} onChange={onChange} />;
      case "location":
        return <LocationEditor field={field} onChange={onChange} />;
      case "reference":
        return <ReferenceEditor field={field} itemId={itemId} onChange={onChange} />;
      case "file":
        return <FileFieldEditor field={field} attachments={attachments} pending={pendingFile} onChange={onChange} onPick={onPickFile} />;
      case "multiline":
        return <textarea {...common} rows={3} spellCheck={false} className={cx(BARE, "block min-h-16 resize-y py-0.5 font-mono text-[13px]")} />;
      case "totp":
        return <input {...common} placeholder={t("editor.totpPlaceholder")} spellCheck={false} autoComplete="off" className={cx(BARE, "h-7 font-mono")} />;
      case "date":
        return <input {...common} type="date" className={cx(BARE, "h-7")} />;
      case "month_year":
        return <input {...common} placeholder="MM/YYYY" autoComplete="off" className={cx(BARE, "h-7")} />;
    }
    if (secret) return <BareSecret {...common} />;
    return (
      <input
        {...common}
        type={field.kind === "email" ? "email" : "text"}
        inputMode={field.kind === "phone" ? "tel" : field.kind === "url" ? "url" : undefined}
        spellCheck={false}
        autoComplete="off"
        className={cx(BARE, "h-7")}
      />
    );
  })();

  // A label still the one of its kind follows a change of kind.
  const changeKind = (kind: FieldKind) =>
    onChange({ ...field, kind, label: !field.label || field.label === defaultFieldLabel(field.kind) ? defaultFieldLabel(kind) : field.label });

  return (
    <div className="group/row relative flex gap-2 py-2 pl-5 pr-3 focus-within:bg-panel-2">
      <div className="absolute left-0.5 top-2.5 opacity-0 transition-opacity group-hover/row:opacity-100 group-focus-within/row:opacity-100">{handle}</div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1">
          <input
            value={fieldLabel(field.label)}
            onChange={(e) => onChange({ ...field, label: e.target.value })}
            placeholder={field.kind === "security_question" ? t("editor.questionPlaceholder") : t("editor.fieldLabel")}
            spellCheck={false}
            // Tab goes from value to value; a label is clicked to rename,
            // but one still to name is in the way.
            tabIndex={field.label ? -1 : undefined}
            autoFocus={autoFocus && !field.label}
            // The login's own fields (username, password) stand out.
            className={cx(LABEL, "min-w-0 flex-1 placeholder:text-subtle/60", field.purpose ? "text-accent" : "text-subtle")}
          />
          <Combobox
            value={field.kind}
            onChange={changeKind}
            options={kindOptions()}
            align="end"
            searchPlaceholder={t("common.searchPlaceholder")}
            trigger={
              <button
                tabIndex={-1}
                className="rounded px-1.5 py-0.5 text-[11px] font-medium text-subtle opacity-0 hover:bg-panel-3 hover:text-fg group-hover/row:opacity-100 focus:opacity-100"
              >
                {fieldKindLabel(field.kind)}
              </button>
            }
          />
        </div>
        <div className="flex items-center gap-1">
          <div className="min-w-0 flex-1">{valueInput}</div>
          {field.purpose === "username" && <UsernameSuggestions value={field.value} onPick={(value) => onChange({ ...field, value })} />}
          {field.kind === "totp" && <ScanQrButton onRead={(value) => onChange({ ...field, value })} />}
          {(field.kind === "date" || field.kind === "month_year") && <AlertButton value={field.alert} onChange={(alert) => onChange({ ...field, alert })} />}
          {canGenerate && <GeneratorButton onUse={(password) => onChange({ ...field, value: password })} />}
        </div>
        {passwordContext && field.purpose === "password" && field.value && <PasswordHints password={field.value} context={passwordContext} />}
      </div>
      <RemoveButton label={t("editor.deleteField")} onClick={onRemove} />
    </div>
  );
}

/** The usernames used most, to pick one for this login. */
function UsernameSuggestions({ value, onPick }: { value: string; onPick: (value: string) => void }) {
  const { t } = useTranslation();
  const items = useApp((s) => s.items);
  const names = useMemo(() => frequentUsernames(items, 6).filter((name) => name !== value), [items, value]);
  if (names.length === 0) return null;
  return (
    <Menu>
      <MenuTrigger asChild>
        <IconButton label={t("editor.usernameSuggestions")} tabIndex={-1}>
          <UserRound className="size-4" />
        </IconButton>
      </MenuTrigger>
      <MenuContent>
        <MenuLabel>{t("editor.usernameSuggestions")}</MenuLabel>
        {names.map((name) => (
          <MenuItem key={name} onSelect={() => onPick(name)}>
            {name}
          </MenuItem>
        ))}
      </MenuContent>
    </Menu>
  );
}

/** Under the password being typed: how strong it is, and whether other items
 * already use it. Checked on this device only; whether it was in a breach is
 * checked online once the item is saved (see Sentinel). */
function PasswordHints({ password, context }: { password: string; context: PasswordContext }) {
  const { t } = useTranslation();
  const [check, setCheck] = useState<PasswordCheck | null>(null);
  useEffect(() => {
    let current = true;
    const handle = setTimeout(() => {
      api
        .checkItemPassword(password, context.itemId, context.inputs)
        .then((result) => current && setCheck(result))
        .catch(() => current && setCheck(null));
    }, 250);
    return () => {
      current = false;
      clearTimeout(handle);
    };
  }, [password, context]);
  if (!check) return null;
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 px-1 text-xs">
      <StrengthBadge level={check.level} />
      {check.reused > 0 && <span className="text-warning">{t("editor.reusedPassword", { count: check.reused })}</span>}
    </div>
  );
}

/** Reads a one-time password QR code, like 1Password's "Scan QR Code". */
/** SSH key items: generates a key, or fills the public key and fingerprint
 * from a pasted private key (asking for its passphrase when it has one). */
function SshKeyTools({ draft, onFields }: { draft: ItemDraft; onFields: (fields: Field[]) => void }) {
  const { t } = useTranslation();
  const privateKey = draft.fields.find((f) => isFieldLabel(f.label, "private key"))?.value ?? "";
  const [needsPassphrase, setNeedsPassphrase] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const derived = useRef("");

  const apply = useCallback(
    (key: SshKeyFields) => {
      const values: Record<string, string> = { "private key": key.privateKey, "public key": key.publicKey, fingerprint: key.fingerprint };
      const keyOf = (label: string) => Object.keys(values).find((k) => isFieldLabel(label, k));
      const fields = draft.fields.map((f) => {
        const k = keyOf(f.label);
        return k ? { ...f, value: values[k] } : f;
      });
      for (const [label, value] of Object.entries(values)) {
        if (!fields.some((f) => isFieldLabel(f.label, label))) {
          fields.push({ id: newFieldId(), label: fieldLabel(label), kind: label === "private key" ? "concealed" : label === "public key" ? "multiline" : "text", value });
        }
      }
      derived.current = key.privateKey;
      onFields(fields);
    },
    [draft.fields, onFields],
  );

  const derive = useCallback(
    async (withPassphrase?: string) => {
      setBusy(true);
      try {
        apply(await api.sshImportKey(privateKey, withPassphrase ?? null, draft.title));
        setNeedsPassphrase(false);
        setPassphrase("");
        setError(null);
      } catch (err) {
        const code = errorCode(err);
        if (code === "ssh_key_passphrase") setNeedsPassphrase(true);
        else setError(errorMessage(err));
      } finally {
        setBusy(false);
      }
    },
    [apply, privateKey, draft.title],
  );

  // A key was pasted: fill in the rest.
  useEffect(() => {
    if (!privateKey.includes("-----END ") || privateKey === derived.current) return;
    derived.current = privateKey;
    const timer = setTimeout(() => void derive(), 300);
    return () => clearTimeout(timer);
  }, [privateKey, derive]);

  const generate = async () => {
    setBusy(true);
    try {
      apply(await api.sshGenerateKey(draft.title));
      setError(null);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-2 rounded-xl border border-line bg-panel-2 p-3">
      {!privateKey.trim() ? (
        <div className="flex items-center gap-3">
          <p className="flex-1 text-[13px] text-muted">{t("sshKey.hint")}</p>
          <Button size="sm" variant="secondary" onClick={generate} loading={busy}>
            <WandSparkles className="size-4" /> {t("sshKey.generate")}
          </Button>
        </div>
      ) : needsPassphrase ? (
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void derive(passphrase);
          }}
        >
          <span className="shrink-0 text-[13px] text-muted">{t("sshKey.passphrase")}</span>
          <PasswordInput value={passphrase} onChange={(e) => setPassphrase(e.target.value)} className="h-8" autoFocus />
          <Button size="sm" type="submit" loading={busy} disabled={!passphrase}>
            {t("sshKey.unlock")}
          </Button>
        </form>
      ) : (
        <p className="text-[13px] text-muted">{t("sshKey.ready")}</p>
      )}
      {error && <p className="text-[13px] text-danger">{error}</p>}
    </div>
  );
}

const FILL_RULES: { value: UrlFill; icon: typeof Globe }[] = [
  { value: "domain", icon: Globe },
  { value: "host", icon: Crosshair },
  { value: "never", icon: Ban },
];

const SUBMIT_RULES = [
  { value: "default", submit: null },
  { value: "always", submit: true },
  { value: "never", submit: false },
] as const;

/** Where the browser extension may fill the login, per website (like
 * 1Password's "autofill behavior"), and whether filling also signs in. */
function FillRuleButton({
  value,
  submit,
  onChange,
  onSubmitChange,
}: {
  value: UrlFill;
  submit: boolean | null;
  onChange: (value: UrlFill) => void;
  onSubmitChange: (submit: boolean | null) => void;
}) {
  const { t } = useTranslation();
  const Current = FILL_RULES.find((r) => r.value === value)?.icon ?? Globe;
  const [open, setOpen] = useState(false);
  return (
    <Menu open={open} onOpenChange={setOpen}>
      <MenuTrigger asChild>
        <IconButton
          label={`${t("editor.fillRule")}: ${t(`editor.fill.${value}`)}`}
          tabIndex={-1}
          className={cx((value !== "domain" || submit !== null) && "text-accent")}
        >
          <Current className="size-4" />
        </IconButton>
      </MenuTrigger>
      <MenuContent>
        <MenuLabel>{t("editor.fillRule")}</MenuLabel>
        <MenuRadioGroup
          value={value}
          onValueChange={(next) => {
            onChange(next as UrlFill);
            setOpen(false);
          }}
        >
          {FILL_RULES.map((rule) => (
            <MenuRadioItem key={rule.value} value={rule.value}>
              <span className="flex items-center gap-2.5">
                <rule.icon className="size-4 text-muted" />
                {t(`editor.fill.${rule.value}`)}
              </span>
            </MenuRadioItem>
          ))}
        </MenuRadioGroup>
        <MenuSeparator />
        <MenuLabel>{t("editor.submitRule")}</MenuLabel>
        <MenuRadioGroup
          value={SUBMIT_RULES.find((rule) => rule.submit === submit)?.value ?? "default"}
          onValueChange={(next) => {
            onSubmitChange(SUBMIT_RULES.find((rule) => rule.value === next)?.submit ?? null);
            setOpen(false);
          }}
        >
          {SUBMIT_RULES.map((rule) => (
            <MenuRadioItem key={rule.value} value={rule.value}>
              {t(`editor.submit.${rule.value}`)}
            </MenuRadioItem>
          ))}
        </MenuRadioGroup>
      </MenuContent>
    </Menu>
  );
}

function ScanQrButton({ onRead }: { onRead: (value: string) => void }) {
  const { t } = useTranslation();
  const scan = async (source: "screen" | "clipboard" | "file") => {
    try {
      onRead(await api.scanQr(source));
      toast.success(t("editor.qrRead"));
    } catch (err) {
      if (errorCode(err) !== "cancelled") toast.error(errorMessage(err));
    }
  };
  return (
    <Menu>
      <MenuTrigger asChild>
        <IconButton label={t("editor.scanQr")} tabIndex={-1}>
          <ScanQrCode className="size-4" />
        </IconButton>
      </MenuTrigger>
      <MenuContent>
        <MenuItem icon={<Monitor className="size-4" />} onSelect={() => void scan("screen")}>
          {t("editor.scanScreen")}
        </MenuItem>
        <MenuItem icon={<ClipboardPaste className="size-4" />} onSelect={() => void scan("clipboard")}>
          {t("editor.scanClipboard")}
        </MenuItem>
        <MenuItem icon={<ImageIcon className="size-4" />} onSelect={() => void scan("file")}>
          {t("editor.scanFile")}
        </MenuItem>
      </MenuContent>
    </Menu>
  );
}

function TagsEditor({ tags, onChange }: { tags: string[]; onChange: (tags: string[]) => void }) {
  const { t } = useTranslation();
  const [input, setInput] = useState("");
  const add = () => {
    const tag = input.trim().replace(/,$/, "");
    if (tag && !tags.some((x) => x.toLowerCase() === tag.toLowerCase())) onChange([...tags, tag]);
    setInput("");
  };
  return (
    <div className="space-y-1.5 px-1">
      <div className="text-xs font-medium text-subtle">{t("item.tags")}</div>
      <div className="flex flex-wrap items-center gap-1.5">
        {tags.map((tag) => (
          <span key={tag} className="inline-flex items-center gap-1 rounded-full bg-panel-3 py-0.5 pl-2.5 pr-1 text-xs font-medium">
            {tag}
            <button
              tabIndex={-1}
              onClick={() => onChange(tags.filter((x) => x !== tag))}
              className="rounded-full p-0.5 text-subtle hover:bg-line hover:text-fg"
              aria-label={t("common.remove")}
            >
              <X className="size-3" />
            </button>
          </span>
        ))}
        <label className="inline-flex items-center gap-1 rounded-full bg-panel-2 py-0.5 pl-2 pr-2.5 text-accent focus-within:ring-2 focus-within:ring-accent-soft">
          <Plus className="size-3.5 shrink-0" />
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === ",") {
                e.preventDefault();
                add();
              } else if (e.key === "Backspace" && !input && tags.length) {
                onChange(tags.slice(0, -1));
              }
            }}
            onBlur={add}
            placeholder={t("editor.addTag")}
            title={t("editor.tagsPlaceholder")}
            spellCheck={false}
            className="h-5 w-36 bg-transparent text-xs font-medium text-fg outline-none placeholder:text-accent"
          />
        </label>
      </div>
    </div>
  );
}

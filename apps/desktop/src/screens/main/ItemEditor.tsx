import { ClipboardPaste, GripVertical, ImageIcon, Monitor, Plus, ScanQrCode, Trash, WandSparkles, X } from "lucide-react";
import { Popover } from "radix-ui";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { ItemIcon, PasswordInput } from "../../components/common";
import { Button, Combobox, Dialog, IconButton, Input, Menu, MenuContent, MenuItem, MenuTrigger, Textarea, cx } from "../../components/ui";
import { fieldLabel } from "../../i18n";
import { api, errorCode, errorMessage, type Field, type FieldKind, type ItemDraft, type Section } from "../../lib/api";
import { FIELD_KINDS, categoryInfo, categoryLabel, fieldKindLabel, isSecretKind, newFieldId } from "../../lib/categories";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { GeneratorPanel } from "./Generator";

export function ItemEditor() {
  const { t } = useTranslation();
  const editing = useApp((s) => s.editing)!;
  const vaults = useApp((s) => s.vaults);
  const stopEditing = useApp((s) => s.stopEditing);
  const [draft, setDraft] = useState<ItemDraft>(editing.draft);
  const [saving, setSaving] = useState(false);
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const initial = useRef(JSON.stringify(editing.draft));
  const titleRef = useRef<HTMLInputElement>(null);
  const info = categoryInfo(draft.category);

  useEffect(() => {
    titleRef.current?.focus();
  }, []);

  const dirty = JSON.stringify(draft) !== initial.current;
  const update = (patch: Partial<ItemDraft>) => setDraft((d) => ({ ...d, ...patch }));

  const save = useCallback(async () => {
    setSaving(true);
    try {
      const saved = await api.saveItem(draft);
      toast.success(t("editor.saved"));
      stopEditing();
      await useApp.getState().loadData();
      useApp.getState().select(saved.id);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }, [draft, stopEditing, t]);

  const cancel = useCallback(() => {
    if (dirty) setConfirmDiscard(true);
    else stopEditing();
  }, [dirty, stopEditing]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        if (!saving) void save();
      } else if (e.key === "Escape" && !document.querySelector("[data-radix-popper-content-wrapper], [role=dialog]")) {
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

  const setField = (index: number, field: Field) => update({ fields: draft.fields.map((f, i) => (i === index ? field : f)) });
  const removeField = (index: number) => update({ fields: draft.fields.filter((_, i) => i !== index) });
  const addField = (kind: FieldKind, sectionIndex?: number) => {
    const field: Field = { id: newFieldId(), label: "", kind, value: "", purpose: null };
    if (sectionIndex === undefined) update({ fields: [...draft.fields, field] });
    else
      update({
        sections: draft.sections.map((s, i) => (i === sectionIndex ? { ...s, fields: [...s.fields, field] } : s)),
      });
  };
  const setSection = (index: number, section: Section) =>
    update({ sections: draft.sections.map((s, i) => (i === index ? section : s)) });

  return (
    <section className="flex min-w-0 flex-1 flex-col bg-panel">
      <header className="flex items-center gap-4 border-b border-line px-8 pb-5 pt-7">
        <ItemIcon title={draft.title || categoryLabel(draft.category)} category={draft.category} url={draft.urls[0]?.href} size="lg" />
        <div className="min-w-0 flex-1">
          <input
            ref={titleRef}
            value={draft.title}
            onChange={(e) => update({ title: e.target.value })}
            placeholder={editing.isNew ? t("editor.newTitle", { category: categoryLabel(draft.category) }) : t("editor.titlePlaceholder")}
            spellCheck={false}
            className="w-full rounded-lg bg-transparent px-1 text-xl font-semibold tracking-tight outline-none placeholder:text-subtle focus:bg-panel-2"
          />
          <div className="mt-1.5 flex items-center gap-2 px-1">
            <span className="text-[13px] text-muted">{categoryLabel(draft.category)}</span>
            <span className="text-subtle">·</span>
            <div className="w-48">
              <Combobox
                value={draft.vaultId}
                onChange={(vaultId) => update({ vaultId })}
                options={vaultOptions}
                searchPlaceholder={t("common.searchPlaceholder")}
                triggerClassName="h-7 text-[13px]"
              />
            </div>
          </div>
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-8 py-6">
        <div className="mx-auto max-w-2xl space-y-6">
          <div className="space-y-2">
            {draft.fields.map((field, i) => (
              <FieldEditor key={field.id} field={field} onChange={(f) => setField(i, f)} onRemove={() => removeField(i)} />
            ))}
            <AddFieldButton onAdd={(kind) => addField(kind)} />
          </div>

          {draft.sections.map((section, si) => (
            <div key={section.id} className="space-y-2 rounded-xl border border-line p-3">
              <div className="flex items-center gap-2">
                <Input
                  value={section.title}
                  onChange={(e) => setSection(si, { ...section, title: e.target.value })}
                  placeholder={t("editor.sectionTitle")}
                  className="h-8 border-transparent bg-transparent text-xs font-semibold uppercase tracking-wider shadow-none focus:bg-panel"
                />
                <IconButton label={t("editor.deleteSection")} onClick={() => update({ sections: draft.sections.filter((_, i) => i !== si) })}>
                  <Trash className="size-4" />
                </IconButton>
              </div>
              {section.fields.map((field, fi) => (
                <FieldEditor
                  key={field.id}
                  field={field}
                  onChange={(f) => setSection(si, { ...section, fields: section.fields.map((x, i) => (i === fi ? f : x)) })}
                  onRemove={() => setSection(si, { ...section, fields: section.fields.filter((_, i) => i !== fi) })}
                />
              ))}
              <AddFieldButton onAdd={(kind) => addField(kind, si)} />
            </div>
          ))}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => update({ sections: [...draft.sections, { id: newFieldId(), title: "", fields: [] }] })}
          >
            <Plus className="size-4" /> {t("editor.addSection")}
          </Button>

          {(info.hasWebsite || draft.urls.length > 0) && (
            <div className="space-y-2">
              <div className="px-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t("item.websites")}</div>
              {draft.urls.map((url, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Input
                    value={url.href}
                    onChange={(e) => update({ urls: draft.urls.map((u, j) => (j === i ? { ...u, href: e.target.value } : u)) })}
                    placeholder={t("editor.websitePlaceholder")}
                  />
                  <IconButton label={t("common.remove")} onClick={() => update({ urls: draft.urls.filter((_, j) => j !== i) })}>
                    <X className="size-4" />
                  </IconButton>
                </div>
              ))}
              <Button variant="ghost" size="sm" onClick={() => update({ urls: [...draft.urls, { href: "" }] })}>
                <Plus className="size-4" /> {t("editor.addWebsite")}
              </Button>
            </div>
          )}

          <div className="space-y-2">
            <div className="px-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t("item.notes")}</div>
            <Textarea value={draft.notes} onChange={(e) => update({ notes: e.target.value })} placeholder={t("editor.notesPlaceholder")} rows={4} />
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

function kindOptions() {
  return FIELD_KINDS.map((kind) => ({ value: kind, label: fieldKindLabel(kind) }));
}

function AddFieldButton({ onAdd }: { onAdd: (kind: FieldKind) => void }) {
  const { t } = useTranslation();
  return (
    <Combobox
      value={null}
      onChange={onAdd}
      options={kindOptions()}
      searchPlaceholder={t("common.searchPlaceholder")}
      trigger={
        <button className="inline-flex h-7 items-center gap-2 rounded-lg px-2.5 text-[13px] font-medium text-muted hover:bg-panel-3 hover:text-fg">
          <Plus className="size-4" /> {t("editor.addField")}
        </button>
      }
    />
  );
}

function FieldEditor({ field, onChange, onRemove }: { field: Field; onChange: (f: Field) => void; onRemove: () => void }) {
  const { t } = useTranslation();
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const secret = isSecretKind(field);
  const canGenerate = field.kind === "concealed" || field.purpose === "password";

  const valueInput = (() => {
    const common = {
      value: field.value,
      onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => onChange({ ...field, value: e.target.value }),
    };
    if (field.kind === "multiline") return <Textarea {...common} rows={3} className="font-mono text-[13px]" />;
    if (field.kind === "totp") return <Input {...common} placeholder={t("editor.totpPlaceholder")} className="font-mono" />;
    if (field.kind === "date") return <Input {...common} type="date" />;
    if (field.kind === "month_year") return <Input {...common} placeholder="MM/YYYY" />;
    if (secret) return <PasswordInput {...common} className="h-9 font-mono" />;
    return (
      <Input
        {...common}
        type={field.kind === "email" ? "email" : "text"}
        inputMode={field.kind === "phone" ? "tel" : field.kind === "url" ? "url" : undefined}
      />
    );
  })();

  return (
    <div className="group flex gap-2 rounded-xl border border-line bg-panel p-2.5 focus-within:border-accent/50">
      <GripVertical className="mt-1.5 size-4 shrink-0 text-subtle/50" />
      <div className="min-w-0 flex-1 space-y-1.5">
        <div className="flex items-center gap-1">
          <input
            value={fieldLabel(field.label)}
            onChange={(e) => onChange({ ...field, label: e.target.value })}
            placeholder={t("editor.fieldLabel")}
            spellCheck={false}
            className="min-w-0 flex-1 rounded bg-transparent px-1 text-xs font-medium text-subtle outline-none placeholder:text-subtle/60 focus:text-fg"
          />
          <Combobox
            value={field.kind}
            onChange={(kind) => onChange({ ...field, kind })}
            options={kindOptions()}
            align="end"
            searchPlaceholder={t("common.searchPlaceholder")}
            trigger={
              <button className="rounded px-1.5 py-0.5 text-[11px] font-medium text-subtle opacity-0 hover:bg-panel-3 hover:text-fg group-hover:opacity-100 focus:opacity-100">
                {fieldKindLabel(field.kind)}
              </button>
            }
          />
        </div>
        <div className="flex items-start gap-1">
          <div className="min-w-0 flex-1">{valueInput}</div>
          {field.kind === "totp" && <ScanQrButton onRead={(value) => onChange({ ...field, value })} />}
          {canGenerate && (
            <Popover.Root open={generatorOpen} onOpenChange={setGeneratorOpen}>
              <Popover.Trigger asChild>
                <IconButton label={t("editor.generate")} className="mt-0.5">
                  <WandSparkles className="size-4" />
                </IconButton>
              </Popover.Trigger>
              <Popover.Portal>
                <Popover.Content align="end" sideOffset={6} className="z-50 rounded-2xl border border-line bg-panel p-4 shadow-2xl animate-pop">
                  <GeneratorPanel
                    compact
                    onUse={(password) => {
                      onChange({ ...field, value: password });
                      setGeneratorOpen(false);
                    }}
                  />
                </Popover.Content>
              </Popover.Portal>
            </Popover.Root>
          )}
          <IconButton label={t("editor.deleteField")} onClick={onRemove} className={cx("mt-0.5 opacity-0 group-hover:opacity-100 focus:opacity-100")}>
            <Trash className="size-4" />
          </IconButton>
        </div>
      </div>
    </div>
  );
}

/** Reads a one-time password QR code, like 1Password's "Scan QR Code". */
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
        <IconButton label={t("editor.scanQr")} className="mt-0.5">
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
    <div className="space-y-2">
      <div className="px-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t("item.tags")}</div>
      <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-line bg-panel px-2 py-1.5 focus-within:border-accent focus-within:ring-3 focus-within:ring-accent-soft">
        {tags.map((tag) => (
          <span key={tag} className="inline-flex items-center gap-1 rounded-full bg-panel-3 py-0.5 pl-2.5 pr-1 text-xs font-medium">
            {tag}
            <button onClick={() => onChange(tags.filter((x) => x !== tag))} className="rounded-full p-0.5 text-subtle hover:bg-line hover:text-fg" aria-label={t("common.remove")}>
              <X className="size-3" />
            </button>
          </span>
        ))}
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
          placeholder={tags.length ? "" : t("editor.tagsPlaceholder")}
          spellCheck={false}
          className="h-6 min-w-32 flex-1 bg-transparent text-sm outline-none placeholder:text-subtle"
        />
      </div>
    </div>
  );
}

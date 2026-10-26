// Editors and views for the field kinds that hold more than a line of text:
// addresses, "sign in with" accounts, places, related items and files, and
// the expiry alert of date fields.

import { Bell, BellOff, ClipboardList, Download, Eye, FileText, Link2, MapPin, Paperclip } from "lucide-react";
import { useMemo } from "react";
import { useTranslation } from "react-i18next";

import { ItemIcon } from "../../components/common";
import { Combobox, IconButton, Input, Menu, MenuContent, MenuItem, MenuLabel, MenuRadioGroup, MenuRadioItem, MenuTrigger, cx } from "../../components/ui";
import { api, errorCode, errorMessage, type Address, type AttachmentView, type ExpiryAlert, type Field, type FieldView, type FileInfo } from "../../lib/api";
import { EXPIRY_ALERTS, PROVIDER_NAMES, SIGN_IN_PROVIDERS, categoryLabel } from "../../lib/categories";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";

// ----- shared -------------------------------------------------------------------------

const ADDRESS_PARTS = ["street", "line2", "city", "state", "zip", "country"] as const;

/** The address as text, as Keyless stores it in the field's value. */
export function formatAddress(address: Address): string {
  const cityLine = [address.city, address.state, address.zip].map((p) => p?.trim()).filter(Boolean).join(", ");
  return [address.street, address.line2, cityLine, address.country]
    .map((p) => p?.trim())
    .filter(Boolean)
    .join("\n");
}

export function providerName(provider: string): string {
  return PROVIDER_NAMES[provider as keyof typeof PROVIDER_NAMES] ?? provider;
}

/** A map of the place: by its coordinates when known, otherwise by text. */
function mapUrl(service: "osm" | "google", query: string, geo: string): string {
  const point = geo.match(/^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$/);
  if (service === "osm") {
    return point
      ? `https://www.openstreetmap.org/?mlat=${point[1]}&mlon=${point[2]}#map=17/${point[1]}/${point[2]}`
      : `https://www.openstreetmap.org/search?query=${encodeURIComponent(query)}`;
  }
  return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(point ? `${point[1]},${point[2]}` : query)}`;
}

async function copyText(label: string, text: string) {
  try {
    const result = await api.copyText(text);
    toast.copied(label, result.clearAfterSeconds);
  } catch (err) {
    toast.error(errorMessage(err));
  }
}

function openLink(url: string) {
  api.openLink(url).catch((err) => toast.error(errorMessage(err)));
}

/** "Open in a map" for an address or a place. */
export function MapMenu({ query, geo = "" }: { query: string; geo?: string }) {
  const { t } = useTranslation();
  if (!query.trim() && !geo.trim()) return null;
  return (
    <Menu>
      <MenuTrigger asChild>
        <IconButton label={t("fields.openMap")}>
          <MapPin className="size-4" />
        </IconButton>
      </MenuTrigger>
      <MenuContent>
        <MenuItem onSelect={() => openLink(mapUrl("osm", query, geo))}>{t("fields.openInOsm")}</MenuItem>
        <MenuItem onSelect={() => openLink(mapUrl("google", query, geo))}>{t("fields.openInGoogle")}</MenuItem>
      </MenuContent>
    </Menu>
  );
}

// ----- editors ------------------------------------------------------------------------

/** Date fields: when to warn before the date. */
export function AlertButton({ value, onChange }: { value: ExpiryAlert | null | undefined; onChange: (alert: ExpiryAlert | null) => void }) {
  const { t } = useTranslation();
  const current = value ?? "auto";
  const Icon = value === "never" ? BellOff : Bell;
  return (
    <Menu>
      <MenuTrigger asChild>
        <IconButton label={`${t("fields.alert")}: ${t(`fields.alerts.${current}`)}`} tabIndex={-1} className={cx("mt-0.5", value && value !== "never" && "text-accent")}>
          <Icon className="size-4" />
        </IconButton>
      </MenuTrigger>
      <MenuContent>
        <MenuLabel>{t("fields.alert")}</MenuLabel>
        <MenuRadioGroup value={current} onValueChange={(next) => onChange(next === "auto" ? null : (next as ExpiryAlert))}>
          <MenuRadioItem value="auto">{t("fields.alerts.auto")}</MenuRadioItem>
          {EXPIRY_ALERTS.map((alert) => (
            <MenuRadioItem key={alert} value={alert}>
              {t(`fields.alerts.${alert}`)}
            </MenuRadioItem>
          ))}
        </MenuRadioGroup>
      </MenuContent>
    </Menu>
  );
}

export function AddressEditor({ field, onChange }: { field: Field; onChange: (field: Field) => void }) {
  const { t } = useTranslation();
  // An address typed before as plain text starts in the street.
  const address: Address = field.address ?? (field.value ? { street: field.value } : {});
  const set = (part: (typeof ADDRESS_PARTS)[number], value: string) => {
    const next = { ...address, [part]: value };
    onChange({ ...field, address: next, value: formatAddress(next) });
  };
  const input = (part: (typeof ADDRESS_PARTS)[number], className?: string, first?: boolean) => (
    <Input
      value={address[part] ?? ""}
      onChange={(e) => set(part, e.target.value)}
      placeholder={t(`fields.${part}`)}
      className={className}
      {...(first ? { "data-field-value": "" } : {})}
    />
  );
  return (
    <div className="grid grid-cols-2 gap-1.5">
      {input("street", "col-span-2", true)}
      {input("line2", "col-span-2")}
      {input("city")}
      {input("state")}
      {input("zip")}
      {input("country")}
    </div>
  );
}

/** Logins (other items) a field may point to. */
function useItemOptions(exclude: string | null, logins = false) {
  const items = useApp((s) => s.items);
  return useMemo(
    () =>
      items
        .filter((i) => i.id !== exclude && i.trashedAt === null && (!logins || i.category === "login"))
        .map((i) => ({ value: i.id, label: i.subtitle ? `${i.title} · ${i.subtitle}` : i.title })),
    [items, exclude, logins],
  );
}

export function SignInWithEditor({ field, itemId, onChange }: { field: Field; itemId: string | null; onChange: (field: Field) => void }) {
  const { t } = useTranslation();
  const accounts = useItemOptions(itemId, true);
  const providers = SIGN_IN_PROVIDERS.map((p) => ({ value: p as string, label: providerName(p) }));
  const known = SIGN_IN_PROVIDERS.includes(field.value as (typeof SIGN_IN_PROVIDERS)[number]);
  return (
    <div className="grid grid-cols-2 gap-1.5">
      <Combobox
        value={known ? field.value : null}
        onChange={(value) => onChange({ ...field, value })}
        options={providers}
        placeholder={known || !field.value ? t("fields.provider") : field.value}
        searchPlaceholder={t("common.searchPlaceholder")}
      />
      <Combobox
        value={field.link || null}
        onChange={(link) => onChange({ ...field, link })}
        options={[{ value: "", label: t("fields.noAccount") }, ...accounts]}
        placeholder={t("fields.account")}
        searchPlaceholder={t("common.searchPlaceholder")}
      />
    </div>
  );
}

export function LocationEditor({ field, onChange }: { field: Field; onChange: (field: Field) => void }) {
  const { t } = useTranslation();
  const geoValid = !field.geo || /^\s*-?\d+(\.\d+)?\s*,\s*-?\d+(\.\d+)?\s*$/.test(field.geo);
  return (
    <div className="grid grid-cols-3 gap-1.5">
      <Input value={field.value} onChange={(e) => onChange({ ...field, value: e.target.value })} placeholder={t("fields.place")} className="col-span-2" data-field-value="" />
      <Input
        value={field.geo ?? ""}
        onChange={(e) => onChange({ ...field, geo: e.target.value })}
        placeholder={t("fields.coordinates")}
        invalid={!geoValid}
        className="font-mono text-[13px]"
      />
    </div>
  );
}

export function ReferenceEditor({ field, itemId, onChange }: { field: Field; itemId: string | null; onChange: (field: Field) => void }) {
  const { t } = useTranslation();
  const options = useItemOptions(itemId);
  const items = useApp((s) => s.items);
  return (
    <Combobox
      value={field.link || null}
      onChange={(link) => onChange({ ...field, link, value: items.find((i) => i.id === link)?.title ?? "" })}
      options={options}
      placeholder={t("fields.chooseItem")}
      searchPlaceholder={t("common.searchPlaceholder")}
    />
  );
}

/** A file field: one of the item's attachments, or a file to attach on save. */
export function FileFieldEditor({
  field,
  attachments,
  pending,
  onChange,
  onPick,
}: {
  field: Field;
  attachments: AttachmentView[];
  /** The file chosen for it, attached when the item is saved. */
  pending: FileInfo | undefined;
  onChange: (field: Field) => void;
  onPick: () => void;
}) {
  const { t } = useTranslation();
  const options = attachments.map((a) => ({ value: a.id, label: a.name }));
  return (
    <div className="flex items-center gap-1.5">
      <div className="min-w-0 flex-1">
        {pending ? (
          <div className="flex h-9 items-center gap-2 rounded-lg border border-line px-3 text-sm">
            <Paperclip className="size-4 shrink-0 text-accent" />
            <span className="truncate">{pending.name}</span>
            <span className="shrink-0 text-xs text-subtle">· {t("editor.addOnSave")}</span>
          </div>
        ) : (
          <Combobox
            value={field.value || null}
            onChange={(value) => onChange({ ...field, value })}
            options={options}
            placeholder={attachments.length ? t("fields.chooseAttachment") : t("fields.noFile")}
            searchPlaceholder={t("common.searchPlaceholder")}
          />
        )}
      </div>
      <IconButton label={t("fields.chooseFile")} onClick={onPick} tabIndex={-1}>
        <Paperclip className="size-4" />
      </IconButton>
    </div>
  );
}

// ----- views --------------------------------------------------------------------------

/** How a field of these kinds shows in the item; null for other kinds. */
export function SpecialValue({ field, attachments, onPreview }: { field: FieldView; attachments: AttachmentView[]; onPreview: (attachment: AttachmentView) => void }) {
  const { t } = useTranslation();
  const items = useApp((s) => s.items);
  const select = useApp((s) => s.select);
  switch (field.kind) {
    case "address":
      return <span className="selectable whitespace-pre-wrap break-words text-[15px]">{field.value}</span>;
    case "sign_in_with": {
      const account = items.find((i) => i.id === field.link);
      return (
        <span className="flex flex-wrap items-center gap-x-2 text-[15px]">
          {t("fields.signInWith", { provider: providerName(field.value ?? "") })}
          {account && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                select(account.id);
              }}
              className="inline-flex items-center gap-1 text-[13px] text-accent hover:underline"
            >
              <Link2 className="size-3.5" />
              {account.subtitle || account.title}
            </button>
          )}
        </span>
      );
    }
    case "location":
      return (
        <span className="selectable text-[15px]">
          {field.value}
          {field.geo && <span className="ml-2 font-mono text-xs text-subtle">{field.geo}</span>}
        </span>
      );
    case "reference": {
      const target = items.find((i) => i.id === field.link);
      if (!target) return <span className="text-[15px] text-subtle">{field.value || t("fields.itemMissing")}</span>;
      return (
        <span
          role="link"
          tabIndex={0}
          onClick={(e) => {
            e.stopPropagation();
            select(target.id);
          }}
          className="inline-flex items-center gap-2 text-[15px] text-accent hover:underline"
        >
          <ItemIcon title={target.title} category={target.category} url={target.iconUrl ?? undefined} size="sm" />
          <span>
            {target.title}
            <span className="ml-1.5 text-xs text-subtle">{categoryLabel(target.category)}</span>
          </span>
        </span>
      );
    }
    case "file": {
      const attachment = attachments.find((a) => a.id === field.value);
      if (!attachment) return <span className="text-[15px] text-subtle">{t("fields.fileMissing")}</span>;
      return (
        <span className="inline-flex items-center gap-2 text-[15px]">
          <FileText className="size-4 text-accent" />
          {attachment.name}
          <button
            onClick={(e) => {
              e.stopPropagation();
              onPreview(attachment);
            }}
            className="rounded p-0.5 text-subtle hover:text-fg"
            aria-label={t("item.attachmentPreview")}
          >
            <Eye className="size-4" />
          </button>
        </span>
      );
    }
    default:
      return null;
  }
}

/** Extra actions on a field of these kinds (the row has copy already). */
export function SpecialActions({ itemId, field, attachments }: { itemId: string; field: FieldView; attachments: AttachmentView[] }) {
  const { t } = useTranslation();
  if (field.kind === "address") {
    const address = field.address ?? {};
    const parts = ADDRESS_PARTS.filter((p) => address[p]?.trim());
    return (
      <>
        {parts.length > 1 && (
          <Menu>
            <MenuTrigger asChild>
              <IconButton label={t("fields.copyPart")}>
                <ClipboardList className="size-4" />
              </IconButton>
            </MenuTrigger>
            <MenuContent>
              <MenuLabel>{t("fields.copyPart")}</MenuLabel>
              {parts.map((part) => (
                <MenuItem key={part} onSelect={() => void copyText(t(`fields.${part}`), address[part] ?? "")}>
                  {t(`fields.${part}`)}
                  <span className="ml-3 max-w-40 truncate text-xs text-subtle">{address[part]}</span>
                </MenuItem>
              ))}
            </MenuContent>
          </Menu>
        )}
        <MapMenu query={(field.value ?? "").replace(/\n/g, ", ")} />
      </>
    );
  }
  if (field.kind === "location") return <MapMenu query={field.value ?? ""} geo={field.geo} />;
  if (field.kind === "file") {
    const attachment = attachments.find((a) => a.id === field.value);
    if (!attachment) return null;
    return (
      <IconButton
        label={t("item.attachmentSave")}
        onClick={() => api.attachmentSave(itemId, attachment.id).catch((err) => errorCode(err) !== "cancelled" && toast.error(errorMessage(err)))}
      >
        <Download className="size-4" />
      </IconButton>
    );
  }
  return null;
}

/** "Expires …, alert 2 weeks before" under a date field. */
export function AlertNote({ field }: { field: FieldView }) {
  const { t } = useTranslation();
  if (!field.alert || field.alert === "never") return null;
  return (
    <div className="mt-0.5 flex items-center gap-1 text-xs text-subtle">
      <Bell className="size-3" /> {t("fields.alertBefore", { when: t(`fields.alerts.${field.alert}`) })}
    </div>
  );
}


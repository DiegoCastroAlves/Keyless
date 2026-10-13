// Dialogs of the item view: a value in large type (and as a QR code), a
// decoded token, an attachment's preview, printing, and copying the item to
// another vault.

import { Printer, QrCode, Type } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";

import { Button, Combobox, Dialog, Switch, cx } from "../../components/ui";
import { fieldLabel } from "../../i18n";
import { api, errorMessage, type AttachmentPreview, type AttachmentView, type FieldView, type ItemDetail } from "../../lib/api";
import { categoryLabel, isSecretKind } from "../../lib/categories";
import { formatDate, hostOf } from "../../lib/format";
import { Markdown } from "../../lib/markdown";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";
import { providerName } from "./FieldKinds";

// ----- Large type ---------------------------------------------------------------------

/** Characters drawn big, each numbered, to read a value aloud or type it on
 * another device; and the value as a QR code. */
export function LargeTypeDialog({
  open,
  onOpenChange,
  title,
  value,
  qr,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  /** The value, when it is shown as text. */
  value: string | null;
  /** Makes the QR code (SVG made by Keyless). */
  qr?: () => Promise<string>;
}) {
  const { t } = useTranslation();
  const [mode, setMode] = useState<"text" | "qr">(value === null ? "qr" : "text");
  const [svg, setSvg] = useState<string | null>(null);
  useEffect(() => {
    if (!open) {
      setSvg(null);
      return;
    }
    setMode(value === null ? "qr" : "text");
  }, [open, value]);
  useEffect(() => {
    if (!open || mode !== "qr" || svg || !qr) return;
    qr()
      .then(setSvg)
      .catch((err) => toast.error(errorMessage(err)));
  }, [open, mode, svg, qr]);

  const chars = useMemo(() => Array.from(value ?? ""), [value]);
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={title} width="max-w-3xl">
      {qr && value !== null && (
        <div className="mb-4 flex justify-center gap-1 rounded-lg bg-panel-2 p-0.5 text-xs">
          {(["text", "qr"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={cx("flex items-center gap-1.5 rounded-md px-3 py-1", mode === m ? "bg-panel font-medium shadow-xs" : "text-muted")}
            >
              {m === "text" ? <Type className="size-3.5" /> : <QrCode className="size-3.5" />}
              {m === "text" ? t("largeType.text") : t("largeType.qr")}
            </button>
          ))}
        </div>
      )}
      {mode === "text" ? (
        <div className="selectable flex flex-wrap justify-center gap-1.5">
          {chars.map((c, i) => (
            <div key={i} className="flex w-12 flex-col items-center rounded-lg border border-line bg-panel-2 pb-1 pt-2">
              <span
                className={cx(
                  "font-mono text-4xl leading-none",
                  /\d/.test(c) ? "text-sky-600 dark:text-sky-400" : /[^\p{L}\p{N}]/u.test(c) ? "text-rose-600 dark:text-rose-400" : "text-fg",
                )}
              >
                {c === " " ? "␣" : c === "\n" ? "↵" : c === "\t" ? "⇥" : c}
              </span>
              <span className="mt-1.5 text-[10px] tabular-nums text-subtle">{i + 1}</span>
            </div>
          ))}
        </div>
      ) : svg ? (
        // The QR code's SVG is made by Keyless itself (only rectangles).
        <div className="mx-auto w-72 rounded-xl bg-white p-3 [&>svg]:h-auto [&>svg]:w-full" dangerouslySetInnerHTML={{ __html: svg }} />
      ) : (
        <div className="h-72" />
      )}
    </Dialog>
  );
}

// ----- tokens -------------------------------------------------------------------------

const JWT = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/;

export function isJwt(value: string | null | undefined): boolean {
  return !!value && JWT.test(value.trim());
}

function decodePart(part: string): unknown {
  const base64 = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
  const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

/** A JSON Web Token's header and claims (decoded here, not verified). */
export function JwtDialog({ token, onClose }: { token: string | null; onClose: () => void }) {
  const { t } = useTranslation();
  const decoded = useMemo(() => {
    if (!token) return null;
    try {
      const [header, payload] = token.trim().split(".");
      return { header: decodePart(header), payload: decodePart(payload) as Record<string, unknown> };
    } catch {
      return null;
    }
  }, [token]);
  const date = (key: string) => {
    const value = decoded?.payload[key];
    return typeof value === "number" ? formatDate(value) : null;
  };
  return (
    <Dialog open={token !== null} onOpenChange={(open) => !open && onClose()} title={t("jwt.title")} description={t("jwt.notVerified")} width="max-w-2xl">
      {!decoded ? (
        <p className="text-sm text-danger">{t("jwt.invalid")}</p>
      ) : (
        <div className="space-y-3">
          {(date("exp") || date("iat")) && (
            <div className="flex flex-wrap gap-x-5 text-sm">
              {date("iat") && <span>{t("jwt.issued", { date: date("iat") })}</span>}
              {date("exp") && <span>{t("jwt.expires", { date: date("exp") })}</span>}
            </div>
          )}
          {(["header", "payload"] as const).map((part) => (
            <div key={part}>
              <div className="mb-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t(`jwt.${part}`)}</div>
              <pre className="selectable max-h-64 overflow-auto rounded-lg bg-panel-2 p-3 font-mono text-[12.5px]">{JSON.stringify(decoded[part], null, 2)}</pre>
            </div>
          ))}
        </div>
      )}
    </Dialog>
  );
}

// ----- attachments --------------------------------------------------------------------

export function AttachmentPreviewDialog({ itemId, attachment, onClose }: { itemId: string; attachment: AttachmentView | null; onClose: () => void }) {
  const { t } = useTranslation();
  const [preview, setPreview] = useState<AttachmentPreview | null>(null);
  const close = useRef(onClose);
  close.current = onClose;
  const attachmentId = attachment?.id;
  useEffect(() => {
    setPreview(null);
    if (!attachmentId) return;
    let current = true;
    api
      .attachmentPreview(itemId, attachmentId)
      .then((p) => current && setPreview(p))
      .catch((err) => {
        toast.error(errorMessage(err));
        close.current();
      });
    return () => {
      current = false;
    };
  }, [itemId, attachmentId]);
  return (
    <Dialog open={attachment !== null} onOpenChange={(open) => !open && onClose()} title={attachment?.name ?? ""} width="max-w-4xl">
      {!preview ? (
        <div className="py-16 text-center text-sm text-muted">{t("item.attachmentLoading")}</div>
      ) : preview.kind === "image" ? (
        <img src={preview.src} alt={attachment?.name} className="mx-auto max-h-[70vh] rounded-lg object-contain" />
      ) : preview.kind === "text" ? (
        <pre className="selectable max-h-[70vh] overflow-auto whitespace-pre-wrap break-words rounded-lg bg-panel-2 p-3 font-mono text-[12.5px]">{preview.text}</pre>
      ) : (
        <div className="space-y-3 py-6 text-center text-sm text-muted">
          <p>{t("item.attachmentNoPreview")}</p>
          <Button onClick={() => attachment && api.attachmentSave(itemId, attachment.id).catch(() => undefined)}>{t("item.attachmentSave")}</Button>
        </div>
      )}
    </Dialog>
  );
}

/** An attachment shown as an image inside notes (`![](name)`), once loaded. */
export function NoteImage({ itemId, attachment, alt }: { itemId: string; attachment: AttachmentView; alt: string }) {
  const [src, setSrc] = useState<string | null>(null);
  useEffect(() => {
    let current = true;
    api
      .attachmentPreview(itemId, attachment.id)
      .then((p) => current && p.kind === "image" && setSrc(p.src))
      .catch(() => undefined);
    return () => {
      current = false;
    };
  }, [itemId, attachment.id]);
  return src ? <img src={src} alt={alt} className="my-1 max-h-96 max-w-full rounded-lg" /> : <span className="text-subtle">{alt || attachment.name}</span>;
}

// ----- copy to another vault ----------------------------------------------------------

export function CopyToVaultDialog({ item, open, onOpenChange }: { item: ItemDetail; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const vaults = useApp((s) => s.vaults);
  const options = vaults.filter((v) => v.canWrite && v.id !== item.vaultId).map((v) => ({ value: v.id, label: v.name }));
  const [vaultId, setVaultId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const first = options[0]?.value ?? null;
  useEffect(() => {
    if (open) setVaultId(first);
  }, [open, first]);
  const copy = async () => {
    if (!vaultId) return;
    setBusy(true);
    try {
      const copied = await api.copyItemToVault(item.id, vaultId);
      onOpenChange(false);
      await useApp.getState().loadData();
      const vault = vaults.find((v) => v.id === vaultId)?.name ?? "";
      toast.undoable(t("copyToVault.done", { vault }), () => {
        void api
          .deleteItemsPermanently([copied.id])
          .then(() => useApp.getState().loadData())
          .catch((err) => toast.error(errorMessage(err)));
      });
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("copyToVault.title", { title: item.title })} description={t("copyToVault.body")}>
      {options.length === 0 ? (
        <p className="text-sm text-muted">{t("copyToVault.noVault")}</p>
      ) : (
        <div className="space-y-4">
          <Combobox value={vaultId} onChange={setVaultId} options={options} searchPlaceholder={t("common.searchPlaceholder")} />
          <div className="flex justify-end gap-2">
            <Button onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
            <Button variant="primary" onClick={copy} loading={busy} disabled={!vaultId}>
              {t("copyToVault.action")}
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}

// ----- printing -----------------------------------------------------------------------

interface PrintField {
  label: string;
  value: string;
}

/** Prints the item; hidden values only when the user asks for them. */
export function PrintDialog({ item, open, onOpenChange }: { item: ItemDetail; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const vaults = useApp((s) => s.vaults);
  const [secrets, setSecrets] = useState(false);
  const [page, setPage] = useState<{ sections: { title: string; fields: PrintField[] }[] } | null>(null);

  const valueOf = async (field: FieldView): Promise<string> => {
    if (field.kind === "address" || !isSecretKind(field)) {
      if (field.kind === "sign_in_with") return t("fields.signInWith", { provider: providerName(field.value ?? "") });
      if (field.kind === "file") return item.attachments.find((a) => a.id === field.value)?.name ?? "";
      return field.value ?? "";
    }
    if (!secrets || field.kind === "totp") return "••••••••";
    return api.revealField(item.id, field.id);
  };

  const print = async () => {
    try {
      const groups = [{ title: "", fields: item.fields }, ...item.sections.map((s) => ({ title: s.title, fields: s.fields }))];
      const sections = [];
      for (const group of groups) {
        const fields: PrintField[] = [];
        for (const field of group.fields.filter((f) => f.hasValue)) fields.push({ label: fieldLabel(field.label) || t("item.value"), value: await valueOf(field) });
        if (fields.length) sections.push({ title: group.title, fields });
      }
      setPage({ sections });
      onOpenChange(false);
      // Once the page is drawn; the values go as soon as printing is done.
      setTimeout(() => {
        window.print();
        setPage(null);
      }, 150);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const vault = vaults.find((v) => v.id === item.vaultId)?.name;
  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange} title={t("print.title")} description={t("print.body")}>
        <div className="space-y-4">
          <label className="flex items-center justify-between gap-4 rounded-lg border border-line px-3 py-2.5 text-sm">
            <span>
              {t("print.secrets")}
              <span className="block text-xs text-muted">{t("print.secretsHint")}</span>
            </span>
            <Switch checked={secrets} onChange={setSecrets} label={t("print.secrets")} />
          </label>
          <div className="flex justify-end gap-2">
            <Button onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
            <Button variant="primary" onClick={() => void print()}>
              <Printer className="size-4" /> {t("print.action")}
            </Button>
          </div>
        </div>
      </Dialog>
      {page &&
        createPortal(
          <div className="print-area print-only bg-white p-10 text-black">
            <h1 className="text-2xl font-semibold">{item.title}</h1>
            <p className="mt-1 text-sm text-neutral-600">
              {categoryLabel(item.category)}
              {vault && ` · ${vault}`}
            </p>
            {page.sections.map((section, i) => (
              <div key={i} className="mt-6">
                {section.title && <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-neutral-500">{section.title}</h2>}
                <table className="w-full border-collapse text-sm">
                  <tbody>
                    {section.fields.map((f, j) => (
                      <tr key={j} className="border-b border-neutral-200">
                        <td className="w-1/3 py-1.5 pr-4 align-top text-neutral-600">{f.label}</td>
                        <td className="whitespace-pre-wrap break-all py-1.5 font-mono">{f.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
            {item.urlEntries.length > 0 && (
              <div className="mt-6 text-sm">
                <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-neutral-500">{t("item.websites")}</h2>
                {item.urlEntries.map((u, i) => (
                  <div key={i}>{u.label ? `${u.label}: ${u.href}` : u.href || hostOf(u.href)}</div>
                ))}
              </div>
            )}
            {item.notes && (
              <div className="mt-6 text-sm">
                <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-neutral-500">{t("item.notes")}</h2>
                <div className="[&_a]:text-black [&_code]:bg-neutral-100">
                  <Markdown text={item.notes} options={{ onLink: () => {} }} />
                </div>
              </div>
            )}
            <p className="mt-8 text-xs text-neutral-500">{t("print.footer", { date: formatDate(Math.floor(Date.now() / 1000)) })}</p>
          </div>,
          document.body,
        )}
    </>
  );
}

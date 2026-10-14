import { Copy, Link2, Mail, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button, Combobox, Dialog, ErrorText, Input, Label, Switch } from "../../components/ui";
import { api, errorMessage, type CreatedShare, type ShareView } from "../../lib/api";
import { formatDate } from "../../lib/format";
import { toast } from "../../lib/toast";

const DURATIONS = ["1", "24", "168", "336", "720"] as const;
type Duration = (typeof DURATIONS)[number];

/** Creates a link that shows a copy of the item to someone without
 * Keyless, and lists the item's links that still work, to revoke them. */
export function ShareDialog({ open, onOpenChange, itemId, title }: { open: boolean; onOpenChange: (open: boolean) => void; itemId: string; title: string }) {
  const { t } = useTranslation();
  const [duration, setDuration] = useState<Duration>("168");
  const [viewOnce, setViewOnce] = useState(false);
  const [who, setWho] = useState<"anyone" | "emails">("anyone");
  const [emails, setEmails] = useState<string[]>([]);
  const [draft, setDraft] = useState("");
  const [created, setCreated] = useState<CreatedShare | null>(null);
  const [links, setLinks] = useState<ShareView[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .shareList(itemId)
      .then(setLinks)
      .catch(() => setLinks([]));
  }, [itemId]);

  useEffect(() => {
    if (!open) return;
    setCreated(null);
    setError(null);
    setViewOnce(false);
    setDuration("168");
    setWho("anyone");
    setEmails([]);
    setDraft("");
    setLinks(null);
    load();
  }, [open, load]);

  // Emails typed or pasted, separated by commas, spaces or new lines.
  const addEmails = (text: string) => {
    const found = text
      .split(/[\s,;]+/)
      .map((e) => e.trim().toLowerCase())
      .filter((e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e));
    if (found.length) setEmails((current) => [...new Set([...current, ...found])].slice(0, 20));
    setDraft("");
  };

  const restricted = who === "emails";
  const pendingDraft = draft.trim();
  const recipients = restricted ? [...new Set([...emails, ...(pendingDraft.includes("@") ? [pendingDraft.toLowerCase()] : [])])] : [];

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      setCreated(await api.shareCreate(itemId, Number(duration), viewOnce, recipients));
      load();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    if (!created) return;
    try {
      const result = await api.copyText(created.link);
      toast.copied(t("share.link"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const revoke = async (id: string) => {
    try {
      await api.shareRevoke(id);
      toast.success(t("share.revoked"));
      if (created?.id === id) setCreated(null);
      load();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const durationLabel = (d: Duration) =>
    Number(d) < 24 ? t("share.hours", { count: Number(d) }) : t("share.days", { count: Number(d) / 24 });

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("share.title", { title })} description={t("share.description")} width="max-w-lg">
      {created ? (
        <div className="space-y-3">
          <Label>{t("share.link")}</Label>
          <div className="flex gap-2">
            <Input readOnly value={created.link} onFocus={(e) => e.currentTarget.select()} className="font-mono text-xs" />
            <Button onClick={copy}>
              <Copy className="size-3.5" /> {t("common.copy")}
            </Button>
          </div>
          <p className="text-xs text-muted">{t("share.onlyNow", { date: formatDate(created.expiresAt) })}</p>
          {restricted && <p className="text-xs leading-relaxed text-muted">{t("share.restrictedCreated", { emails: recipients.join(", ") })}</p>}
        </div>
      ) : (
        <div className="space-y-4">
          <div>
            <Label>{t("share.expires")}</Label>
            <Combobox
              value={duration}
              onChange={setDuration}
              options={DURATIONS.map((d) => ({ value: d, label: durationLabel(d) }))}
              className="mt-1.5 w-full"
            />
          </div>
          <div>
            <Label>{t("share.who")}</Label>
            <Combobox
              value={who}
              onChange={setWho}
              options={[
                { value: "anyone", label: t("share.anyone") },
                { value: "emails", label: t("share.onlyEmails") },
              ]}
              className="mt-1.5 w-full"
            />
            {restricted && (
              <div className="mt-2 space-y-2">
                <div className="flex flex-wrap gap-1.5 rounded-lg border border-line bg-panel px-2 py-1.5 focus-within:border-accent">
                  {emails.map((email) => (
                    <span key={email} className="flex items-center gap-1 rounded-md bg-accent-soft px-2 py-0.5 text-xs text-accent">
                      <Mail className="size-3" /> {email}
                      <button type="button" aria-label={t("common.remove")} onClick={() => setEmails((list) => list.filter((e) => e !== email))}>
                        <X className="size-3" />
                      </button>
                    </span>
                  ))}
                  <input
                    value={draft}
                    onChange={(e) => {
                      const value = e.target.value;
                      if (/[\s,;]$/.test(value)) addEmails(value);
                      else setDraft(value);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        addEmails(draft);
                      } else if (e.key === "Backspace" && !draft && emails.length) {
                        setEmails((list) => list.slice(0, -1));
                      }
                    }}
                    onPaste={(e) => {
                      e.preventDefault();
                      addEmails(draft + " " + e.clipboardData.getData("text"));
                    }}
                    onBlur={() => draft && addEmails(draft)}
                    placeholder={emails.length ? "" : t("share.emailsPlaceholder")}
                    className="h-7 min-w-40 flex-1 bg-transparent text-sm outline-none"
                  />
                </div>
                <p className="text-xs leading-relaxed text-muted">{t("share.emailsHint")}</p>
              </div>
            )}
          </div>
          <label className="flex items-center gap-2.5 text-sm">
            <Switch checked={viewOnce} onChange={setViewOnce} label={t("share.viewOnce")} />
            {t("share.viewOnce")}
          </label>
          {error && <ErrorText>{error}</ErrorText>}
          <div className="flex justify-end">
            <Button variant="primary" onClick={create} loading={busy} disabled={restricted && recipients.length === 0}>
              <Link2 className="size-3.5" /> {t("share.create")}
            </Button>
          </div>
        </div>
      )}

      {links && links.length > 0 && (
        <div className="mt-6 border-t border-line pt-4">
          <div className="mb-2 text-xs font-medium text-subtle">{t("share.active")}</div>
          <ul className="space-y-1.5">
            {links.map((link) => (
              <li key={link.id} className="flex items-center gap-3 rounded-lg bg-panel-2 px-3 py-2 text-xs">
                <span className="flex-1 text-muted">
                  {t("share.until", { date: formatDate(link.expiresAt) })}
                  {" · "}
                  {link.maxViews === null ? t("share.views", { count: link.views }) : t("share.viewsOf", { count: link.views, max: link.maxViews })}
                  {link.recipients.length > 0 && (
                    <span className="mt-0.5 block truncate text-subtle" title={link.recipients.join(", ")}>
                      {t("share.onlyFor", { emails: link.recipients.join(", ") })}
                    </span>
                  )}
                </span>
                <Button size="sm" variant="ghost" onClick={() => revoke(link.id)}>
                  {t("share.revoke")}
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Dialog>
  );
}

import { Copy, Link2 } from "lucide-react";
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
    setLinks(null);
    load();
  }, [open, load]);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      setCreated(await api.shareCreate(itemId, Number(duration), viewOnce));
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
          <label className="flex items-center gap-2.5 text-sm">
            <Switch checked={viewOnce} onChange={setViewOnce} label={t("share.viewOnce")} />
            {t("share.viewOnce")}
          </label>
          {error && <ErrorText>{error}</ErrorText>}
          <div className="flex justify-end">
            <Button variant="primary" onClick={create} loading={busy}>
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

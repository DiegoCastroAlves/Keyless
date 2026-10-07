import { ExternalLink } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button, Dialog, Spinner, cx } from "../../components/ui";
import { api, errorMessage, type ShareView } from "../../lib/api";
import { formatDate } from "../../lib/format";
import { useApp } from "../../lib/store";
import { toast } from "../../lib/toast";

/** Every link the account shared recently, with what became of it. Ended
 * links stay listed for a day, until the server purges them. */
export function SharesDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const [links, setLinks] = useState<ShareView[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    api
      .shareList(undefined, true)
      .then(setLinks)
      .catch((err) => setError(errorMessage(err)));
  }, []);

  useEffect(() => {
    if (open) {
      setLinks(null);
      load();
    }
  }, [open, load]);

  const revoke = async (id: string) => {
    try {
      await api.shareRevoke(id);
      toast.success(t("share.revoked"));
      load();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const openItem = (itemId: string) => {
    const store = useApp.getState();
    if (!store.items.some((i) => i.id === itemId)) {
      toast.error(t("share.itemGone"));
      return;
    }
    store.setView({ kind: "all" });
    store.select(itemId);
    onOpenChange(false);
  };

  const tone: Record<ShareView["status"], string> = {
    active: "bg-accent-soft text-accent",
    expired: "bg-panel-3 text-muted",
    revoked: "bg-danger-soft text-danger",
    used: "bg-panel-3 text-muted",
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("share.listTitle")} description={t("share.listBody")} width="max-w-2xl">
      {error && <p className="text-sm text-danger">{error}</p>}
      {!links && !error && (
        <div className="flex justify-center py-10">
          <Spinner className="size-5 text-accent" />
        </div>
      )}
      {links && links.length === 0 && <p className="py-8 text-center text-sm text-muted">{t("share.listEmpty")}</p>}
      {links && links.length > 0 && (
        <ul className="max-h-[60vh] divide-y divide-line overflow-y-auto rounded-xl border border-line">
          {links.map((link) => (
            <li key={link.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium">{link.title}</span>
                  <span className={cx("shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium", tone[link.status])}>{t(`share.status_${link.status}`)}</span>
                </div>
                <div className="mt-0.5 text-xs text-muted">
                  {t("share.created", { date: formatDate(link.createdAt) })}
                  {" · "}
                  {t(link.status === "active" ? "share.until" : link.status === "expired" ? "share.expiredOn" : "share.wasUntil", { date: formatDate(link.expiresAt) })}
                  {" · "}
                  {link.maxViews === null ? t("share.views", { count: link.views }) : t("share.viewsOf", { count: link.views, max: link.maxViews })}
                </div>
              </div>
              <div className="flex shrink-0 gap-1.5">
                <Button size="sm" variant="ghost" onClick={() => openItem(link.itemId)}>
                  <ExternalLink className="size-3.5" /> {t("share.openItem")}
                </Button>
                {link.status === "active" && (
                  <Button size="sm" onClick={() => revoke(link.id)}>
                    {t("share.revoke")}
                  </Button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Dialog>
  );
}

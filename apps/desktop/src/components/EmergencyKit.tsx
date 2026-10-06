import { Copy, Printer } from "lucide-react";
import { useTranslation } from "react-i18next";

import { api, errorMessage } from "../lib/api";
import { toast } from "../lib/toast";
import { Logo } from "./common";
import { Button } from "./ui";

/**
 * The Emergency Kit holds what someone needs to get back into their account
 * on a new device: the email, the Secret Key and (written by hand) the
 * master password.
 */
export function EmergencyKit({ email, secretKey }: { email: string; secretKey: string }) {
  const { t, i18n } = useTranslation();
  const created = new Date().toLocaleDateString(i18n.language, { year: "numeric", month: "long", day: "numeric" });

  const copy = async () => {
    try {
      const result = await api.copyText(secretKey);
      toast.copied(t("common.secretKey"), result.clearAfterSeconds);
    } catch {
      // Not signed in yet (e.g. waiting for email confirmation): fall back
      // to the browser clipboard.
      try {
        await navigator.clipboard.writeText(secretKey);
        toast.success(t("kit.copy"));
      } catch (err) {
        toast.error(errorMessage(err));
      }
    }
  };

  return (
    <div>
      <div className="print-area rounded-2xl border border-line bg-panel p-6 shadow-sm print:border-0 print:shadow-none">
        <div className="flex items-center gap-3">
          <Logo className="size-10" />
          <div>
            <div className="text-lg font-semibold">{t("kit.title")}</div>
            <div className="text-xs text-muted">{t("kit.created", { date: created })}</div>
          </div>
        </div>
        <p className="mt-4 text-[13px] leading-relaxed text-muted">{t("kit.intro")}</p>
        <dl className="mt-5 space-y-4">
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-subtle">{t("common.email")}</dt>
            <dd className="selectable mt-1 font-medium">{email}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-subtle">{t("common.secretKey")}</dt>
            <dd className="selectable mt-1 rounded-lg border border-dashed border-accent bg-accent-soft px-3 py-2.5 text-center font-mono text-[15px] font-semibold tracking-wider text-fg">
              {secretKey}
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-subtle">{t("common.masterPassword")}</dt>
            <dd className="mt-1 h-9 rounded-lg border border-line bg-panel-2 print:bg-white" />
            <dd className="mt-1 text-[11px] text-subtle">{t("kit.writeByHand")}</dd>
          </div>
        </dl>
      </div>
      <div className="no-print mt-3 flex gap-2">
        <Button className="flex-1" onClick={copy}>
          <Copy className="size-4" /> {t("kit.copy")}
        </Button>
        <Button className="flex-1" onClick={() => window.print()}>
          <Printer className="size-4" /> {t("kit.print")}
        </Button>
      </div>
    </div>
  );
}

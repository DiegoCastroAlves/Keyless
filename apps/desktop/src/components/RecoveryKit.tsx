import { Copy, LifeBuoy, Printer } from "lucide-react";
import { useTranslation } from "react-i18next";

import { api, errorMessage } from "../lib/api";
import { toast } from "../lib/toast";
import { Button } from "./ui";

/**
 * The recovery key, laid out to print or copy: with the account's email it
 * gets the user back in when the master password is forgotten or the Secret
 * Key lost.
 */
export function RecoveryKit({ email, recoveryKey }: { email: string; recoveryKey: string }) {
  const { t, i18n } = useTranslation();
  const created = new Date().toLocaleDateString(i18n.language, { year: "numeric", month: "long", day: "numeric" });

  // Copied by Rust with the protected clipboard.
  const copy = async () => {
    try {
      const result = await api.recoveryCopy("recovery_key");
      toast.copied(t("recovery.keyLabel"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <div>
      <div className="print-area rounded-2xl border border-line bg-panel p-6 shadow-sm print:border-0 print:shadow-none">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-xl bg-accent-soft text-accent">
            <LifeBuoy className="size-5" />
          </div>
          <div>
            <div className="text-lg font-semibold">{t("recovery.kitTitle")}</div>
            <div className="text-xs text-muted">{t("kit.created", { date: created })}</div>
          </div>
        </div>
        <p className="mt-4 text-[13px] leading-relaxed text-muted">{t("recovery.kitIntro")}</p>
        <dl className="mt-5 space-y-4">
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-subtle">{t("common.email")}</dt>
            <dd className="selectable mt-1 font-medium">{email}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-subtle">{t("recovery.keyLabel")}</dt>
            <dd className="selectable mt-1 rounded-lg border border-dashed border-accent bg-accent-soft px-3 py-2.5 text-center font-mono text-[14px] font-semibold leading-relaxed tracking-wider text-fg">
              {recoveryKey}
            </dd>
          </div>
        </dl>
      </div>
      <div className="no-print mt-3 flex gap-2">
        <Button className="flex-1" onClick={copy}>
          <Copy className="size-4" /> {t("recovery.copy")}
        </Button>
        <Button className="flex-1" onClick={() => window.print()}>
          <Printer className="size-4" /> {t("kit.print")}
        </Button>
      </div>
    </div>
  );
}

import { Copy, FileDown, Printer } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { api, errorMessage, isCancelled, type SetupQr } from "../lib/api";
import { toast } from "../lib/toast";
import { Logo } from "./common";
import { Button } from "./ui";

/**
 * The Emergency Kit holds what someone needs to get back into their account
 * on a new device: the email, the Secret Key and (written by hand) the
 * master password. Its setup code (a QR code of the email and Secret Key)
 * fills in the sign-in form of a new device, read with the camera or from
 * the screen, or by opening the Kit's PDF in Keyless.
 */
export function EmergencyKit({ email, secretKey, recovering = false }: { email: string; secretKey: string; recovering?: boolean }) {
  const { t, i18n } = useTranslation();
  const created = new Date().toLocaleDateString(i18n.language, { year: "numeric", month: "long", day: "numeric" });
  const [qr, setQr] = useState<SetupQr | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .kitSetupCode(email, secretKey)
      .then((code) => live && setQr(code))
      .catch(() => live && setQr(null));
    return () => {
      live = false;
    };
  }, [email, secretKey]);

  const savePdf = async () => {
    setSaving(true);
    try {
      await api.saveEmergencyKit(
        {
          title: t("kit.title"),
          created: t("kit.created", { date: created }),
          intro: t("kit.intro"),
          email: t("common.email"),
          secretKey: t("common.secretKey"),
          masterPassword: t("common.masterPassword"),
          writeByHand: t("kit.writeByHand"),
          setupCode: t("kit.setupCode"),
          setupCodeHelp: t("kit.setupCodeHelp"),
        },
        email,
        secretKey,
      );
      toast.success(t("kit.pdfSaved"));
    } catch (err) {
      if (!isCancelled(err)) toast.error(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  // Copied by Rust with the protected clipboard (kept out of clipboard
  // history and cleared after a while), even before the first sign-in. A
  // recovery's new Secret Key is not on the device yet.
  const copy = async () => {
    try {
      const result = recovering ? await api.recoveryCopy("secret_key") : await api.copySecretKey();
      toast.copied(t("common.secretKey"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
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
          {qr && (
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-subtle">{t("kit.setupCode")}</dt>
              <dd className="mt-2 flex items-center gap-4">
                {/* A link too, so a PDF printed from here keeps it. */}
                <a href={qr.link} onClick={(e) => e.preventDefault()} className="block size-28 shrink-0 cursor-default overflow-hidden rounded-lg border border-line bg-white p-1">
                  <img src={`data:image/svg+xml;utf8,${encodeURIComponent(qr.svg)}`} alt="" className="size-full" />
                </a>
                <span className="text-[12px] leading-relaxed text-muted">{t("kit.setupCodeHelp")}</span>
              </dd>
            </div>
          )}
        </dl>
      </div>
      <div className="no-print mt-3 grid grid-cols-3 gap-2">
        <Button onClick={copy}>
          <Copy className="size-4" /> {t("kit.copy")}
        </Button>
        <Button onClick={savePdf} loading={saving}>
          <FileDown className="size-4" /> {t("kit.savePdf")}
        </Button>
        <Button onClick={() => window.print()}>
          <Printer className="size-4" /> {t("kit.printOnly")}
        </Button>
      </div>
    </div>
  );
}

import { Globe } from "lucide-react";
import { useTranslation } from "react-i18next";

import { api, errorMessage } from "../lib/api";
import { useApp } from "../lib/store";
import { toast } from "../lib/toast";
import { Button, Dialog } from "./ui";

/** Asks whether a browser Keyless does not know (installed on the system)
 * may connect: its extension is refused until the user allows it (the
 * request is kept by App, which listens from the start). */
export function BrowserRequestDialog() {
  const { t } = useTranslation();
  const request = useApp((s) => s.browserRequest);

  const answer = (allow: boolean) => {
    if (request) api.bridgeBrowserRespond(request.requestId, allow).catch((err) => toast.error(errorMessage(err)));
    useApp.setState({ browserRequest: null });
  };

  return (
    <Dialog
      open={!!request}
      onOpenChange={(open) => !open && answer(false)}
      title={t("browserRequest.title")}
      description={t("browserRequest.body", { name: request?.name ?? "" })}
      hideClose
    >
      <div className="flex items-center gap-3 rounded-xl border border-line bg-panel-2 px-4 py-3">
        <Globe className="size-5 shrink-0 text-accent" />
        <div className="min-w-0">
          <div className="truncate text-sm font-medium">{request?.name}</div>
          <div className="break-all font-mono text-xs text-muted">{request?.path}</div>
        </div>
      </div>
      <p className="mt-3 text-xs leading-relaxed text-muted">{t("browserRequest.hint")}</p>
      <div className="mt-5 flex justify-end gap-2">
        <Button onClick={() => answer(false)}>{t("browserRequest.deny")}</Button>
        <Button variant="primary" onClick={() => answer(true)}>
          {t("browserRequest.allow")}
        </Button>
      </div>
    </Dialog>
  );
}

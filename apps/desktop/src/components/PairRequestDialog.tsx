import { Globe } from "lucide-react";
import { useTranslation } from "react-i18next";

import { api } from "../lib/api";
import { useApp } from "../lib/store";
import { Button, Dialog } from "./ui";

/** Asks the user to approve a browser extension that wants to connect (the
 * request is kept by App, which listens from the start). */
export function PairRequestDialog() {
  const { t } = useTranslation();
  const request = useApp((s) => s.pairRequest);
  const setRequest = (next: null) => useApp.setState({ pairRequest: next });

  const answer = (approve: boolean) => {
    if (request) void api.bridgePairRespond(request.requestId, approve);
    setRequest(null);
  };

  return (
    <Dialog
      open={!!request}
      onOpenChange={(open) => !open && answer(false)}
      title={t("pairing.title")}
      description={t("pairing.body", { name: request?.name ?? "" })}
      hideClose
    >
      <div className="flex flex-col items-center gap-3 rounded-xl border border-line bg-panel-2 py-5">
        <Globe className="size-6 text-accent" />
        <div className="font-mono text-3xl font-semibold tracking-[0.2em]">{request?.code}</div>
        <p className="px-6 text-center text-xs text-muted">{t("pairing.compare")}</p>
      </div>
      <div className="mt-5 flex justify-end gap-2">
        <Button onClick={() => answer(false)}>{t("pairing.deny")}</Button>
        <Button variant="primary" onClick={() => answer(true)}>
          {t("pairing.allow")}
        </Button>
      </div>
    </Dialog>
  );
}

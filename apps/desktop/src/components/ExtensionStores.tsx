import { ExternalLink } from "lucide-react";
import { useTranslation } from "react-i18next";

import { api, errorMessage } from "../lib/api";
import { toast } from "../lib/toast";
import { Button } from "./ui";

/** The extension's pages in the stores: the Chrome Web Store serves every
 * Chromium browser (its id is in CHROME_EXTENSION_IDS, bridge/mod.rs). */
export const EXTENSION_STORES = [
  { label: "extension.chromium", url: "https://chromewebstore.google.com/detail/hcmaplniiophbidhkclpbicbpleonhja" },
  { label: "extension.firefox", url: "https://addons.mozilla.org/firefox/addon/keyless/" },
] as const;

export function openStore(url: string) {
  api.openLink(url).catch((err) => toast.error(errorMessage(err)));
}

/** A button for each store, opened in the default browser. */
export function ExtensionStores() {
  const { t } = useTranslation();
  return (
    <div className="flex flex-wrap gap-2">
      {EXTENSION_STORES.map((store) => (
        <Button key={store.url} size="sm" onClick={() => openStore(store.url)}>
          <ExternalLink className="size-3.5" /> {t(store.label)}
        </Button>
      ))}
    </div>
  );
}

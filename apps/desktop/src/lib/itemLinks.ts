// Links to items, `keyless://item/<id>`: copied from an item and followed
// from notes, the search box or anywhere else on the computer.

import i18n from "../i18n";
import { api, errorMessage } from "./api";
import { useApp } from "./store";
import { toast } from "./toast";
import { itemWindowId } from "./windows";

const PREFIX = "keyless://item/";

export function itemLink(id: string): string {
  return PREFIX + id;
}

/** The item a link names, if it is a link to an item. */
export function itemIdOfLink(text: string): string | null {
  const link = text.trim();
  if (link.slice(0, PREFIX.length).toLowerCase() !== PREFIX) return null;
  const id = link.slice(PREFIX.length).replace(/\/+$/, "");
  return /^[A-Za-z0-9-]{1,64}$/.test(id) ? id : null;
}

/** Shows the item: selected in the main window, or in a window of its own
 * from an item window. */
export function showLinkedItem(id: string) {
  if (itemWindowId) {
    void api.openItemWindow(id).catch((err) => toast.error(errorMessage(err)));
    return;
  }
  const store = useApp.getState();
  if (!store.items.some((i) => i.id === id)) {
    toast.error(i18n.t("errors.item_link_missing"));
    return;
  }
  store.setSearch("");
  store.setView({ kind: "all" });
  store.select(id);
}

// Which of Keyless's windows this page is in (the same bundle serves them
// all).

import { getCurrentWindow } from "@tauri-apps/api/window";

export const windowLabel = getCurrentWindow().label;

/** Item windows are labeled `item-` and the item's id. */
export const ITEM_WINDOW_PREFIX = "item-";

/** The item this window shows on its own, if it is an item window. */
export const itemWindowId = windowLabel.startsWith(ITEM_WINDOW_PREFIX) ? windowLabel.slice(ITEM_WINDOW_PREFIX.length) : null;

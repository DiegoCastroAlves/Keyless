import { useEffect, useState } from "react";

import { api, events } from "./api";

// Items' own icons, read from their details when first shown and kept
// until Keyless locks.

const cache = new Map<string, string | null>();
const pending = new Map<string, Promise<void>>();
const listeners = new Set<() => void>();

void events.onLocked(() => {
  cache.clear();
  listeners.forEach((listener) => listener());
});

function load(key: string, itemId: string) {
  if (cache.has(key) || pending.has(key)) return;
  pending.set(
    key,
    api
      .itemIcon(itemId)
      .then((icon) => void cache.set(key, icon))
      .catch(() => void cache.set(key, null))
      .finally(() => {
        pending.delete(key);
        listeners.forEach((listener) => listener());
      }),
  );
}

/** The item's own icon (a PNG data URL), when it has one; `stamp` (its last
 * change) makes a changed icon load again. */
export function useItemIcon(itemId: string | undefined, has: boolean | undefined, stamp: number | undefined): string | null {
  const key = itemId && has ? `${itemId}:${stamp ?? 0}` : "";
  const [, rerender] = useState(0);
  useEffect(() => {
    if (!key || !itemId) return;
    const listener = () => rerender((n) => n + 1);
    listeners.add(listener);
    load(key, itemId);
    return () => {
      listeners.delete(listener);
    };
  }, [key, itemId]);
  return key ? (cache.get(key) ?? null) : null;
}

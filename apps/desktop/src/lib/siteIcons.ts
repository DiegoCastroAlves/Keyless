import { useEffect, useState } from "react";

import { api, events, type SiteIcon } from "./api";
import { hostOf } from "./format";

// Website icons from the app's encrypted cache (see site_icons.rs), asked
// for in batches as items appear on screen.

const cache = new Map<string, SiteIcon | null>();
const listeners = new Set<() => void>();
let queued = new Set<string>();
let timer: ReturnType<typeof setTimeout> | null = null;

function flush() {
  timer = null;
  const hosts = [...queued];
  queued = new Set();
  if (hosts.length === 0) return;
  api
    .siteIcons(hosts)
    .then((found) => {
      for (const host of hosts) cache.set(host, found[host] ?? null);
      listeners.forEach((listener) => listener());
    })
    .catch(() => undefined);
}

function request(host: string) {
  if (cache.has(host) || queued.has(host)) return;
  queued.add(host);
  timer ??= setTimeout(flush, 0);
}

function reset() {
  cache.clear();
  listeners.forEach((listener) => listener());
}

// New icons arrived or the setting changed; locking forgets them.
void events.onSiteIconsChanged(reset);
void events.onLocked(reset);

/** The site's icon for a login address, once the app has it. */
export function useSiteIcon(url: string | undefined): SiteIcon | null {
  const host = url ? hostOf(url).toLowerCase() : "";
  const [, rerender] = useState(0);
  useEffect(() => {
    if (!host) return;
    const listener = () => {
      request(host);
      rerender((n) => n + 1);
    };
    listeners.add(listener);
    request(host);
    return () => {
      listeners.delete(listener);
    };
  }, [host]);
  return host ? (cache.get(host) ?? null) : null;
}

import { ArrowRight, ChevronLeft, Eye, EyeOff, Fingerprint, Search } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useTranslation } from "react-i18next";

import { ItemIcon, Logo } from "../components/common";
import { Kbd, cx } from "../components/ui";
import { applyLanguage } from "../i18n";
import { api, errorCode, errorMessage, events, type AppStatus, type ItemSummary } from "../lib/api";
import { sortItems } from "../lib/store";
import { useTheme } from "../lib/theme";

type Action = "open" | "app" | "username" | "password" | "totp";

const MAX_RESULTS = 50;
const SUGGESTIONS = 8;

function hostOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

/** Items matching the query, best matches and most used first. */
function search(items: ItemSummary[], query: string): ItemSummary[] {
  const active = items.filter((i) => i.trashedAt === null && !i.archived);
  const q = query.trim().toLowerCase();
  if (!q) {
    const used = active.filter((i) => i.uses > 0);
    return (used.length ? sortItems(used, { sort: "frequent", desc: true }) : sortItems(active, { sort: "modified", desc: true })).slice(
      0,
      SUGGESTIONS,
    );
  }
  const rank = (item: ItemSummary) => {
    const title = item.title.toLowerCase();
    if (title.startsWith(q)) return 0;
    if (title.includes(q)) return 1;
    if (item.urls.some((u) => hostOf(u).toLowerCase().includes(q))) return 2;
    return 3;
  };
  return active
    .filter(
      (i) =>
        i.title.toLowerCase().includes(q) ||
        i.subtitle.toLowerCase().includes(q) ||
        i.urls.some((u) => u.toLowerCase().includes(q)) ||
        i.tags.some((t) => t.toLowerCase().includes(q)),
    )
    .sort((a, b) => rank(a) - rank(b) || b.uses - a.uses || a.title.localeCompare(b.title, undefined, { sensitivity: "base" }))
    .slice(0, MAX_RESULTS);
}

export function QuickAccess() {
  const { t } = useTranslation();
  const [theme, setTheme] = useState<string>();
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const [actions, setActions] = useState<{ open: boolean; index: number }>({ open: false, index: 0 });
  const [notice, setNotice] = useState<{ text: string; error?: boolean } | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useTheme(theme);

  const refresh = useCallback(async () => {
    const next = await api.status();
    setStatus(next);
    setItems(next.state === "unlocked" ? await api.listItems() : []);
  }, []);

  const reset = useCallback(() => {
    setQuery("");
    setIndex(0);
    setActions({ open: false, index: 0 });
    setNotice(null);
    void api.getSettings().then((s) => {
      applyLanguage(s.language);
      setTheme(s.theme);
    });
    void refresh();
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [refresh]);

  useEffect(() => {
    reset();
    // Rust shows the window only once this page has rendered.
    void api.quickAccessReady();
    const subscriptions = [
      events.onQuickAccessOpened(reset),
      events.onLocked(() => void refresh()),
      events.onUnlocked(() => void refresh()),
      events.onItemsChanged(() => void refresh()),
    ];
    return () => subscriptions.forEach((p) => void p.then((unlisten) => unlisten()));
  }, [reset, refresh]);

  // Escape closes Quick Access from anywhere (the search box handles it first).
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape" && !e.defaultPrevented) void api.hideQuickAccess();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const results = useMemo(() => search(items, query), [items, query]);
  const selected = results[Math.min(index, results.length - 1)] as ItemSummary | undefined;
  const itemActions: Action[] = selected
    ? [...(selected.urls.length ? (["open"] as Action[]) : []), "app", "username", "password", "totp"]
    : [];

  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${index}"]`)?.scrollIntoView({ block: "nearest" });
  }, [index]);

  const hide = () => void api.hideQuickAccess();

  const run = async (action: Action, item = selected) => {
    if (!item) return;
    try {
      if (action === "open") {
        await api.openItemUrl(item.id, 0);
        hide();
      } else if (action === "app") {
        await api.showItemInApp(item.id);
      } else {
        const result = await api.copyItemValue(item.id, action);
        setNotice({ text: t("quick.copied", { seconds: result.clearAfterSeconds }) });
        setTimeout(hide, 700);
      }
    } catch (err) {
      setNotice({ text: errorMessage(err), error: true });
    }
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    const input = e.currentTarget;
    const key = e.key.toLowerCase();
    if (e.ctrlKey && key === "c" && input.selectionStart === input.selectionEnd) {
      e.preventDefault();
      void run(e.altKey ? "totp" : e.shiftKey ? "password" : "username");
      return;
    }
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        if (actions.open) setActions((a) => ({ ...a, index: Math.min(itemActions.length - 1, a.index + 1) }));
        else setIndex((i) => Math.min(results.length - 1, i + 1));
        break;
      case "ArrowUp":
        e.preventDefault();
        if (actions.open) setActions((a) => ({ ...a, index: Math.max(0, a.index - 1) }));
        else setIndex((i) => Math.max(0, i - 1));
        break;
      case "ArrowRight":
        if (selected && !actions.open && input.selectionStart === input.value.length) {
          e.preventDefault();
          setActions({ open: true, index: 0 });
        }
        break;
      case "ArrowLeft":
        if (actions.open) {
          e.preventDefault();
          setActions({ open: false, index: 0 });
        }
        break;
      case "Enter":
        e.preventDefault();
        void run(actions.open ? itemActions[actions.index] : itemActions[0]);
        break;
      case "Escape":
        e.preventDefault();
        if (actions.open) setActions({ open: false, index: 0 });
        else hide();
        break;
    }
  };

  const actionLabel = (action: Action) =>
    ({
      open: t("quick.openInBrowser"),
      app: t("quick.openInApp"),
      username: t("quick.copyUsername"),
      password: t("quick.copyPassword"),
      totp: t("quick.copyCode"),
    })[action];

  return (
    <div className="flex h-full flex-col overflow-hidden border border-line bg-panel text-fg">
      {status?.state === "locked" ? (
        <QuickUnlock status={status} onUnlocked={refresh} />
      ) : status?.state === "no_account" ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 text-sm text-muted">
          <Logo className="size-10" />
          {t("quick.noAccount")}
        </div>
      ) : (
        <>
          <div className="flex items-center gap-2.5 border-b border-line px-4 py-3">
            <Search className="size-4 shrink-0 text-subtle" />
            <input
              ref={inputRef}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setIndex(0);
                setActions({ open: false, index: 0 });
              }}
              onKeyDown={onKeyDown}
              placeholder={t("quick.placeholder")}
              spellCheck={false}
              autoComplete="off"
              className="h-8 flex-1 bg-transparent text-[15px] outline-none placeholder:text-subtle"
            />
            <Logo className="size-6 shrink-0" />
          </div>

          <div ref={listRef} className="flex-1 overflow-y-auto p-2">
            {actions.open && selected ? (
              <div>
                <button
                  onClick={() => setActions({ open: false, index: 0 })}
                  className="mb-1 flex w-full items-center gap-1.5 px-2 py-1 text-xs text-subtle hover:text-fg"
                >
                  <ChevronLeft className="size-3.5" /> {selected.title}
                </button>
                {itemActions.map((action, i) => (
                  <button
                    key={action}
                    onClick={() => void run(action)}
                    onMouseEnter={() => setActions({ open: true, index: i })}
                    className={cx(
                      "flex w-full items-center rounded-lg px-3 py-2 text-left text-sm",
                      i === actions.index ? "bg-accent text-accent-fg" : "hover:bg-panel-3",
                    )}
                  >
                    {actionLabel(action)}
                  </button>
                ))}
              </div>
            ) : results.length === 0 ? (
              <p className="px-3 py-8 text-center text-sm text-subtle">
                {query.trim() ? t("quick.noResults", { query: query.trim() }) : t("quick.empty")}
              </p>
            ) : (
              <>
                {!query.trim() && <div className="px-2 pb-1 pt-0.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("quick.suggestions")}</div>}
                {results.map((item, i) => (
                  <button
                    key={item.id}
                    data-index={i}
                    onClick={() => void run(item.urls.length ? "open" : "app", item)}
                    onMouseMove={() => i !== index && setIndex(i)}
                    className={cx(
                      "flex w-full items-center gap-3 rounded-lg px-2.5 py-1.5 text-left",
                      i === index ? "bg-accent text-accent-fg" : "hover:bg-panel-3",
                    )}
                  >
                    <ItemIcon title={item.title} category={item.category} url={item.urls[0]} size="sm" />
                    <span className="min-w-0 flex-1 truncate text-sm">
                      <span className="font-medium">{item.title}</span>
                      {item.subtitle && <span className={cx(i === index ? "text-accent-fg/80" : "text-muted")}> · {item.subtitle}</span>}
                      {item.urls[0] && <span className={cx(i === index ? "text-accent-fg/70" : "text-subtle")}> · {hostOf(item.urls[0])}</span>}
                    </span>
                    {i === index && (
                      <span className="flex shrink-0 items-center gap-1 text-xs font-medium">
                        {actionLabel(item.urls.length ? "open" : "app")}
                      </span>
                    )}
                  </button>
                ))}
              </>
            )}
          </div>

          <div className="flex items-center gap-4 border-t border-line px-4 py-2.5 text-xs text-muted">
            {notice ? (
              <span className={notice.error ? "text-danger" : "text-accent"}>{notice.text}</span>
            ) : (
              <>
                <span className="flex items-center gap-1.5">
                  <Kbd>Ctrl</Kbd>
                  <Kbd>C</Kbd>
                  {t("quick.copyUsername")}
                </span>
                <span className="flex items-center gap-1.5">
                  <Kbd>Ctrl</Kbd>
                  <Kbd>Shift</Kbd>
                  <Kbd>C</Kbd>
                  {t("quick.copyPassword")}
                </span>
                <span className="ml-auto flex items-center gap-1.5">
                  <Kbd>
                    <ArrowRight className="inline size-3" />
                  </Kbd>
                  {t("quick.moreActions")}
                </span>
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function QuickUnlock({ status, onUnlocked }: { status: AppStatus; onUnlocked: () => Promise<void> }) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const unlock = async (withSystem: boolean) => {
    setBusy(true);
    setError(null);
    try {
      if (withSystem) await api.unlockWithSystem();
      else await api.unlock(password);
      setPassword("");
      await onUnlocked();
    } catch (err) {
      if (errorCode(err) !== "cancelled") setError(errorMessage(err));
      await onUnlocked();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-1 flex-col items-center justify-center px-10">
      <Logo className="size-12" />
      <p className="mt-3 text-sm font-medium">{t("quick.locked")}</p>
      <form
        className="mt-5 w-full max-w-sm"
        onSubmit={(e) => {
          e.preventDefault();
          if (password && !busy) void unlock(false);
        }}
      >
        <div className="relative">
          <input
            type={visible ? "text" : "password"}
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onFocus={(e) => e.currentTarget.select()}
            placeholder={t("lock.placeholder")}
            disabled={busy}
            className="h-10 w-full rounded-lg border border-line bg-panel-2 pl-3 pr-10 text-sm outline-none focus:border-accent"
          />
          <button
            type="button"
            onClick={() => setVisible((v) => !v)}
            aria-label={visible ? t("common.hide") : t("common.show")}
            className="absolute right-1 top-1/2 flex size-8 -translate-y-1/2 items-center justify-center rounded-md text-muted hover:text-fg"
          >
            {visible ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
          </button>
        </div>
      </form>
      {status.systemUnlock && (
        <button
          onClick={() => void unlock(true)}
          disabled={busy}
          className="mt-2 flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm text-accent hover:bg-panel-3 disabled:opacity-50"
        >
          <Fingerprint className="size-4" /> {t("lock.systemUnlock")}
        </button>
      )}
      <p className="mt-2 min-h-5 text-center text-xs text-danger">{error}</p>
    </div>
  );
}

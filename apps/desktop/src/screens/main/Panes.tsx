import { useCallback, useEffect, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import { useTranslation } from "react-i18next";

import { cx } from "../../components/ui";

/** Widths of the sidebar and the item list, in pixels. The item pane takes
 * the rest. */
export interface PaneWidths {
  sidebar: number;
  list: number;
}

const DEFAULTS: PaneWidths = { sidebar: 248, list: 340 };
/** Narrowest each column may get; the widest is whatever the window leaves
 * once the others have their narrowest. */
const MIN = { sidebar: 200, list: 260, item: 420 };
const STORAGE_KEY = "keyless.panes";

function load(): PaneWidths {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "null");
    if (saved && typeof saved.sidebar === "number" && typeof saved.list === "number") return saved;
  } catch {
    // Unreadable or unavailable: the defaults.
  }
  return DEFAULTS;
}

/** Limits for each column in a window `total` pixels wide. */
export function paneLimits(total: number, widths: PaneWidths) {
  const sidebarMax = Math.max(MIN.sidebar, total - MIN.list - MIN.item);
  const sidebar = Math.min(Math.max(widths.sidebar, MIN.sidebar), sidebarMax);
  const listMax = Math.max(MIN.list, total - sidebar - MIN.item);
  const list = Math.min(Math.max(widths.list, MIN.list), listMax);
  return { sidebar, list, sidebarMin: MIN.sidebar, sidebarMax, listMin: MIN.list, listMax };
}

/** The column widths as the user left them (on this device), fitted to the
 * window. */
export function usePaneWidths() {
  const [wanted, setWanted] = useState<PaneWidths>(load);
  const [total, setTotal] = useState(() => window.innerWidth);

  useEffect(() => {
    const onResize = () => setTotal(window.innerWidth);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(wanted));
    } catch {
      // Remembered until the app closes only.
    }
  }, [wanted]);

  const limits = paneLimits(total, wanted);
  const set = useCallback((patch: Partial<PaneWidths>) => setWanted((w) => ({ ...w, ...patch })), []);
  const reset = useCallback((pane: keyof PaneWidths) => setWanted((w) => ({ ...w, [pane]: DEFAULTS[pane] })), []);
  return { ...limits, set, reset };
}

/** The handle on a column's right edge: drag (or use the arrow keys) to
 * resize it, double-click to go back to the default width. */
export function ResizeHandle({
  value,
  min,
  max,
  label,
  onResize,
  onReset,
}: {
  value: number;
  min: number;
  max: number;
  label: string;
  onResize: (width: number) => void;
  onReset: () => void;
}) {
  const { t } = useTranslation();
  const start = useRef<{ x: number; width: number } | null>(null);
  const [dragging, setDragging] = useState(false);

  const down = (e: PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    e.preventDefault();
    e.currentTarget.setPointerCapture(e.pointerId);
    start.current = { x: e.clientX, width: value };
    setDragging(true);
  };
  const move = (e: PointerEvent<HTMLDivElement>) => {
    if (!start.current) return;
    onResize(Math.round(start.current.width + e.clientX - start.current.x));
  };
  const up = (e: PointerEvent<HTMLDivElement>) => {
    start.current = null;
    setDragging(false);
    e.currentTarget.releasePointerCapture(e.pointerId);
  };
  const key = (e: KeyboardEvent<HTMLDivElement>) => {
    const step = e.shiftKey ? 64 : 16;
    if (e.key === "ArrowLeft") onResize(value - step);
    else if (e.key === "ArrowRight") onResize(value + step);
    else if (e.key === "Home") onResize(min);
    else if (e.key === "End") onResize(max);
    else return;
    e.preventDefault();
  };

  // While dragging, the whole window shows the resize cursor and no text
  // gets selected.
  useEffect(() => {
    if (!dragging) return;
    document.body.classList.add("cursor-col-resize", "select-none");
    return () => document.body.classList.remove("cursor-col-resize", "select-none");
  }, [dragging]);

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      aria-valuenow={value}
      aria-valuemin={min}
      aria-valuemax={max}
      title={t("panes.resizeHint")}
      tabIndex={0}
      onPointerDown={down}
      onPointerMove={move}
      onPointerUp={up}
      onPointerCancel={up}
      onDoubleClick={onReset}
      onKeyDown={key}
      className="group absolute inset-y-0 -right-1 z-20 flex w-2 cursor-col-resize justify-center outline-none"
    >
      <span
        className={cx(
          "h-full w-0.5 transition-colors",
          dragging ? "bg-accent" : "bg-transparent group-hover:bg-accent/70 group-focus-visible:bg-accent",
        )}
      />
    </div>
  );
}

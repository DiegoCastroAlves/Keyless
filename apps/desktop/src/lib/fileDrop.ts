import { getCurrentWebview } from "@tauri-apps/api/webview";
import { useEffect, useRef, useState } from "react";

import { api, type FileInfo } from "./api";

/** A dialog is open over the screen: what is dropped then is not for it. */
function dialogOpen(): boolean {
  return document.querySelector('[role="dialog"], [role="alertdialog"]') !== null;
}

/** Files dropped on the window while `enabled` and no dialog is open: calls
 * `onDrop` with them (only regular files) and tells whether files are being
 * dragged over. */
export function useFileDrop(enabled: boolean, onDrop: (files: FileInfo[]) => void): boolean {
  const [dragging, setDragging] = useState(false);
  const handler = useRef(onDrop);
  handler.current = onDrop;

  useEffect(() => {
    if (!enabled) {
      setDragging(false);
      return;
    }
    let stop: (() => void) | undefined;
    let cancelled = false;
    void getCurrentWebview()
      .onDragDropEvent(async (event) => {
        const kind = event.payload.type;
        if (kind === "enter" || kind === "over") setDragging(!dialogOpen());
        else if (kind === "leave") setDragging(false);
        else if (kind === "drop") {
          setDragging(false);
          if (dialogOpen()) return;
          // The app records the drop too (it only accepts files offered
          // this way): give it a moment.
          await new Promise((resolve) => setTimeout(resolve, 120));
          const files = await api.attachmentInspect(event.payload.paths).catch(() => []);
          if (files.length) handler.current(files);
        }
      })
      .then((unlisten) => {
        if (cancelled) unlisten();
        else stop = unlisten;
      });
    return () => {
      cancelled = true;
      stop?.();
    };
  }, [enabled]);

  return dragging;
}

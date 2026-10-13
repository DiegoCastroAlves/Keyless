import { create } from "zustand";

import i18n from "../i18n";

export interface Toast {
  id: number;
  message: string;
  tone: "neutral" | "success" | "error";
  /** A button on the toast ("Undo"). */
  action?: { label: string; run: () => void };
}

interface ToastStore {
  toasts: Toast[];
  push: (message: string, tone?: Toast["tone"], action?: Toast["action"]) => void;
  dismiss: (id: number) => void;
}

let nextId = 1;

export const useToasts = create<ToastStore>((set, get) => ({
  toasts: [],
  push: (message, tone = "neutral", action) => {
    const id = nextId++;
    set({ toasts: [...get().toasts.slice(-2), { id, message, tone, action }] });
    setTimeout(() => get().dismiss(id), tone === "error" || action ? 6000 : 2600);
  },
  dismiss: (id) => set({ toasts: get().toasts.filter((t) => t.id !== id) }),
}));

export const toast = {
  show: (message: string) => useToasts.getState().push(message, "neutral"),
  success: (message: string) => useToasts.getState().push(message, "success"),
  error: (message: string) => useToasts.getState().push(message, "error"),
  /** A success with a button that undoes it. */
  undoable: (message: string, undo: () => void) => useToasts.getState().push(message, "success", { label: i18n.t("common.undo"), run: undo }),
  copied: (what: string, clearAfterSeconds: number) =>
    useToasts.getState().push(i18n.t("item.copied", { what, seconds: clearAfterSeconds }), "success"),
};

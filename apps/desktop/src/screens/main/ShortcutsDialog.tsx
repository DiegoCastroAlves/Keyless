import { useTranslation } from "react-i18next";

import { Dialog, Kbd } from "../../components/ui";
import { useApp } from "../../lib/store";

const isWindows = navigator.userAgent.includes("Windows");

/** Every keyboard shortcut of the main window (Ctrl+/). */
export function ShortcutsDialog() {
  const { t } = useTranslation();
  const open = useApp((s) => s.shortcutsOpen);
  const settings = useApp((s) => s.settings);
  const groups: { title: string; rows: [string, string][] }[] = [
    {
      title: t("shortcuts.groupApp"),
      rows: [
        ["Ctrl+N", t("shortcuts.newItem")],
        ["Ctrl+F", t("shortcuts.search")],
        ["Ctrl+G", t("shortcuts.generator")],
        ["Ctrl+L", t("shortcuts.lockApp")],
        ["Ctrl+,", t("shortcuts.settings")],
        ["Ctrl+/", t("shortcuts.title")],
        ["Ctrl+= / Ctrl+- / Ctrl+0", t("shortcuts.zoom")],
        ["Alt+← / Alt+→", t("shortcuts.backForward")],
      ],
    },
    {
      title: t("shortcuts.groupList"),
      rows: [
        ["↑ / ↓", t("shortcuts.moveInList")],
        ["Shift+↑ / Shift+↓", t("shortcuts.extendSelection")],
        ["Ctrl+A", t("shortcuts.selectAll")],
        ["Delete", t("shortcuts.trash")],
      ],
    },
    {
      title: t("shortcuts.groupItem"),
      rows: [
        ["Ctrl+C", t("shortcuts.copyPassword")],
        ["Ctrl+Shift+C", t("shortcuts.copyUsername")],
        ["Ctrl+Alt+C", t("shortcuts.copyCode")],
        ["Ctrl+E", t("shortcuts.edit")],
        ["Ctrl+D", t("shortcuts.duplicate")],
        ["Ctrl+S", t("shortcuts.save")],
        ["Esc", t("shortcuts.cancel")],
        ["Alt+↑ / Alt+↓", t("shortcuts.reorder")],
      ],
    },
    {
      title: t("shortcuts.groupGlobal"),
      rows: isWindows
        ? [
            [settings?.quick_access_shortcut || "—", t("shortcuts.quickAccess")],
            [settings?.show_shortcut || "—", t("shortcuts.showApp")],
            [settings?.lock_shortcut || "—", t("shortcuts.lockApp")],
          ]
        : [
            ["Ctrl+Shift+Space", t("shortcuts.quickAccess")],
            ["keyless-desktop --show", t("shortcuts.showApp")],
            ["keyless-desktop --lock", t("shortcuts.lockApp")],
          ],
    },
  ];
  return (
    <Dialog open={open} onOpenChange={(shortcutsOpen) => useApp.setState({ shortcutsOpen })} title={t("shortcuts.title")} width="max-w-xl">
      <div className="max-h-[60vh] space-y-5 overflow-y-auto pr-1">
        {groups.map((group) => (
          <div key={group.title}>
            <div className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-subtle">{group.title}</div>
            <div className="divide-y divide-line overflow-hidden rounded-xl border border-line">
              {group.rows.map(([keys, action]) => (
                <div key={action} className="flex items-center justify-between gap-4 px-3.5 py-2 text-sm">
                  <span>{action}</span>
                  <Kbd>{keys}</Kbd>
                </div>
              ))}
            </div>
          </div>
        ))}
        {!isWindows && <p className="text-xs text-muted">{t("settings.globalShortcutsHintLinux")}</p>}
      </div>
    </Dialog>
  );
}

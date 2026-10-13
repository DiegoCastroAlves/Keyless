import "./i18n";
import "./styles.css";

import { getCurrentWindow } from "@tauri-apps/api/window";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { itemWindowId } from "./lib/windows";
import { ItemWindow } from "./screens/ItemWindow";
import { QuickAccess } from "./screens/QuickAccess";
import { SshApprove } from "./screens/SshApprove";
import { UnlockPrompt } from "./screens/UnlockPrompt";

// The same bundle serves every window: main, Quick Access, the unlock prompt
// shown for the browser extension, the SSH agent's approval and items opened
// in windows of their own.
const label = getCurrentWindow().label;
const screen =
  label === "quick-access" ? (
    <QuickAccess />
  ) : label === "unlock-prompt" ? (
    <UnlockPrompt />
  ) : label === "ssh-approve" ? (
    <SshApprove />
  ) : itemWindowId ? (
    <ItemWindow itemId={itemWindowId} />
  ) : (
    <App />
  );

createRoot(document.getElementById("root")!).render(<StrictMode>{screen}</StrictMode>);

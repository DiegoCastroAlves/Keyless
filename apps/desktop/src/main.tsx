import "./i18n";
import "./styles.css";

import { getCurrentWindow } from "@tauri-apps/api/window";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { QuickAccess } from "./screens/QuickAccess";

// The same bundle serves the main window and the Quick Access window.
const quickAccess = getCurrentWindow().label === "quick-access";

createRoot(document.getElementById("root")!).render(<StrictMode>{quickAccess ? <QuickAccess /> : <App />}</StrictMode>);

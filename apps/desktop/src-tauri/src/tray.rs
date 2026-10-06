//! Tray icon. With "keep running in the tray" on, closing the window hides it
//! and Keyless keeps running (auto-lock, browser extension, Quick Access).
//! A click on the icon opens Keyless; its menu has Open, Quick Access, Lock
//! and Quit.
//!
//! On Linux the icon is a StatusNotifierItem served over D-Bus (ksni): unlike
//! the AppIndicator library behind Tauri's tray, it reports clicks, and it
//! needs no native library. Elsewhere Tauri's tray is used.

use serde::Deserialize;
use tauri::{AppHandle, Manager};

use crate::state::AppState;

/// Menu texts, translated by the UI.
#[derive(Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrayLabels {
    pub open: String,
    pub quick_access: String,
    pub lock: String,
    pub quit: String,
}

/// Creates the tray icon, or updates its menu when the language changes.
pub fn configure(app: &AppHandle, labels: &TrayLabels) -> tauri::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::configure(app, labels);
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        native::configure(app, labels)
    }
}

/// Whether the window can hide into the tray instead of closing.
pub fn available(app: &AppHandle) -> bool {
    #[cfg(target_os = "linux")]
    {
        let _ = app;
        linux::available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        app.tray_by_id(native::TRAY_ID).is_some()
    }
}

pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn lock(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move { crate::auth::lock(&app).await });
}

/// Quits for real (from the tray), clearing a copied secret first.
pub fn quit(app: &AppHandle) {
    app.state::<AppState>().clipboard.clear_now();
    app.exit(0);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::Mutex;

    use ksni::{
        Icon, TrayMethods,
        menu::{MenuItem, StandardItem},
    };
    use tauri::AppHandle;

    use super::TrayLabels;

    struct KeylessTray {
        app: AppHandle,
        labels: TrayLabels,
        icon: Vec<Icon>,
    }

    impl ksni::Tray for KeylessTray {
        fn id(&self) -> String {
            "keyless".into()
        }

        fn title(&self) -> String {
            "Keyless".into()
        }

        fn icon_name(&self) -> String {
            "keyless-desktop".into()
        }

        fn icon_pixmap(&self) -> Vec<Icon> {
            self.icon.clone()
        }

        /// A click on the icon.
        fn activate(&mut self, _x: i32, _y: i32) {
            super::show_main(&self.app);
        }

        fn menu(&self) -> Vec<MenuItem<Self>> {
            let item = |label: &str, run: fn(&AppHandle)| -> MenuItem<Self> {
                StandardItem { label: label.to_string(), activate: Box::new(move |tray: &mut Self| run(&tray.app)), ..Default::default() }.into()
            };
            vec![
                item(&self.labels.open, super::show_main),
                item(&self.labels.quick_access, |app| {
                    let _ = crate::quick_access::show(app);
                }),
                item(&self.labels.lock, super::lock),
                MenuItem::Separator,
                item(&self.labels.quit, super::quit),
            ]
        }
    }

    enum State {
        Idle,
        /// Registering; the latest labels are applied once it runs.
        Starting(TrayLabels),
        Running(ksni::Handle<KeylessTray>),
        /// No tray host (e.g. GNOME without the AppIndicator extension).
        Unavailable,
    }

    static STATE: Mutex<State> = Mutex::new(State::Idle);

    /// The app icon as ARGB32 in network byte order.
    fn icon(app: &AppHandle) -> Vec<Icon> {
        let Some(image) = app.default_window_icon() else { return Vec::new() };
        let data = image.rgba().as_chunks::<4>().0.iter().flat_map(|&[r, g, b, a]| [a, r, g, b]).collect();
        vec![Icon { width: image.width() as i32, height: image.height() as i32, data }]
    }

    pub fn configure(app: &AppHandle, labels: &TrayLabels) {
        let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        match &mut *state {
            State::Running(handle) => {
                let (handle, labels) = (handle.clone(), labels.clone());
                tauri::async_runtime::spawn(async move { handle.update(|tray| tray.labels = labels).await });
            }
            State::Starting(latest) => *latest = labels.clone(),
            State::Idle | State::Unavailable => {
                *state = State::Starting(labels.clone());
                let tray = KeylessTray { app: app.clone(), labels: labels.clone(), icon: icon(app) };
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let result = tray.spawn().await;
                    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
                    match result {
                        Ok(handle) => {
                            if let State::Starting(latest) = &*state {
                                let (latest, handle) = (latest.clone(), handle.clone());
                                tauri::async_runtime::spawn(async move { handle.update(|tray| tray.labels = latest).await });
                            }
                            *state = State::Running(handle);
                        }
                        Err(err) => {
                            log::warn!("tray icon unavailable: {err}");
                            *state = State::Unavailable;
                            drop(state);
                            // Without a tray there is no way back to a hidden window.
                            super::show_main(&app);
                        }
                    }
                });
            }
        }
    }

    pub fn available() -> bool {
        matches!(&*STATE.lock().unwrap_or_else(|e| e.into_inner()), State::Running(handle) if !handle.is_closed())
    }
}

#[cfg(not(target_os = "linux"))]
mod native {
    use tauri::{
        AppHandle,
        menu::{Menu, MenuItem, PredefinedMenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    };

    use super::TrayLabels;

    pub const TRAY_ID: &str = "keyless";

    pub fn configure(app: &AppHandle, labels: &TrayLabels) -> tauri::Result<()> {
        let open = MenuItem::with_id(app, "open", &labels.open, true, None::<&str>)?;
        let quick_access = MenuItem::with_id(app, "quick-access", &labels.quick_access, true, None::<&str>)?;
        let lock = MenuItem::with_id(app, "lock", &labels.lock, true, None::<&str>)?;
        let quit = MenuItem::with_id(app, "quit", &labels.quit, true, None::<&str>)?;
        let separator = PredefinedMenuItem::separator(app)?;
        let menu = Menu::with_items(app, &[&open, &quick_access, &lock, &separator, &quit])?;

        if let Some(tray) = app.tray_by_id(TRAY_ID) {
            return tray.set_menu(Some(menu));
        }
        let mut builder = TrayIconBuilder::with_id(TRAY_ID)
            .tooltip("Keyless")
            .menu(&menu)
            .show_menu_on_left_click(false)
            .on_menu_event(|app, event| match event.id().as_ref() {
                "open" => super::show_main(app),
                "quick-access" => {
                    let _ = crate::quick_access::show(app);
                }
                "lock" => super::lock(app),
                "quit" => super::quit(app),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                    super::show_main(tray.app_handle());
                }
            });
        if let Some(icon) = app.default_window_icon() {
            builder = builder.icon(icon.clone());
        }
        builder.build(app)?;
        Ok(())
    }
}

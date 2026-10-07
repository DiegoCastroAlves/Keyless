//! Tray icon. With "keep running in the tray" on, closing the window hides it
//! and Keyless keeps running (auto-lock, browser extension, Quick Access).
//! A click on the icon opens Keyless; its menu has Open, Quick Access, Lock
//! and Quit. While Keyless is locked the icon shows a padlock.
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
    static FOLLOW_LOCK: std::sync::Once = std::sync::Once::new();
    FOLLOW_LOCK.call_once(|| {
        let app = app.clone();
        let mut changes = app.state::<AppState>().lock_state.subscribe();
        tauri::async_runtime::spawn(async move {
            while changes.changed().await.is_ok() {
                let locked = *changes.borrow_and_update();
                #[cfg(target_os = "linux")]
                linux::set_locked(locked);
                #[cfg(not(target_os = "linux"))]
                native::set_locked(&app, locked);
            }
        });
    });
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

fn is_locked(app: &AppHandle) -> bool {
    *app.state::<AppState>().lock_state.borrow()
}

/// The app icon at the sizes the tray may use, as RGBA, with and without
/// the padlock.
fn icons() -> Vec<(u32, Vec<u8>, Vec<u8>)> {
    [&include_bytes!("../icons/32x32.png")[..], &include_bytes!("../icons/64x64.png")[..]]
        .into_iter()
        .filter_map(|png| tauri::image::Image::from_bytes(png).ok())
        .filter(|image| image.width() == image.height())
        .map(|image| {
            let size = image.width();
            let plain = image.rgba().to_vec();
            let locked = with_padlock(&plain, size);
            (size, plain, locked)
        })
        .collect()
}

/// Draws a padlock in the bottom-right corner (RGBA, square image).
fn with_padlock(rgba: &[u8], size: u32) -> Vec<u8> {
    const WHITE: [u8; 3] = [255, 255, 255];
    const DARK: [u8; 3] = [17, 24, 39];
    let s = size as f32;
    let b = s * 0.62;
    let (ox, oy) = (s - b, s - b);
    let cx = ox + b * 0.5;
    // The shackle is an arc meeting the top of the body.
    let joint = oy + b * 0.46;
    let (radius, stroke) = (b * 0.22, b * 0.12);
    let body = (ox + b * 0.16, joint, ox + b * 0.84, oy + b * 0.98);
    let outline = (b * 0.09).max(1.0);
    let keyhole = (cx, oy + b * 0.71, b * 0.075);

    let mut out = rgba.to_vec();
    for y in 0..size {
        for x in 0..size {
            let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
            let d_body = rounded_rect(px, py, body, b * 0.12);
            let d_shackle = if py <= joint {
                ((px - cx).hypot(py - joint) - radius).abs() - stroke / 2.0
            } else {
                (((px - cx).abs() - radius).abs() - stroke / 2.0).max(py - body.3)
            };
            let d = d_body.min(d_shackle);
            let pixel = &mut out[((y * size + x) * 4) as usize..][..4];
            blend(pixel, WHITE, (outline - d + 0.5).clamp(0.0, 1.0));
            let fill = (0.5 - d).clamp(0.0, 1.0);
            blend(pixel, DARK, fill);
            if size >= 32 {
                let hole = (keyhole.2 - (px - keyhole.0).hypot(py - keyhole.1) + 0.5).clamp(0.0, 1.0);
                blend(pixel, WHITE, hole * fill);
            }
        }
    }
    out
}

/// Signed distance to a rounded rectangle (negative inside).
fn rounded_rect(px: f32, py: f32, (x0, y0, x1, y1): (f32, f32, f32, f32), r: f32) -> f32 {
    let qx = (px - (x0 + x1) / 2.0).abs() - ((x1 - x0) / 2.0 - r);
    let qy = (py - (y0 + y1) / 2.0).abs() - ((y1 - y0) / 2.0 - r);
    qx.max(0.0).hypot(qy.max(0.0)) + qx.max(qy).min(0.0) - r
}

/// Paints `color` with coverage `a` over a straight-alpha RGBA pixel.
fn blend(pixel: &mut [u8], color: [u8; 3], a: f32) {
    if a <= 0.0 {
        return;
    }
    let below = pixel[3] as f32 / 255.0;
    let alpha = a + below * (1.0 - a);
    for (channel, value) in pixel.iter_mut().zip(color) {
        *channel = ((value as f32 * a + *channel as f32 * below * (1.0 - a)) / alpha).round() as u8;
    }
    pixel[3] = (alpha * 255.0).round() as u8;
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
        locked_icon: Vec<Icon>,
        locked: bool,
    }

    impl ksni::Tray for KeylessTray {
        fn id(&self) -> String {
            "keyless".into()
        }

        fn title(&self) -> String {
            "Keyless".into()
        }

        // No icon name: the theme's icon would win over the pixmaps, and it
        // has no locked variant.
        fn icon_pixmap(&self) -> Vec<Icon> {
            if self.locked { self.locked_icon.clone() } else { self.icon.clone() }
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

    /// RGBA to ARGB32 in network byte order.
    fn argb(size: u32, rgba: &[u8]) -> Icon {
        let data = rgba.as_chunks::<4>().0.iter().flat_map(|&[r, g, b, a]| [a, r, g, b]).collect();
        Icon { width: size as i32, height: size as i32, data }
    }

    pub fn set_locked(locked: bool) {
        if let State::Running(handle) = &*STATE.lock().unwrap_or_else(|e| e.into_inner()) {
            let handle = handle.clone();
            tauri::async_runtime::spawn(async move { handle.update(|tray| tray.locked = locked).await });
        }
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
                let icons = super::icons();
                let tray = KeylessTray {
                    app: app.clone(),
                    labels: labels.clone(),
                    icon: icons.iter().map(|(size, plain, _)| argb(*size, plain)).collect(),
                    locked_icon: icons.iter().map(|(size, _, locked)| argb(*size, locked)).collect(),
                    locked: super::is_locked(app),
                };
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let result = tray.spawn().await;
                    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
                    match result {
                        Ok(handle) => {
                            if let State::Starting(latest) = &*state {
                                // Labels and lock state may have changed while registering.
                                let (latest, handle, locked) = (latest.clone(), handle.clone(), super::is_locked(&app));
                                tauri::async_runtime::spawn(async move {
                                    handle
                                        .update(|tray| {
                                            tray.labels = latest;
                                            tray.locked = locked;
                                        })
                                        .await
                                });
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
        image::Image,
        menu::{Menu, MenuItem, PredefinedMenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    };

    use super::TrayLabels;

    pub const TRAY_ID: &str = "keyless";

    fn icon(locked: bool) -> Option<Image<'static>> {
        let (size, plain, padlock) = super::icons().pop()?;
        Some(Image::new_owned(if locked { padlock } else { plain }, size, size))
    }

    pub fn set_locked(app: &AppHandle, locked: bool) {
        if let Some(tray) = app.tray_by_id(TRAY_ID) {
            let _ = tray.set_icon(icon(locked));
        }
    }

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
        if let Some(icon) = icon(super::is_locked(app)) {
            builder = builder.icon(icon);
        }
        builder.build(app)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padlock_covers_only_the_corner() {
        let size = 64;
        let plain: Vec<u8> = [20u8, 184, 166, 255].repeat((size * size) as usize);
        let locked = with_padlock(&plain, size);
        let at = |rgba: &[u8], x: u32, y: u32| rgba[((y * size + x) * 4) as usize..][..4].to_vec();
        // Top-left untouched; the padlock's body is dark, its keyhole light.
        assert_eq!(at(&locked, 5, 5), at(&plain, 5, 5));
        assert_eq!(at(&locked, 44, 58)[..3], [17, 24, 39]);
        assert!(at(&locked, 44, 51)[0] > 200);
        assert_eq!(locked.len(), plain.len());
    }

    #[test]
    fn tray_icons_decode() {
        let icons = icons();
        assert_eq!(icons.iter().map(|(size, ..)| *size).collect::<Vec<_>>(), [32, 64]);
        assert!(icons.iter().all(|(size, plain, locked)| plain.len() == (size * size * 4) as usize && plain != locked));
    }
}

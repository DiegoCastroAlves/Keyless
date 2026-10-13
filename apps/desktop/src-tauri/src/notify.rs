//! The system's own notifications: Sentinel's new alerts (how many there
//! are, never which items: notifications can show on a locked screen), and a
//! new device asking to sign in. Clicking one opens what it is about.

use std::sync::Mutex;

use serde::Deserialize;
use tauri::{AppHandle, Emitter};

/// Tells the main window to show Sentinel.
pub const EVENT_OPEN_SENTINEL: &str = "keyless://open-sentinel";

/// Texts translated by the UI ("{count}" stands for the number).
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationLabels {
    pub sentinel_title: String,
    pub new_alerts_one: String,
    pub new_alerts_other: String,
    #[serde(default)]
    pub device_setup_title: String,
    #[serde(default)]
    pub device_setup_body: String,
}

static LABELS: Mutex<Option<NotificationLabels>> = Mutex::new(None);

pub fn configure(labels: NotificationLabels) {
    *LABELS.lock().unwrap_or_else(|e| e.into_inner()) = Some(labels);
}

/// "Sentinel found `count` new alerts". Nothing before the UI gave its texts.
pub fn sentinel(app: &AppHandle, count: usize) {
    let Some(labels) = LABELS.lock().unwrap_or_else(|e| e.into_inner()).clone() else { return };
    let body = if count == 1 { &labels.new_alerts_one } else { &labels.new_alerts_other }.replace("{count}", &count.to_string());
    show(app, labels.sentinel_title, body, open_sentinel);
}

/// "A new device asks to sign in to your account".
pub fn device_setup(app: &AppHandle) {
    let Some(labels) = LABELS.lock().unwrap_or_else(|e| e.into_inner()).clone() else { return };
    if labels.device_setup_title.is_empty() {
        return;
    }
    show(app, labels.device_setup_title, labels.device_setup_body, open_device_setup);
}

fn open_sentinel(app: &AppHandle) {
    crate::tray::show_main(app);
    let _ = app.emit(EVENT_OPEN_SENTINEL, ());
}

fn open_device_setup(app: &AppHandle) {
    crate::tray::show_main(app);
    let _ = app.emit(crate::device_setup::EVENT_SETUP_REQUESTED, ());
}

/// What clicking the notification does.
type OnClick = fn(&AppHandle);

#[cfg(target_os = "linux")]
fn show(app: &AppHandle, title: String, body: String, on_click: OnClick) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(err) = linux::show(&app, &title, &body, on_click).await {
            log::info!("notification: {err}");
        }
    });
}

#[cfg(windows)]
fn show(app: &AppHandle, title: String, body: String, on_click: OnClick) {
    if let Err(err) = windows::show(app, &title, &body, on_click) {
        log::info!("notification: {err}");
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn show(_: &AppHandle, _: String, _: String, _: OnClick) {}

#[cfg(target_os = "linux")]
mod linux {
    use std::{collections::HashMap, time::Duration};

    use futures_lite::StreamExt;
    use tauri::AppHandle;
    use zbus::{MatchRule, MessageStream, message::Type, zvariant::Value};

    const DEST: &str = "org.freedesktop.Notifications";
    const PATH: &str = "/org/freedesktop/Notifications";

    /// Through the desktop's notification service; waits a while for a click.
    pub async fn show(app: &AppHandle, title: &str, body: &str, on_click: super::OnClick) -> zbus::Result<()> {
        let conn = zbus::Connection::session().await?;
        let hints: HashMap<&str, Value> = HashMap::from([("desktop-entry", Value::from("keyless-desktop"))]);
        let reply = conn
            .call_method(Some(DEST), PATH, Some(DEST), "Notify", &("Keyless", 0u32, "keyless-desktop", title, body, vec!["default", ""], hints, -1i32))
            .await?;
        let id: u32 = reply.body().deserialize()?;

        let invoked = MatchRule::builder().msg_type(Type::Signal).interface(DEST)?.member("ActionInvoked")?.build();
        let closed = MatchRule::builder().msg_type(Type::Signal).interface(DEST)?.member("NotificationClosed")?.build();
        let mut invoked = MessageStream::for_match_rule(invoked, &conn, None).await?;
        let mut closed = MessageStream::for_match_rule(closed, &conn, None).await?;
        let wait = async {
            loop {
                tokio::select! {
                    Some(Ok(msg)) = invoked.next() => {
                        if msg.body().deserialize::<(u32, String)>().is_ok_and(|(n, _)| n == id) {
                            on_click(app);
                            return;
                        }
                    }
                    Some(Ok(msg)) = closed.next() => {
                        if msg.body().deserialize::<(u32, u32)>().is_ok_and(|(n, _)| n == id) {
                            return;
                        }
                    }
                    else => return,
                }
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(3600), wait).await;
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use tauri::AppHandle;
    use windows::{
        Data::Xml::Dom::XmlDocument,
        Foundation::TypedEventHandler,
        UI::Notifications::{ToastNotification, ToastNotificationManager},
        core::{HSTRING, IInspectable},
    };

    /// The id the installer gives Keyless's Start menu shortcut (the bundle
    /// identifier), which Windows shows the notification under.
    const APP_ID: &str = "io.github.diegocastroalves.keyless";

    fn escape(text: &str) -> String {
        text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }

    pub fn show(app: &AppHandle, title: &str, body: &str, on_click: super::OnClick) -> windows::core::Result<()> {
        let xml = XmlDocument::new()?;
        xml.LoadXml(&HSTRING::from(format!(
            "<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual></toast>",
            escape(title),
            escape(body)
        )))?;
        let toast = ToastNotification::CreateToastNotification(&xml)?;
        let app = app.clone();
        toast.Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(move |_, _| {
            on_click(&app);
            Ok(())
        }))?;
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(APP_ID))?.Show(&toast)
    }
}

//! Automatic locking: after inactivity, when the computer sleeps and when
//! the screen is locked.

use std::time::{Duration, SystemTime};

use tauri::{AppHandle, Manager};

use crate::{auth, state::AppState};

pub fn start(app: AppHandle) {
    start_idle_watch(app.clone());
    #[cfg(target_os = "linux")]
    {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(err) = linux::watch(app).await {
                log::warn!("could not watch for sleep/screen lock: {err}");
            }
        });
    }
    #[cfg(windows)]
    windows::start(app);
}

async fn lock_for_system_event(app: &AppHandle) {
    let state = app.state::<AppState>();
    if state.settings().lock_on_sleep {
        auth::lock(app).await;
    }
}

fn start_idle_watch(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut last_tick = SystemTime::now();
        loop {
            interval.tick().await;
            let state = app.state::<AppState>();
            let now = SystemTime::now();
            // A large jump in wall-clock time between ticks means the
            // machine was suspended.
            let slept = now.duration_since(last_tick).unwrap_or_default() > Duration::from_secs(60);
            last_tick = now;
            if state.session.lock().await.is_none() {
                continue;
            }
            if slept {
                lock_for_system_event(&app).await;
                continue;
            }
            let timeout = Duration::from_secs(state.settings().auto_lock_minutes as u64 * 60);
            if state.idle_for() >= timeout {
                auth::lock(&app).await;
            }
        }
    });
}

#[cfg(target_os = "linux")]
mod linux {
    use futures_lite::StreamExt;
    use tauri::AppHandle;
    use zbus::{MatchRule, MessageStream, message::Type};

    /// Listens for logind's PrepareForSleep / session Lock and for the
    /// desktop screensaver (KDE, GNOME and others implement
    /// org.freedesktop.ScreenSaver).
    pub async fn watch(app: AppHandle) -> zbus::Result<()> {
        let system = zbus::Connection::system().await?;
        let session = zbus::Connection::session().await?;

        let sleep = MatchRule::builder()
            .msg_type(Type::Signal)
            .interface("org.freedesktop.login1.Manager")?
            .member("PrepareForSleep")?
            .build();
        let session_lock = MatchRule::builder()
            .msg_type(Type::Signal)
            .interface("org.freedesktop.login1.Session")?
            .member("Lock")?
            .build();
        let screensaver = MatchRule::builder()
            .msg_type(Type::Signal)
            .interface("org.freedesktop.ScreenSaver")?
            .member("ActiveChanged")?
            .build();

        let mut sleep = MessageStream::for_match_rule(sleep, &system, None).await?;
        let mut session_lock = MessageStream::for_match_rule(session_lock, &system, None).await?;
        let mut screensaver = MessageStream::for_match_rule(screensaver, &session, None).await?;

        loop {
            let should_lock = tokio::select! {
                Some(Ok(msg)) = sleep.next() => msg.body().deserialize::<bool>().unwrap_or(false),
                Some(Ok(_)) = session_lock.next() => true,
                Some(Ok(msg)) = screensaver.next() => msg.body().deserialize::<bool>().unwrap_or(false),
                else => break,
            };
            if should_lock {
                super::lock_for_system_event(&app).await;
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use std::time::Duration;

    use tauri::AppHandle;
    use windows_sys::Win32::System::StationsAndDesktops::{CloseDesktop, OpenInputDesktop};

    const DESKTOP_SWITCHDESKTOP: u32 = 0x0100;

    /// The input desktop cannot be opened while the workstation is locked
    /// (Win+L) or the secure desktop is showing.
    fn workstation_locked() -> bool {
        // SAFETY: plain Win32 calls; the handle is closed when valid.
        unsafe {
            let desktop = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP);
            if desktop.is_null() {
                return true;
            }
            CloseDesktop(desktop);
            false
        }
    }

    pub fn start(app: AppHandle) {
        tauri::async_runtime::spawn(async move {
            let mut was_locked = false;
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                let locked = workstation_locked();
                if locked && !was_locked {
                    super::lock_for_system_event(&app).await;
                }
                was_locked = locked;
            }
        });
    }
}

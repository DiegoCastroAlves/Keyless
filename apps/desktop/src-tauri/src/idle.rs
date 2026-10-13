//! How long the user has left the whole computer alone, where the system can
//! say: the last input on Windows; on Linux the Wayland compositor (the
//! ext-idle-notify protocol, which KDE, GNOME and others offer) or, in an X11
//! session, the desktop's D-Bus services. Where nothing tells, only Keyless's
//! own use counts for the auto-lock.

use std::time::Duration;

/// Starts what has to watch from the start (the Wayland notification).
pub fn init() {
    #[cfg(target_os = "linux")]
    linux::init();
}

/// How long there has been no input on this computer, if the system says.
pub async fn system_idle() -> Option<Duration> {
    #[cfg(windows)]
    {
        windows::idle()
    }
    #[cfg(target_os = "linux")]
    {
        linux::idle().await
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

#[cfg(windows)]
mod windows {
    use std::time::Duration;

    use windows_sys::Win32::{
        System::SystemInformation::GetTickCount,
        UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
    };

    pub fn idle() -> Option<Duration> {
        let mut info = LASTINPUTINFO { cbSize: size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
        // SAFETY: a correctly sized LASTINPUTINFO; GetTickCount has no
        // preconditions.
        let (ok, now) = unsafe { (GetLastInputInfo(&mut info), GetTickCount()) };
        // Both wrap around every 49.7 days, together.
        (ok != 0).then(|| Duration::from_millis(u64::from(now.wrapping_sub(info.dwTime))))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        sync::Mutex,
        time::{Duration, Instant},
    };

    use tokio::sync::OnceCell;

    /// What the compositor last told.
    #[derive(Clone, Copy)]
    enum Watch {
        /// Nothing (it cannot tell, or stopped telling).
        Off,
        /// There is input.
        Input,
        /// No input since then.
        IdleSince(Instant),
    }

    static WAYLAND: Mutex<Watch> = Mutex::new(Watch::Off);

    fn set(watch: Watch) {
        *WAYLAND.lock().unwrap_or_else(|e| e.into_inner()) = watch;
    }

    pub fn init() {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            match wayland::start() {
                Ok(()) => log::info!("system idle time: from the Wayland compositor"),
                Err(err) => log::info!("no idle notifications from the Wayland compositor: {err}"),
            }
        }
    }

    pub async fn idle() -> Option<Duration> {
        let watch = *WAYLAND.lock().unwrap_or_else(|e| e.into_inner());
        match watch {
            Watch::Input => Some(Duration::ZERO),
            Watch::IdleSince(since) => Some(since.elapsed()),
            Watch::Off => dbus::idle().await,
        }
    }

    mod wayland {
        use std::time::{Duration, Instant};

        use wayland_client::{
            Connection, Dispatch, QueueHandle,
            globals::{GlobalListContents, registry_queue_init},
            protocol::{wl_registry, wl_seat},
        };
        use wayland_protocols::ext::idle_notify::v1::client::{
            ext_idle_notification_v1::{self, ExtIdleNotificationV1},
            ext_idle_notifier_v1::ExtIdleNotifierV1,
        };

        /// The notification fires once there was no input for this long;
        /// the time before it is added back.
        const THRESHOLD: Duration = Duration::from_secs(20);

        struct State;

        impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
            fn event(_: &mut Self, _: &wl_registry::WlRegistry, _: wl_registry::Event, _: &GlobalListContents, _: &Connection, _: &QueueHandle<Self>) {}
        }

        impl Dispatch<wl_seat::WlSeat, ()> for State {
            fn event(_: &mut Self, _: &wl_seat::WlSeat, _: wl_seat::Event, _: &(), _: &Connection, _: &QueueHandle<Self>) {}
        }

        impl Dispatch<ExtIdleNotifierV1, ()> for State {
            fn event(
                _: &mut Self,
                _: &ExtIdleNotifierV1,
                _: <ExtIdleNotifierV1 as wayland_client::Proxy>::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<Self>,
            ) {
            }
        }

        impl Dispatch<ExtIdleNotificationV1, ()> for State {
            fn event(_: &mut Self, _: &ExtIdleNotificationV1, event: ext_idle_notification_v1::Event, _: &(), _: &Connection, _: &QueueHandle<Self>) {
                match event {
                    ext_idle_notification_v1::Event::Idled => {
                        super::set(super::Watch::IdleSince(Instant::now().checked_sub(THRESHOLD).unwrap_or_else(Instant::now)))
                    }
                    ext_idle_notification_v1::Event::Resumed => super::set(super::Watch::Input),
                    _ => {}
                }
            }
        }

        /// Asks the compositor for a notification after `THRESHOLD` without
        /// input, and listens for it on a thread of its own.
        pub fn start() -> Result<(), String> {
            let conn = Connection::connect_to_env().map_err(|e| e.to_string())?;
            let (globals, mut queue) = registry_queue_init::<State>(&conn).map_err(|e| e.to_string())?;
            let qh = queue.handle();
            let seat: wl_seat::WlSeat = globals.bind(&qh, 1..=1, ()).map_err(|e| e.to_string())?;
            let notifier: ExtIdleNotifierV1 = globals.bind(&qh, 1..=2, ()).map_err(|e| e.to_string())?;
            let timeout = THRESHOLD.as_millis() as u32;
            // Version 2 counts input only: a playing video, which keeps the
            // screen on, does not keep Keyless unlocked.
            let notification = if wayland_client::Proxy::version(&notifier) >= 2 {
                notifier.get_input_idle_notification(timeout, &seat, &qh, ())
            } else {
                notifier.get_idle_notification(timeout, &seat, &qh, ())
            };
            super::set(super::Watch::Input);
            if let Err(err) = queue.roundtrip(&mut State) {
                super::set(super::Watch::Off);
                return Err(err.to_string());
            }
            let spawned = std::thread::Builder::new().name("idle-notify".into()).spawn(move || {
                let _kept = (seat, notifier, notification);
                while queue.blocking_dispatch(&mut State).is_ok() {}
                // Without notifications, only Keyless's own use counts.
                super::set(super::Watch::Off);
                log::info!("the Wayland idle notifications stopped");
            });
            if let Err(err) = spawned {
                super::set(super::Watch::Off);
                return Err(err.to_string());
            }
            Ok(())
        }
    }

    /// X11 sessions: GNOME's idle monitor, or the desktop's screen saver
    /// service (KDE, Xfce and others).
    mod dbus {
        use std::time::Duration;

        use super::OnceCell;

        #[derive(Clone, Copy)]
        enum Source {
            Mutter,
            ScreenSaver,
        }

        static SESSION: OnceCell<Option<(zbus::Connection, Source)>> = OnceCell::const_new();

        async fn ask(conn: &zbus::Connection, source: Source) -> Option<Duration> {
            match source {
                Source::Mutter => {
                    let reply = conn
                        .call_method(
                            Some("org.gnome.Mutter.IdleMonitor"),
                            "/org/gnome/Mutter/IdleMonitor/Core",
                            Some("org.gnome.Mutter.IdleMonitor"),
                            "GetIdletime",
                            &(),
                        )
                        .await
                        .ok()?;
                    reply.body().deserialize::<u64>().ok().map(Duration::from_millis)
                }
                Source::ScreenSaver => {
                    let reply = conn
                        .call_method(
                            Some("org.freedesktop.ScreenSaver"),
                            "/org/freedesktop/ScreenSaver",
                            Some("org.freedesktop.ScreenSaver"),
                            "GetSessionIdleTime",
                            &(),
                        )
                        .await
                        .ok()?;
                    reply.body().deserialize::<u32>().ok().map(|s| Duration::from_secs(u64::from(s)))
                }
            }
        }

        pub async fn idle() -> Option<Duration> {
            // Which service answers is found once.
            let found = SESSION
                .get_or_init(|| async {
                    let conn = zbus::Connection::session().await.ok()?;
                    for source in [Source::Mutter, Source::ScreenSaver] {
                        if ask(&conn, source).await.is_some() {
                            return Some((conn, source));
                        }
                    }
                    None
                })
                .await;
            let (conn, source) = found.as_ref()?;
            ask(conn, *source).await
        }
    }
}

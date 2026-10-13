//! Auto-Type: types a login into the app that had the focus before Quick
//! Access opened (username, Tab, password, Enter), for apps the browser
//! extension cannot fill. Never into Keyless's own windows.
//!
//! - Windows: SendInput, as Unicode characters (any keyboard layout).
//! - Linux on X11: XTest, through a spare key for characters the keyboard
//!   layout lacks.
//! - Linux on Wayland: the desktop's RemoteDesktop portal, which asks the
//!   user first; the permission lasts until Keyless locks.

use std::time::Duration;

use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::{
    error::{AppError, AppResult, Msg},
    state::AppState,
};

/// Time for the focus to go back to the app Quick Access covered.
const FOCUS_DELAY: Duration = Duration::from_millis(450);
/// Between keys: some apps lose keys that come too fast.
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
const KEY_DELAY: Duration = Duration::from_millis(8);

/// Keysyms (X11's names for keys, also the portal's).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod keysym {
    pub const TAB: u32 = 0xff09;
    pub const RETURN: u32 = 0xff0d;
    pub const SHIFT_L: u32 = 0xffe1;

    /// The keysym of a character: Latin-1 as itself, the rest as Unicode.
    pub fn of(c: char) -> u32 {
        match c {
            '\t' => TAB,
            '\n' | '\r' => RETURN,
            ' '..='~' | '\u{a0}'..='\u{ff}' => c as u32,
            c => 0x0100_0000 | c as u32,
        }
    }
}

/// What gets typed.
pub enum Step {
    Text(Zeroizing<String>),
    Tab,
    Enter,
}

fn error(code: &'static str) -> AppError {
    AppError::Invalid(Msg::new(code))
}

/// The window that had the focus when Quick Access opened (X11 and
/// Windows; Wayland gives it back by itself and tells no one which).
static PREVIOUS: std::sync::Mutex<Option<u64>> = std::sync::Mutex::new(None);

/// Quick Access opens: the window to type into later.
pub fn remember_focus() {
    *PREVIOUS.lock().unwrap_or_else(|e| e.into_inner()) = platform::focused_window();
}

/// Types item `item_id`'s username and password into the app in front.
pub async fn run(app: &AppHandle, item_id: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    let username = crate::items::copy_value(&state, item_id, None, Some("username")).await.ok().filter(|v| !v.is_empty());
    let password = crate::items::copy_value(&state, item_id, None, Some("password")).await.ok().filter(|v| !v.is_empty());
    let mut steps = Vec::new();
    let both = username.is_some() && password.is_some();
    if let Some(username) = username {
        steps.push(Step::Text(username));
        if both {
            steps.push(Step::Tab);
        }
    }
    if let Some(password) = password {
        steps.push(Step::Text(password));
    }
    if steps.is_empty() {
        return Err(error("autotype_nothing"));
    }
    steps.push(Step::Enter);
    crate::quick_access::hide(app);
    tokio::time::sleep(FOCUS_DELAY).await;
    let previous = PREVIOUS.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(window) = previous {
        platform::focus(window);
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    platform::type_steps(app, steps).await?;
    crate::commands::record_use(&state, item_id);
    Ok(())
}

/// Keyless locked: the permission to type ends with it.
pub fn forget() {
    #[cfg(target_os = "linux")]
    tauri::async_runtime::spawn(platform::wayland::close());
}

#[cfg(windows)]
mod platform {
    use windows_sys::Win32::UI::{
        Input::KeyboardAndMouse::{INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, SendInput, VK_RETURN, VK_TAB},
        WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId, IsWindow, SetForegroundWindow},
    };

    use super::*;

    pub fn focused_window() -> Option<u64> {
        // SAFETY: a plain call; the handle is kept as a number.
        let window = unsafe { GetForegroundWindow() };
        (!window.is_null()).then_some(window as usize as u64)
    }

    pub fn focus(window: u64) {
        let window = window as usize as windows_sys::Win32::Foundation::HWND;
        // SAFETY: the handle is checked to still be a window first.
        unsafe {
            if IsWindow(window) != 0 {
                SetForegroundWindow(window);
            }
        }
    }

    fn key(vk: u16, unit: u16, flags: u32) -> INPUT {
        INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: unit, dwFlags: flags, time: 0, dwExtraInfo: 0 } } }
    }

    fn send(inputs: &[INPUT]) -> AppResult<()> {
        // SAFETY: a slice of initialized INPUT structures, with its length
        // and the structure's size.
        let sent = unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), std::mem::size_of::<INPUT>() as i32) };
        if sent as usize == inputs.len() { Ok(()) } else { Err(error("autotype_failed")) }
    }

    pub async fn type_steps(_app: &AppHandle, steps: Vec<Step>) -> AppResult<()> {
        // The window that would get the keys: never one of Keyless's.
        let ours = {
            // SAFETY: plain calls; the window handle is only read.
            let window = unsafe { GetForegroundWindow() };
            let mut pid = 0u32;
            unsafe { GetWindowThreadProcessId(window, &mut pid) };
            window.is_null() || pid == std::process::id()
        };
        if ours {
            return Err(error("autotype_own_window"));
        }
        for step in &steps {
            match step {
                Step::Text(text) => {
                    for unit in text.encode_utf16() {
                        send(&[key(0, unit, KEYEVENTF_UNICODE), key(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)])?;
                        tokio::time::sleep(KEY_DELAY).await;
                    }
                }
                Step::Tab => send(&[key(VK_TAB, 0, 0), key(VK_TAB, 0, KEYEVENTF_KEYUP)])?,
                Step::Enter => send(&[key(VK_RETURN, 0, 0), key(VK_RETURN, 0, KEYEVENTF_KEYUP)])?,
            }
            tokio::time::sleep(KEY_DELAY).await;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    fn keysyms(steps: &[Step]) -> Zeroizing<Vec<u32>> {
        let mut keys = Zeroizing::new(Vec::new());
        for step in steps {
            match step {
                Step::Text(text) => keys.extend(text.chars().map(keysym::of)),
                Step::Tab => keys.push(keysym::TAB),
                Step::Enter => keys.push(keysym::RETURN),
            }
        }
        keys
    }

    fn wayland_session() -> bool {
        std::env::var_os("WAYLAND_DISPLAY").is_some()
    }

    pub fn focused_window() -> Option<u64> {
        if wayland_session() { None } else { x11::focused_window() }
    }

    pub fn focus(window: u64) {
        if !wayland_session() {
            x11::focus(window);
        }
    }

    pub async fn type_steps(_app: &AppHandle, steps: Vec<Step>) -> AppResult<()> {
        let keys = keysyms(&steps);
        drop(steps);
        if wayland_session() {
            wayland::type_keys(&keys).await
        } else {
            tokio::task::spawn_blocking(move || x11::type_keys(&keys)).await.map_err(|_| error("autotype_failed"))?
        }
    }

    pub mod x11 {
        use x11rb::{
            CURRENT_TIME,
            connection::Connection,
            protocol::{
                xproto::{AtomEnum, ClientMessageEvent, ConnectionExt as _, EventMask, InputFocus, KEY_PRESS_EVENT, KEY_RELEASE_EVENT},
                xtest::ConnectionExt as _,
            },
        };

        use super::*;

        fn failed<E>(_: E) -> AppError {
            error("autotype_failed")
        }

        /// Whether the window with the keyboard focus is Keyless's (its
        /// top-level window says whose it is).
        fn focus_is_ours(conn: &impl Connection) -> AppResult<bool> {
            let pid_atom = conn.intern_atom(true, b"_NET_WM_PID").map_err(failed)?.reply().map_err(failed)?.atom;
            let mut window = conn.get_input_focus().map_err(failed)?.reply().map_err(failed)?.focus;
            // None or PointerRoot: no window to check.
            while window > 1 && pid_atom != 0 {
                let reply = conn.get_property(false, window, pid_atom, AtomEnum::CARDINAL, 0, 1).map_err(failed)?.reply().map_err(failed)?;
                if let Some(pid) = reply.value32().and_then(|mut v| v.next()) {
                    return Ok(pid == std::process::id());
                }
                let tree = conn.query_tree(window).map_err(failed)?.reply().map_err(failed)?;
                if tree.parent == tree.root || tree.parent == 0 {
                    break;
                }
                window = tree.parent;
            }
            Ok(false)
        }

        pub fn focused_window() -> Option<u64> {
            let (conn, _) = x11rb::connect(None).ok()?;
            let focus = conn.get_input_focus().ok()?.reply().ok()?.focus;
            (focus > 1).then_some(u64::from(focus))
        }

        /// Gives the focus back to `window`: through the window manager
        /// when there is one, so it also comes to the front.
        pub fn focus(window: u64) {
            let Ok(window) = u32::try_from(window) else { return };
            let Ok((conn, screen)) = x11rb::connect(None) else { return };
            let root = conn.setup().roots[screen].root;
            let atom = |name: &[u8]| conn.intern_atom(true, name).ok().and_then(|c| c.reply().ok()).map(|r| r.atom).filter(|&a| a != 0);
            let managed = atom(b"_NET_SUPPORTING_WM_CHECK")
                .and_then(|check| conn.get_property(false, root, check, AtomEnum::WINDOW, 0, 1).ok()?.reply().ok())
                .is_some_and(|reply| reply.value_len > 0);
            if let (true, Some(active)) = (managed, atom(b"_NET_ACTIVE_WINDOW")) {
                // The top-level window, which is what the window manager knows.
                let mut top = window;
                while let Some(tree) = conn.query_tree(top).ok().and_then(|c| c.reply().ok()) {
                    if tree.parent == tree.root || tree.parent == 0 {
                        break;
                    }
                    top = tree.parent;
                }
                let event = ClientMessageEvent::new(32, top, active, [2, CURRENT_TIME, 0, 0, 0]);
                let _ = conn.send_event(false, root, EventMask::SUBSTRUCTURE_REDIRECT | EventMask::SUBSTRUCTURE_NOTIFY, event);
            } else {
                let _ = conn.set_input_focus(InputFocus::PARENT, window, CURRENT_TIME);
            }
            let _ = conn.flush();
        }

        pub fn type_keys(keys: &[u32]) -> AppResult<()> {
            let (conn, screen) = x11rb::connect(None).map_err(|_| error("autotype_unavailable"))?;
            if focus_is_ours(&conn)? {
                return Err(error("autotype_own_window"));
            }
            let setup = conn.setup();
            let root = setup.roots[screen].root;
            let (min, max) = (setup.min_keycode, setup.max_keycode);
            let mapping = conn.get_keyboard_mapping(min, max - min + 1).map_err(failed)?.reply().map_err(failed)?;
            let per = usize::from(mapping.keysyms_per_keycode.max(1));
            // The key and whether it needs Shift, on the current layout.
            let find = |sym: u32| {
                mapping.keysyms.chunks(per).enumerate().find_map(|(i, syms)| {
                    let code = min + i as u8;
                    if syms.first() == Some(&sym) {
                        Some((code, false))
                    } else if syms.get(1) == Some(&sym) {
                        Some((code, true))
                    } else {
                        None
                    }
                })
            };
            let shift = find(keysym::SHIFT_L).map(|(code, _)| code);
            // A key with nothing on it, for characters the layout lacks.
            let spare = mapping.keysyms.chunks(per).position(|syms| syms.iter().all(|&s| s == 0)).map(|i| min + i as u8);
            let fake = |kind: u8, code: u8| conn.xtest_fake_input(kind, code, CURRENT_TIME, root, 0, 0, 0).map(drop).map_err(failed);
            let mut remapped = false;
            let mut result = Ok(());
            for &sym in keys {
                let (code, shifted) = match find(sym) {
                    Some(found) => found,
                    None => {
                        let Some(spare) = spare else {
                            result = Err(error("autotype_unavailable"));
                            break;
                        };
                        let mut syms = vec![0u32; per];
                        syms[0] = sym;
                        if per > 1 {
                            syms[1] = sym;
                        }
                        conn.change_keyboard_mapping(1, spare, per as u8, &syms).map_err(failed)?;
                        // Applied before the key goes (a round trip).
                        conn.get_input_focus().map_err(failed)?.reply().map_err(failed)?;
                        std::thread::sleep(Duration::from_millis(20));
                        remapped = true;
                        (spare, false)
                    }
                };
                let shift = shift.filter(|_| shifted);
                if let Some(shift) = shift {
                    fake(KEY_PRESS_EVENT, shift)?;
                }
                fake(KEY_PRESS_EVENT, code)?;
                fake(KEY_RELEASE_EVENT, code)?;
                if let Some(shift) = shift {
                    fake(KEY_RELEASE_EVENT, shift)?;
                }
                conn.get_input_focus().map_err(failed)?.reply().map_err(failed)?;
                std::thread::sleep(KEY_DELAY);
            }
            if let (true, Some(spare)) = (remapped, spare) {
                std::thread::sleep(Duration::from_millis(20));
                conn.change_keyboard_mapping(1, spare, per as u8, &vec![0u32; per]).map_err(failed)?;
            }
            conn.flush().map_err(failed)?;
            result
        }
    }

    pub mod wayland {
        use ashpd::desktop::{
            PersistMode, Session,
            remote_desktop::{DeviceType, KeyState, RemoteDesktop},
        };
        use tokio::sync::Mutex;

        use super::*;

        /// The portal's session, kept while Keyless is unlocked so the
        /// desktop asks once.
        struct Portal {
            proxy: RemoteDesktop<'static>,
            session: Session<'static, RemoteDesktop<'static>>,
        }

        static PORTAL: Mutex<Option<Portal>> = Mutex::const_new(None);

        fn unavailable<E: std::fmt::Display>(err: E) -> AppError {
            log::warn!("remote desktop portal: {err}");
            error("autotype_unavailable")
        }

        async fn start() -> AppResult<Portal> {
            let proxy = RemoteDesktop::new().await.map_err(unavailable)?;
            let session = proxy.create_session().await.map_err(unavailable)?;
            proxy.select_devices(&session, DeviceType::Keyboard.into(), None, PersistMode::DoNot).await.map_err(unavailable)?;
            proxy.start(&session, None).await.map_err(unavailable)?.response().map_err(|_| error("autotype_denied"))?;
            Ok(Portal { proxy, session })
        }

        pub async fn type_keys(keys: &[u32]) -> AppResult<()> {
            let mut portal = PORTAL.lock().await;
            if portal.is_none() {
                *portal = Some(start().await?);
                // The desktop's question took the focus: back to the app.
                tokio::time::sleep(FOCUS_DELAY).await;
            }
            let sent = {
                let Some(Portal { proxy, session }) = portal.as_ref() else { return Err(error("autotype_unavailable")) };
                let mut sent = Ok(());
                for &sym in keys {
                    let key = async {
                        proxy.notify_keyboard_keysym(session, sym as i32, KeyState::Pressed).await?;
                        proxy.notify_keyboard_keysym(session, sym as i32, KeyState::Released).await
                    };
                    if let Err(err) = key.await {
                        sent = Err(err);
                        break;
                    }
                    tokio::time::sleep(KEY_DELAY).await;
                }
                sent
            };
            // A session the desktop ended: the desktop asks again next time.
            sent.map_err(|err| {
                *portal = None;
                unavailable(err)
            })
        }

        pub async fn close() {
            if let Some(portal) = PORTAL.lock().await.take() {
                let _ = portal.session.close().await;
            }
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod platform {
    use super::*;

    pub fn focused_window() -> Option<u64> {
        None
    }

    pub fn focus(_window: u64) {}

    pub async fn type_steps(_app: &AppHandle, _steps: Vec<Step>) -> AppResult<()> {
        Err(error("autotype_unavailable"))
    }
}

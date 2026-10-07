//! Reading a one-time password QR code (`otpauth://`) from the screen, the
//! clipboard or an image file, like 1Password's "Scan QR Code".
//!
//! The screen is captured through the system: the screenshot portal on
//! Linux (the desktop may ask the user the first time), GDI on Windows. The
//! image only lives in memory; a screenshot the portal saved to disk is
//! deleted at once.

use std::{io::Cursor, time::Duration};

use image::GrayImage;
use keyless_core::totp::Totp;
use tauri::{AppHandle, Manager};

use crate::error::{AppError, AppResult, Msg};

/// Larger images are refused (and screenshots this large do not exist).
const MAX_FILE: u64 = 25 * 1024 * 1024;

fn not_found() -> AppError {
    AppError::Invalid(Msg::new("qr_not_found"))
}

/// Reads a QR code from `source` ("screen", "clipboard" or "file") and
/// returns its `otpauth://` address.
pub async fn scan(app: &AppHandle, source: &str) -> AppResult<String> {
    let image = match source {
        "screen" => screenshot(app).await?,
        "clipboard" => tokio::task::spawn_blocking(clipboard_image).await.map_err(|_| not_found())??,
        "file" => pick_image(app).await?,
        _ => return Err(AppError::Invalid(Msg::new("invalid_request"))),
    };
    tokio::task::spawn_blocking(move || decode(&image)).await.map_err(|_| not_found())?.ok_or_else(not_found)
}

/// The first QR code in the image holding a valid one-time password setup.
fn decode(image: &GrayImage) -> Option<String> {
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(image.width() as usize, image.height() as usize, |x, y| {
        image.get_pixel(x as u32, y as u32)[0]
    });
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok())
        .map(|(_, content)| content)
        .find(|content| content.starts_with("otpauth://") && Totp::parse(content).is_ok())
}

/// Decodes an image file's bytes with size limits.
fn load(bytes: &[u8]) -> AppResult<GrayImage> {
    let mut reader = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format().map_err(|_| not_found())?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(512 * 1024 * 1024);
    reader.limits(limits);
    Ok(reader.decode().map_err(|_| not_found())?.to_luma8())
}

fn clipboard_image() -> AppResult<GrayImage> {
    let image = arboard::Clipboard::new()
        .and_then(|mut clipboard| clipboard.get_image())
        .map_err(|_| AppError::Invalid(Msg::new("qr_no_clipboard_image")))?;
    let (width, height) = (image.width as u32, image.height as u32);
    let rgba = image::RgbaImage::from_raw(width, height, image.bytes.into_owned()).ok_or_else(not_found)?;
    Ok(image::DynamicImage::ImageRgba8(rgba).to_luma8())
}

async fn pick_image(app: &AppHandle) -> AppResult<GrayImage> {
    use tauri_plugin_dialog::DialogExt;
    let dialog = app.dialog().file().add_filter("Images", &["png", "jpg", "jpeg", "gif", "bmp", "webp"]);
    let picked = tokio::task::spawn_blocking(move || dialog.blocking_pick_file()).await.map_err(|_| AppError::Cancelled)?;
    let path = picked.and_then(|p| p.into_path().ok()).ok_or(AppError::Cancelled)?;
    tokio::task::spawn_blocking(move || {
        let size = std::fs::metadata(&path).map_err(|e| AppError::Store(e.to_string()))?.len();
        if size > MAX_FILE {
            return Err(not_found());
        }
        load(&std::fs::read(&path).map_err(|e| AppError::Store(e.to_string()))?)
    })
    .await
    .map_err(|_| not_found())?
}

/// Captures the screen with Keyless's own windows out of the way.
async fn screenshot(app: &AppHandle) -> AppResult<GrayImage> {
    let visible: Vec<_> = app.webview_windows().into_values().filter(|w| w.is_visible().unwrap_or(false)).collect();
    for window in &visible {
        let _ = window.hide();
    }
    tokio::time::sleep(Duration::from_millis(350)).await;
    let image = capture().await;
    for window in &visible {
        let _ = window.show();
    }
    if let Some(window) = visible.first() {
        let _ = window.set_focus();
    }
    image
}

#[cfg(target_os = "linux")]
async fn capture() -> AppResult<GrayImage> {
    use std::collections::HashMap;

    use futures_lite::StreamExt;
    use zbus::zvariant::{OwnedValue, Value};

    let failed = |detail: String| AppError::Invalid(Msg::new("qr_screen_failed").with("detail", detail));
    let connection = zbus::Connection::session().await.map_err(|e| failed(e.to_string()))?;
    // The portal answers on a request object whose path follows from our
    // bus name and a token we choose: listen before asking.
    let sender = connection.unique_name().ok_or_else(|| failed("no bus name".into()))?.trim_start_matches(':').replace('.', "_");
    let token = format!("keyless{}", uuid::Uuid::new_v4().simple());
    let path = format!("/org/freedesktop/portal/desktop/request/{sender}/{token}");
    let request = zbus::Proxy::new(&connection, "org.freedesktop.portal.Desktop", path.as_str(), "org.freedesktop.portal.Request")
        .await
        .map_err(|e| failed(e.to_string()))?;
    let mut responses = request.receive_signal("Response").await.map_err(|e| failed(e.to_string()))?;

    let mut options: HashMap<&str, Value> = HashMap::new();
    options.insert("handle_token", Value::from(token.as_str()));
    options.insert("interactive", Value::from(false));
    options.insert("modal", Value::from(true));
    connection
        .call_method(
            Some("org.freedesktop.portal.Desktop"),
            "/org/freedesktop/portal/desktop",
            Some("org.freedesktop.portal.Screenshot"),
            "Screenshot",
            &("", options),
        )
        .await
        .map_err(|e| failed(e.to_string()))?;

    let message = tokio::time::timeout(Duration::from_secs(60), responses.next())
        .await
        .map_err(|_| failed("no answer".into()))?
        .ok_or_else(|| failed("no answer".into()))?;
    let (response, results): (u32, HashMap<String, OwnedValue>) = message.body().deserialize().map_err(|e| failed(e.to_string()))?;
    match response {
        0 => {}
        // The user said no.
        1 => return Err(AppError::Cancelled),
        _ => return Err(failed(format!("portal response {response}"))),
    }
    let uri = results.get("uri").and_then(|v| <&str>::try_from(&**v).ok()).ok_or_else(|| failed("no screenshot".into()))?;
    let path = url::Url::parse(uri).ok().and_then(|u| u.to_file_path().ok()).ok_or_else(|| failed("bad screenshot address".into()))?;
    tokio::task::spawn_blocking(move || {
        let bytes = std::fs::read(&path);
        // A capture of the whole screen: not kept anywhere.
        let _ = std::fs::remove_file(&path);
        load(&bytes.map_err(|e| failed(e.to_string()))?)
    })
    .await
    .map_err(|e| failed(e.to_string()))?
}

#[cfg(windows)]
async fn capture() -> AppResult<GrayImage> {
    tokio::task::spawn_blocking(windows::capture).await.map_err(|_| not_found())?
}

#[cfg(not(any(target_os = "linux", windows)))]
async fn capture() -> AppResult<GrayImage> {
    Err(AppError::Invalid(Msg::new("qr_screen_failed").with("detail", "unsupported")))
}

#[cfg(windows)]
mod windows {
    use image::{GrayImage, Luma};
    use windows_sys::Win32::{
        Graphics::Gdi::{
            BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC, DeleteObject,
            GetDC, GetDIBits, ReleaseDC, SRCCOPY, SelectObject,
        },
        UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN},
    };

    use crate::error::{AppError, AppResult, Msg};

    /// The whole virtual screen (every monitor), in grey.
    pub fn capture() -> AppResult<GrayImage> {
        let failed = |detail: &str| AppError::Invalid(Msg::new("qr_screen_failed").with("detail", detail));
        // SAFETY: plain GDI calls on handles created and released here; the
        // pixel buffer is sized for the bitmap GetDIBits writes.
        unsafe {
            let (x, y) = (GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN));
            let (width, height) = (GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
            if width <= 0 || height <= 0 {
                return Err(failed("no screen"));
            }
            let screen = GetDC(std::ptr::null_mut());
            let memory = CreateCompatibleDC(screen);
            let bitmap = CreateCompatibleBitmap(screen, width, height);
            let previous = SelectObject(memory, bitmap);
            let copied = BitBlt(memory, 0, 0, width, height, screen, x, y, SRCCOPY);
            let mut info: BITMAPINFO = std::mem::zeroed();
            info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
            info.bmiHeader.biWidth = width;
            info.bmiHeader.biHeight = -height; // top-down rows
            info.bmiHeader.biPlanes = 1;
            info.bmiHeader.biBitCount = 32;
            info.bmiHeader.biCompression = BI_RGB;
            let mut pixels = vec![0u8; width as usize * height as usize * 4];
            let lines = GetDIBits(memory, bitmap, 0, height as u32, pixels.as_mut_ptr().cast(), &mut info, DIB_RGB_COLORS);
            SelectObject(memory, previous);
            DeleteObject(bitmap);
            DeleteDC(memory);
            ReleaseDC(std::ptr::null_mut(), screen);
            if copied == 0 || lines == 0 {
                return Err(failed("capture failed"));
            }
            let (width, height) = (width as u32, height as u32);
            Ok(GrayImage::from_fn(width, height, |px, py| {
                let i = (py as usize * width as usize + px as usize) * 4;
                let (b, g, r) = (pixels[i] as u32, pixels[i + 1] as u32, pixels[i + 2] as u32);
                Luma([((299 * r + 587 * g + 114 * b) / 1000) as u8])
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `otpauth://` QR code rendered by `qrencode`, with a quiet zone.
    const QR_PNG: &[u8] = include_bytes!("../testdata/otpauth-qr.png");

    #[test]
    fn reads_otpauth_codes() {
        let image = load(QR_PNG).unwrap();
        let uri = decode(&image).unwrap();
        assert!(uri.starts_with("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP"));
        // Noise is not a code.
        assert!(decode(&GrayImage::from_fn(200, 200, |x, y| image::Luma([((x * 7 + y * 13) % 255) as u8]))).is_none());
        assert!(load(b"not an image").is_err());
    }
}

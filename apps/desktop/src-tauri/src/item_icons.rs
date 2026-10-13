//! Icons the user gives an item: any image they choose, made into a small
//! PNG here (so only a clean, small image is ever stored, whatever the file
//! held).

use std::io::Cursor;

use base64::{Engine, engine::general_purpose::STANDARD};
use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;

use crate::{
    dialog_text::DialogText,
    error::{AppError, AppResult, Msg},
    items::ICON_PREFIX,
};

/// Largest side of a stored icon, in pixels.
const SIZE: u32 = 128;
/// Larger files are not read.
const MAX_FILE: u64 = 16 * 1024 * 1024;

/// Asks for an image and returns it as an item icon (a PNG data URL).
pub async fn pick(app: &AppHandle, text: &DialogText) -> AppResult<String> {
    let dialog = text.apply(app.dialog().file(), &["png", "jpg", "jpeg", "webp", "gif", "bmp", "ico"]);
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_pick_file())
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
        .ok_or(AppError::Cancelled)?;
    let path = picked.into_path().map_err(|_| AppError::Invalid(Msg::new("file_unreadable")))?;
    let size = tokio::fs::metadata(&path).await.map_err(|e| AppError::Invalid(Msg::new("file_unreadable").with("detail", e)))?.len();
    if size > MAX_FILE {
        return Err(AppError::Invalid(Msg::new("icon_invalid")));
    }
    let bytes = tokio::fs::read(&path).await.map_err(|e| AppError::Invalid(Msg::new("file_unreadable").with("detail", e)))?;
    tauri::async_runtime::spawn_blocking(move || icon_from(&bytes))
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
}

/// Decodes an image and makes it an icon: at most `SIZE` pixels a side,
/// keeping its proportions, as PNG.
pub fn icon_from(bytes: &[u8]) -> AppResult<String> {
    let image = image::load_from_memory(bytes).map_err(|_| AppError::Invalid(Msg::new("icon_invalid")))?;
    let image = if image.width() > SIZE || image.height() > SIZE {
        image.resize(SIZE, SIZE, image::imageops::FilterType::Lanczos3)
    } else {
        image
    };
    let mut png = Vec::new();
    image::DynamicImage::ImageRgba8(image.to_rgba8())
        .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
        .map_err(|_| AppError::Invalid(Msg::new("icon_invalid")))?;
    Ok(format!("{ICON_PREFIX}{}", STANDARD.encode(png)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn images_become_small_pngs() {
        let mut source = Vec::new();
        image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(600, 300, image::Rgba([10, 20, 30, 255])))
            .write_to(&mut Cursor::new(&mut source), image::ImageFormat::Png)
            .unwrap();
        let icon = icon_from(&source).unwrap();
        assert!(icon.starts_with(ICON_PREFIX));
        let png = STANDARD.decode(&icon[ICON_PREFIX.len()..]).unwrap();
        let decoded = image::load_from_memory(&png).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (128, 64));
        assert!(icon_from(b"not an image").is_err());
    }
}

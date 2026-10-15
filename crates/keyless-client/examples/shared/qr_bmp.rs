//! Shared by the examples: a QR code as a picture the apps' "Scan QR
//! code" can be pointed at.

/// A QR code as a BMP picture (black on white), in base64, for the apps'
/// "Scan QR code" tests.
pub fn qr_bmp(text: &str) -> String {
    use base64::Engine;
    let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
    let (modules, colors) = (code.width(), code.to_colors());
    let scale = 8;
    let size = (modules + 8) * scale;
    let row = (size * 3).div_ceil(4) * 4;
    let mut bmp = Vec::with_capacity(54 + row * size);
    let file_size = (54 + row * size) as u32;
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&file_size.to_le_bytes());
    bmp.extend_from_slice(&[0, 0, 0, 0, 54, 0, 0, 0, 40, 0, 0, 0]);
    bmp.extend_from_slice(&(size as i32).to_le_bytes());
    bmp.extend_from_slice(&(size as i32).to_le_bytes());
    bmp.extend_from_slice(&[1, 0, 24, 0, 0, 0, 0, 0]);
    bmp.extend_from_slice(&((row * size) as u32).to_le_bytes());
    bmp.extend_from_slice(&[0; 16]);
    // Rows go bottom up.
    for y in (0..size).rev() {
        let mut line = vec![255u8; row];
        for x in 0..size {
            let (mx, my) = (x / scale, y / scale);
            if (4..modules + 4).contains(&mx) && (4..modules + 4).contains(&my) && colors[(my - 4) * modules + (mx - 4)] == qrcode::Color::Dark {
                line[x * 3..x * 3 + 3].fill(0);
            }
        }
        bmp.extend_from_slice(&line);
    }
    base64::engine::general_purpose::STANDARD.encode(bmp)
}

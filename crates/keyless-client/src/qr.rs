//! QR codes in a camera frame or a picture (greyscale), for the apps' "Scan
//! QR code": a one-time password setup (`otpauth://`) or a setup code
//! (`keyless://setup`). The app decides what it was looking for.

/// The contents of every QR code found in a greyscale image whose rows are
/// `stride` bytes apart (a camera's luminance plane, as it comes).
pub fn decode_grey(pixels: &[u8], width: usize, height: usize, stride: usize) -> Vec<String> {
    if width == 0 || height == 0 || stride < width || pixels.len() < stride * (height - 1) + width {
        return Vec::new();
    }
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| pixels[y * stride + x]);
    prepared.detect_grids().into_iter().filter_map(|grid| grid.decode().ok()).map(|(_, content)| content).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A QR code drawn the way a camera would see it: dark modules on white,
    /// scaled up, with a margin, in a frame with padding after each row.
    fn picture(text: &str, scale: usize, stride_pad: usize) -> (Vec<u8>, usize, usize, usize) {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let modules = code.width();
        let colors = code.to_colors();
        let size = (modules + 8) * scale;
        let stride = size + stride_pad;
        let mut pixels = vec![255u8; stride * size];
        for y in 0..size {
            for x in 0..size {
                let (mx, my) = (x / scale, y / scale);
                if (4..modules + 4).contains(&mx) && (4..modules + 4).contains(&my) && colors[(my - 4) * modules + (mx - 4)] == qrcode::Color::Dark {
                    pixels[y * stride + x] = 0;
                }
            }
        }
        (pixels, size, size, stride)
    }

    #[test]
    fn reads_codes_in_frames() {
        let uri = "otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let (pixels, width, height, stride) = picture(uri, 6, 32);
        assert_eq!(decode_grey(&pixels, width, height, stride), vec![uri.to_string()]);
        assert!(decode_grey(&vec![255u8; 100 * 100], 100, 100, 100).is_empty());
        // A frame shorter than it says is refused, not read past.
        assert!(decode_grey(&pixels[..10], width, height, stride).is_empty());
    }
}

//! QR codes: reading them from pictures and camera frames, and Keyless's own
//! look for the ones one Keyless app shows another (signing in, setup
//! codes): round dots, rounded finder and alignment patterns, and the logo in
//! the middle.
//!
//! What the reader (rqrr, a port of quirc) needs from that look, measured
//! over many codes and sizes:
//! - The finder patterns keep square outer corners: readers find a code by
//!   them, and rounding them by even a module stops it reading.
//! - The timing patterns and the format and version information stay
//!   squares: as dots, codes at some sizes were not found at all. Only the
//!   data modules are dots.
//! - The color stays close to black.
//! - The modules under the logo read as errors, well within what the code's
//!   error correction (level Q, a quarter of it) fixes; a higher level would
//!   make the code larger, so smaller on screen and harder for a camera.
//!
//! Each app draws the shapes described here, with the sizes in [`QrArt`].

use serde::Serialize;

/// The logo's clear circle, as a share of the code's width (without the
/// quiet zone).
const LOGO_SHARE: f32 = 0.24;
const DOT_RADIUS: f32 = 0.45;
const FINDER_CORNER: f32 = 0.3;
const FINDER_HOLE_CORNER: f32 = 1.2;
const FINDER_STONE_CORNER: f32 = 1.0;
const ALIGNMENT_CORNER: f32 = 1.2;
const ALIGNMENT_HOLE_CORNER: f32 = 0.65;

/// A QR code's shapes, in modules (the quiet zone is the app's to add).
#[derive(Debug, Serialize)]
pub struct QrArt {
    /// Modules per side.
    pub size: usize,
    /// The dark modules outside the finder and alignment patterns and the
    /// logo's circle, row by row: '1' a dot (data), '2' a square (timing
    /// patterns, format and version information), '0' nothing.
    pub modules: Vec<String>,
    /// Top-left corners of the three 7×7 finder patterns.
    pub finders: Vec<[usize; 2]>,
    /// Centers of the 5×5 alignment patterns outside the logo's circle.
    pub alignments: Vec<[usize; 2]>,
    /// Radius of the logo's circle, centered in the code.
    pub logo_radius: f32,
    /// Radius of a dot (a module is 1 wide).
    pub dot_radius: f32,
    /// Corner radii of a finder pattern: its 7×7 square, the light 5×5
    /// square inside it and the dark 3×3 one in the middle.
    pub finder_corners: [f32; 3],
    /// Corner radii of an alignment pattern: its 5×5 square and the light
    /// 3×3 one inside it (a dot of `dot_radius` in the middle).
    pub alignment_corners: [f32; 2],
}

/// Other sizes an image is read again at when no code was found in it: rqrr
/// misses codes at some sizes (around 4 pixels per module, a different size
/// for each look), and another size reads them.
const RETRY_SCALES: [f32; 3] = [1.3, 0.77, 1.6];
/// Larger retries are skipped past this many pixels (a whole 4K screen).
const MAX_RETRY_PIXELS: usize = 16_000_000;

/// The contents of every QR code found in a greyscale image whose rows are
/// `stride` bytes apart (a camera's luminance plane, as it comes).
pub fn decode_grey(pixels: &[u8], width: usize, height: usize, stride: usize) -> Vec<String> {
    if width == 0 || height == 0 || stride < width || pixels.len() < stride * (height - 1) + width {
        return Vec::new();
    }
    let found = detect(width, height, |x, y| pixels[y * stride + x]);
    if !found.is_empty() {
        return found;
    }
    for scale in RETRY_SCALES {
        let (w, h) = ((width as f32 * scale) as usize, (height as f32 * scale) as usize);
        if w < 21 || h < 21 || w * h > MAX_RETRY_PIXELS {
            continue;
        }
        // Bilinear samples, close enough to averaging at these scales.
        let sample = |x: usize, y: usize| {
            let (fx, fy) = (((x as f32 + 0.5) / scale - 0.5).max(0.0), ((y as f32 + 0.5) / scale - 0.5).max(0.0));
            let (x0, y0) = ((fx as usize).min(width - 1), (fy as usize).min(height - 1));
            let (x1, y1) = ((x0 + 1).min(width - 1), (y0 + 1).min(height - 1));
            let (tx, ty) = (fx - x0 as f32, fy - y0 as f32);
            let p = |x: usize, y: usize| pixels[y * stride + x] as f32;
            let top = p(x0, y0) * (1.0 - tx) + p(x1, y0) * tx;
            let bottom = p(x0, y1) * (1.0 - tx) + p(x1, y1) * tx;
            (top * (1.0 - ty) + bottom * ty).round() as u8
        };
        let found = detect(w, h, sample);
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

fn detect(width: usize, height: usize, pixel: impl FnMut(usize, usize) -> u8) -> Vec<String> {
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(width, height, pixel);
    prepared.detect_grids().into_iter().filter_map(|grid| grid.decode().ok()).map(|(_, content)| content).collect()
}

/// The shapes of a QR code for `text`; None when it is too long for one.
pub fn art(text: &str) -> Option<QrArt> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::Q).ok()?;
    let size = code.width();
    let colors = code.to_colors();
    let dark = |x: usize, y: usize| colors[y * size + x] == qrcode::Color::Dark;

    let finders = vec![[0, 0], [size - 7, 0], [0, size - 7]];
    let in_finder = |x: usize, y: usize| finders.iter().any(|&[fx, fy]| (fx..fx + 7).contains(&x) && (fy..fy + 7).contains(&y));

    let center = size as f32 / 2.0;
    let logo_radius = size as f32 * LOGO_SHARE / 2.0;
    let under_logo = |x: usize, y: usize| {
        let (dx, dy) = (x as f32 + 0.5 - center, y as f32 + 0.5 - center);
        // The whole module, not just its center, keeps clear of the logo.
        (dx * dx + dy * dy).sqrt() < logo_radius + 0.75
    };

    // An alignment pattern: functional modules, dark in the middle and on
    // the outer ring, light in between.
    let alignment_at = |cx: usize, cy: usize| {
        if cx < 2 || cy < 2 || cx + 2 >= size || cy + 2 >= size {
            return false;
        }
        (cy - 2..=cy + 2).all(|y| {
            (cx - 2..=cx + 2).all(|x| {
                let ring = x.abs_diff(cx).max(y.abs_diff(cy));
                code.is_functional(x, y) && !in_finder(x, y) && dark(x, y) == (ring != 1)
            })
        })
    };
    let alignments: Vec<[usize; 2]> = (0..size)
        .flat_map(|y| (0..size).map(move |x| (x, y)))
        .filter(|&(x, y)| alignment_at(x, y))
        .map(|(x, y)| [x, y])
        .collect();
    let in_alignment = |x: usize, y: usize| alignments.iter().any(|&[ax, ay]| x.abs_diff(ax) <= 2 && y.abs_diff(ay) <= 2);
    let shown_alignments = alignments.iter().copied().filter(|&[x, y]| !under_logo(x, y)).collect();

    let modules = (0..size)
        .map(|y| {
            (0..size)
                .map(|x| match () {
                    _ if !dark(x, y) || in_finder(x, y) || in_alignment(x, y) || under_logo(x, y) => '0',
                    _ if code.is_functional(x, y) => '2',
                    _ => '1',
                })
                .collect()
        })
        .collect();
    Some(QrArt {
        size,
        modules,
        finders,
        alignments: shown_alignments,
        logo_radius,
        dot_radius: DOT_RADIUS,
        finder_corners: [FINDER_CORNER, FINDER_HOLE_CORNER, FINDER_STONE_CORNER],
        alignment_corners: [ALIGNMENT_CORNER, ALIGNMENT_HOLE_CORNER],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGN_IN: &str = "keyless://sign-in#id=0f8fad5b-d9cb-469f-a165-70867728950e&key=Q2hlY2sgdGhlIGxlbmd0aCBvZiB0aGlzIGtleSBwbGVhc2Uu&token=dGVzdHRva2VudGVzdHRva2Vu";

    /// A link shaped like a real sign-in link, different for each `seed`.
    fn sign_in_link(seed: u64) -> String {
        let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ seed.wrapping_mul(0x2545_F491_4F6C_DD1D);
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut pick = |n: usize, alphabet: &[u8]| (0..n).map(|_| alphabet[(next() % alphabet.len() as u64) as usize] as char).collect::<String>();
        let hex = b"0123456789abcdef";
        let id = format!("{}-{}-4{}-a{}-{}", pick(8, hex), pick(4, hex), pick(3, hex), pick(3, hex), pick(12, hex));
        format!("keyless://sign-in#id={id}&key={}&token={}", pick(43, B64), pick(22, B64))
    }

    fn rounded_rect(x: f32, y: f32, left: f32, top: f32, side: f32, radius: f32) -> bool {
        if !(left..left + side).contains(&x) || !(top..top + side).contains(&y) {
            return false;
        }
        let (cx, cy) = (x.clamp(left + radius, left + side - radius), y.clamp(top + radius, top + side - radius));
        (x - cx).powi(2) + (y - cy).powi(2) <= radius * radius + 1e-6
    }

    /// Whether the point (in modules from the code's corner) is dark, drawn
    /// like the apps do; the logo is a teal ring around a dark disk with a
    /// light keyhole.
    fn ink(art: &QrArt, x: f32, y: f32) -> u8 {
        let center = art.size as f32 / 2.0;
        let d = ((x - center).powi(2) + (y - center).powi(2)).sqrt();
        if d < art.logo_radius + 0.75 {
            let r = art.logo_radius * 0.82;
            return if d > r { 255 } else if d > r * 0.7 { 150 } else if (x - center).abs() < r * 0.15 && y < center + r * 0.35 { 240 } else { 25 };
        }
        let [outer, hole, stone] = art.finder_corners;
        for &[fx, fy] in &art.finders {
            let (fx, fy) = (fx as f32, fy as f32);
            if rounded_rect(x, y, fx, fy, 7.0, outer) {
                let ring = !rounded_rect(x, y, fx + 1.0, fy + 1.0, 5.0, hole);
                return if ring || rounded_rect(x, y, fx + 2.0, fy + 2.0, 3.0, stone) { 15 } else { 255 };
            }
        }
        let [outer, hole] = art.alignment_corners;
        for &[ax, ay] in &art.alignments {
            let (cx, cy) = (ax as f32 + 0.5, ay as f32 + 0.5);
            if rounded_rect(x, y, cx - 2.5, cy - 2.5, 5.0, outer) {
                let ring = !rounded_rect(x, y, cx - 1.5, cy - 1.5, 3.0, hole);
                return if ring || (x - cx).powi(2) + (y - cy).powi(2) <= art.dot_radius.powi(2) { 15 } else { 255 };
            }
        }
        if x < 0.0 || y < 0.0 || x >= art.size as f32 || y >= art.size as f32 {
            return 255;
        }
        let (mx, my) = (x as usize, y as usize);
        match art.modules[my].as_bytes()[mx] {
            b'2' => 15,
            b'1' if (x - mx as f32 - 0.5).powi(2) + (y - my as f32 - 0.5).powi(2) <= art.dot_radius.powi(2) => 15,
            _ => 255,
        }
    }

    /// The code as a screen or camera shows it: `scale` pixels per module,
    /// smoothed edges (3×3 samples per pixel), a quiet zone of 4 modules,
    /// inside a dark frame `margin` pixels wide (the app around it).
    fn picture(art: &QrArt, scale: f32, margin: usize) -> (Vec<u8>, usize) {
        let card = ((art.size as f32 + 8.0) * scale).round() as usize;
        let side = card + 2 * margin;
        let mut pixels = vec![30u8; side * side];
        for py in 0..card {
            for px in 0..card {
                let mut sum = 0u32;
                for sy in 0..3 {
                    for sx in 0..3 {
                        let x = (px as f32 + (sx as f32 + 0.5) / 3.0) / scale - 4.0;
                        let y = (py as f32 + (sy as f32 + 0.5) / 3.0) / scale - 4.0;
                        sum += ink(art, x, y) as u32;
                    }
                }
                pixels[(py + margin) * side + px + margin] = (sum / 9) as u8;
            }
        }
        (pixels, side)
    }

    fn read(pixels: &[u8], side: usize) -> Vec<String> {
        decode_grey(pixels, side, side, side)
    }

    #[test]
    fn reads_back_at_many_sizes() {
        // On its own, rqrr misses codes at some sizes (plain ones too); read
        // again at other sizes, every one of these reads.
        for scale in [3.6, 3.9, 4.1, 4.3, 4.6, 4.8, 5.1, 5.3, 5.6, 6.0, 6.5, 7.0, 7.7, 8.5] {
            for seed in 0..5 {
                let link = sign_in_link(seed);
                let (pixels, side) = picture(&art(&link).unwrap(), scale, 40);
                assert_eq!(read(&pixels, side), vec![link], "at {scale} px per module");
            }
        }
    }

    #[test]
    fn setup_codes_read_back_too() {
        let link = "keyless://setup#v=1&e=someone.with.a.long.address%40example.com&k=K1-ABCDEF-GHJKMN-PQRST-VWXYZ-01234-5";
        let art = art(link).unwrap();
        let (pixels, side) = picture(&art, 6.0, 30);
        assert_eq!(read(&pixels, side), vec![link.to_string()]);
    }

    #[test]
    fn shapes() {
        let art = art(SIGN_IN).unwrap();
        assert_eq!(art.modules.len(), art.size);
        assert!(art.modules.iter().all(|row| row.len() == art.size));
        assert_eq!(art.finders, vec![[0, 0], [art.size - 7, 0], [0, art.size - 7]]);
        // Nothing drawn under the logo or inside a finder pattern.
        let c = art.size / 2;
        assert_eq!(art.modules[c].as_bytes()[c], b'0');
        assert!(art.modules[..7].iter().all(|row| row.as_bytes()[..7].iter().all(|&b| b == b'0')));
        // The timing pattern (row 6, between the finders) is squares.
        let in_alignment = |x: usize, y: usize| art.alignments.iter().any(|&[ax, ay]| x.abs_diff(ax) <= 2 && y.abs_diff(ay) <= 2);
        assert!((8..art.size - 8).step_by(2).all(|x| art.modules[6].as_bytes()[x] == b'2' || in_alignment(x, 6)));
        assert!(art.modules.iter().any(|row| row.contains('1')));
        // The bottom-right alignment pattern (the one readers use) is there.
        assert!(art.alignments.contains(&[art.size - 7, art.size - 7]));
        assert!(art.logo_radius > 3.0);

        let small = super::art("hi").unwrap();
        assert_eq!(small.size, 21);
        assert!(small.alignments.is_empty());
    }
}

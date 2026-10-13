//! The Emergency Kit as a PDF file: the email, the Secret Key, a box to write
//! the master password in by hand, and the setup code as a QR code that also
//! links to `keyless://setup` (so opening the file in Keyless, or clicking
//! the code, fills in the sign-in form; see `device_setup`).
//!
//! A small writer of its own: one A4 page with the PDF standard fonts
//! (Helvetica and Courier, which every reader has) in WinAnsi encoding, which
//! covers the interface's languages.

use std::fmt::Write as _;

use serde::Deserialize;

const PAGE_WIDTH: f32 = 595.0;
const PAGE_HEIGHT: f32 = 842.0;
const MARGIN: f32 = 56.0;
const ACCENT: (f32, f32, f32) = (0.31, 0.27, 0.90);
const MUTED: (f32, f32, f32) = (0.40, 0.42, 0.47);
const TEXT: (f32, f32, f32) = (0.07, 0.09, 0.15);

/// The texts, translated by the interface.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KitLabels {
    pub title: String,
    /// "Created on 13 October 2026".
    pub created: String,
    pub intro: String,
    pub email: String,
    pub secret_key: String,
    pub master_password: String,
    pub write_by_hand: String,
    pub setup_code: String,
    pub setup_code_help: String,
}

/// Helvetica's widths (1/1000 em) for the printable ASCII characters.
const HELVETICA: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278,
    278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722,
    667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556,
    556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];

/// The character in WinAnsi encoding (`?` when it has none).
fn win_ansi(c: char) -> u8 {
    match c as u32 {
        0x20..=0x7E | 0xA0..=0xFF => c as u32 as u8,
        _ => match c {
            '€' => 0x80,
            '…' => 0x85,
            '‘' => 0x91,
            '’' => 0x92,
            '“' => 0x93,
            '”' => 0x94,
            '•' => 0x95,
            '–' => 0x96,
            '—' => 0x97,
            _ => b'?',
        },
    }
}

/// Width of `text` in points, in Helvetica at `size` (accented letters as
/// their base letter: close enough to wrap lines).
fn text_width(text: &str, size: f32) -> f32 {
    let units: u32 = text
        .chars()
        .map(|c| {
            let base = unicode_base(c);
            if (' '..='~').contains(&base) { HELVETICA[base as usize - 32] as u32 } else { 556 }
        })
        .sum();
    units as f32 * size / 1000.0
}

fn unicode_base(c: char) -> char {
    match c {
        'à'..='å' => 'a',
        'À'..='Å' => 'A',
        'ç' => 'c',
        'Ç' => 'C',
        'è'..='ë' => 'e',
        'È'..='Ë' => 'E',
        'ì'..='ï' => 'i',
        'Ì'..='Ï' => 'I',
        'ñ' => 'n',
        'Ñ' => 'N',
        'ò'..='ö' => 'o',
        'Ò'..='Ö' => 'O',
        'ù'..='ü' => 'u',
        'Ù'..='Ü' => 'U',
        other => other,
    }
}

/// Splits `text` into lines no wider than `width`.
fn wrap(text: &str, size: f32, width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            let candidate = if line.is_empty() { word.to_string() } else { format!("{line} {word}") };
            if text_width(&candidate, size) > width && !line.is_empty() {
                lines.push(std::mem::take(&mut line));
                line = word.to_string();
            } else {
                line = candidate;
            }
        }
        lines.push(line);
    }
    lines
}

/// A PDF literal string.
fn pdf_string(text: &str) -> Vec<u8> {
    let mut out = vec![b'('];
    for c in text.chars() {
        let byte = win_ansi(c);
        if matches!(byte, b'(' | b')' | b'\\') {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out.push(b')');
    out
}

/// The page's drawing operators.
struct Content(Vec<u8>);

impl Content {
    fn op(&mut self, text: &str) {
        self.0.extend_from_slice(text.as_bytes());
        self.0.push(b'\n');
    }

    fn color(&mut self, (r, g, b): (f32, f32, f32)) {
        self.op(&format!("{r:.3} {g:.3} {b:.3} rg {r:.3} {g:.3} {b:.3} RG"));
    }

    /// `font` is F1 (Helvetica), F2 (Helvetica-Bold) or F3 (Courier-Bold);
    /// `y` is measured from the top of the page.
    fn text(&mut self, font: &str, size: f32, x: f32, y: f32, text: &str) {
        self.op(&format!("BT /{font} {size} Tf {x:.2} {:.2} Td", PAGE_HEIGHT - y));
        self.0.extend_from_slice(&pdf_string(text));
        self.op(" Tj ET");
    }

    fn rect(&mut self, x: f32, y: f32, width: f32, height: f32, operator: &str) {
        self.op(&format!("{x:.2} {:.2} {width:.2} {height:.2} re {operator}", PAGE_HEIGHT - y - height));
    }
}

/// The kit's PDF. `setup_link` is the `keyless://setup` link the QR code
/// holds and points to.
pub fn emergency_kit(labels: &KitLabels, email: &str, secret_key: &str, setup_link: &str) -> Result<Vec<u8>, String> {
    let qr = qrcode::QrCode::new(setup_link.as_bytes()).map_err(|e| e.to_string())?;
    let width = PAGE_WIDTH - 2.0 * MARGIN;
    let mut page = Content(Vec::new());

    // Header.
    page.color(ACCENT);
    page.rect(0.0, 0.0, PAGE_WIDTH, 8.0, "f");
    page.text("F2", 11.0, MARGIN, 52.0, "Keyless");
    page.color(TEXT);
    page.text("F2", 24.0, MARGIN, 84.0, &labels.title);
    page.color(MUTED);
    page.text("F1", 10.0, MARGIN, 102.0, &labels.created);

    let mut y = 134.0;
    page.color(TEXT);
    for line in wrap(&labels.intro, 10.5, width) {
        page.text("F1", 10.5, MARGIN, y, &line);
        y += 15.0;
    }

    let label = |page: &mut Content, y: f32, text: &str| {
        page.color(MUTED);
        page.text("F2", 8.5, MARGIN, y, &text.to_uppercase());
        page.color(TEXT);
    };

    y += 22.0;
    label(&mut page, y, &labels.email);
    page.text("F1", 13.0, MARGIN, y + 20.0, email);

    y += 52.0;
    label(&mut page, y, &labels.secret_key);
    page.color(ACCENT);
    page.op("[4 3] 0 d 1.2 w");
    page.rect(MARGIN, y + 8.0, width, 34.0, "S");
    page.op("[] 0 d");
    page.color(TEXT);
    // Courier: every character is 0.6 em wide.
    let key_size = 15.0;
    let key_width = secret_key.chars().count() as f32 * 0.6 * key_size;
    page.text("F3", key_size, MARGIN + (width - key_width) / 2.0, y + 30.0, secret_key);

    y += 66.0;
    label(&mut page, y, &labels.master_password);
    page.color(MUTED);
    page.op("0.8 w");
    page.rect(MARGIN, y + 8.0, width, 30.0, "S");
    page.text("F1", 8.5, MARGIN, y + 52.0, &labels.write_by_hand);

    // Setup code.
    y += 82.0;
    label(&mut page, y, &labels.setup_code);
    let size = 150.0;
    let modules = qr.width();
    let quiet = 2;
    let cell = size / (modules + 2 * quiet) as f32;
    let (qr_x, qr_y) = (MARGIN, y + 10.0);
    page.op("0 0 0 rg");
    let colors = qr.to_colors();
    for row in 0..modules {
        let mut col = 0;
        while col < modules {
            if colors[row * modules + col] == qrcode::Color::Dark {
                let start = col;
                while col < modules && colors[row * modules + col] == qrcode::Color::Dark {
                    col += 1;
                }
                let x = qr_x + (start + quiet) as f32 * cell;
                let top = qr_y + (row + quiet) as f32 * cell;
                page.rect(x, top, (col - start) as f32 * cell, cell, "f");
            } else {
                col += 1;
            }
        }
    }
    page.color(TEXT);
    let help_x = MARGIN + size + 18.0;
    let mut help_y = qr_y + 22.0;
    for line in wrap(&labels.setup_code_help, 10.0, width - size - 18.0) {
        page.text("F1", 10.0, help_x, help_y, &line);
        help_y += 14.0;
    }

    let link_rect = [qr_x, PAGE_HEIGHT - qr_y - size, qr_x + size, PAGE_HEIGHT - qr_y];
    Ok(assemble(&page.0, link_rect, setup_link, &labels.title))
}

/// The file around the page: catalog, page, fonts, link and document info.
fn assemble(content: &[u8], link_rect: [f32; 4], link: &str, title: &str) -> Vec<u8> {
    let mut objects: Vec<Vec<u8>> = Vec::new();
    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    objects.push(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec());
    objects.push(
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >> >> /Contents 7 0 R /Annots [8 0 R] >>"
        )
        .into_bytes(),
    );
    for font in ["Helvetica", "Helvetica-Bold", "Courier-Bold"] {
        objects.push(format!("<< /Type /Font /Subtype /Type1 /BaseFont /{font} /Encoding /WinAnsiEncoding >>").into_bytes());
    }
    let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
    stream.extend_from_slice(content);
    stream.extend_from_slice(b"\nendstream");
    objects.push(stream);
    let mut annot = format!(
        "<< /Type /Annot /Subtype /Link /Rect [{:.2} {:.2} {:.2} {:.2}] /Border [0 0 0] /A << /S /URI /URI ",
        link_rect[0], link_rect[1], link_rect[2], link_rect[3]
    )
    .into_bytes();
    annot.extend_from_slice(&pdf_string(link));
    annot.extend_from_slice(b" >> >>");
    objects.push(annot);
    let mut info = b"<< /Producer (Keyless) /Title ".to_vec();
    info.extend_from_slice(&pdf_string(title));
    info.extend_from_slice(b" >>");
    objects.push(info);

    let mut out = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::new();
    for (i, object) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(object);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    let mut table = format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1);
    for offset in offsets {
        let _ = writeln!(table, "{offset:010} 00000 n ");
    }
    out.extend_from_slice(table.as_bytes());
    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R /Info {} 0 R >>\nstartxref\n{xref}\n%%EOF\n", objects.len() + 1, objects.len()).as_bytes(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyless_core::{keys::SecretKey, setup_code};

    #[test]
    fn writes_a_kit_that_holds_the_setup_link() {
        let key = SecretKey::generate().unwrap();
        let link = setup_code::setup_link("me@example.com", &key);
        let labels = KitLabels {
            title: "Kit de Emergência".into(),
            created: "Criado em 13 de outubro de 2026".into(),
            intro: "Guarde este documento (impresso ou num lugar seguro). ".repeat(6),
            email: "E-mail".into(),
            secret_key: "Chave Secreta".into(),
            master_password: "Senha mestra".into(),
            write_by_hand: "Escreva à mão (nunca a guarde no computador).".into(),
            setup_code: "Código de configuração".into(),
            setup_code_help: "Leia este código com o Keyless num dispositivo novo, ou abra este arquivo nele.".into(),
        };
        let pdf = emergency_kit(&labels, "me@example.com", &key.to_display(), &link).unwrap();
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert_eq!(setup_code::find_setup_link(&pdf).unwrap().as_str(), link.as_str());
        // WinAnsi: "ê" is one byte.
        let title = b"(Kit de Emerg\xEAncia)";
        assert!(pdf.windows(title.len()).any(|w| w == title));
        // The cross-reference table points at each object.
        let xref = pdf.windows(5).rposition(|w| w == b"xref\n").unwrap();
        let table = std::str::from_utf8(&pdf[xref..]).unwrap();
        for (i, line) in table.lines().skip(3).take(9).enumerate() {
            let offset: usize = line[..10].parse().unwrap();
            assert!(pdf[offset..].starts_with(format!("{} 0 obj", i + 1).as_bytes()), "object {}", i + 1);
        }
        if let Ok(dir) = std::env::var("KEYLESS_KIT_PDF_DIR") {
            std::fs::write(std::path::Path::new(&dir).join("kit.pdf"), &pdf).unwrap();
        }
    }

    #[test]
    fn wraps_and_escapes() {
        assert_eq!(wrap("a b c", 10.0, 1000.0), vec!["a b c"]);
        assert!(wrap(&"palavra ".repeat(40), 10.0, 200.0).len() > 5);
        assert_eq!(pdf_string("a(b)\\ç"), b"(a\\(b\\)\\\\\xE7)".to_vec());
        assert_eq!(win_ansi('漢'), b'?');
    }
}

//! A wireless router item as a Wi-Fi QR code, which phones read to join
//! the network ("WIFI:S:<name>;T:<security>;P:<password>;;").

use zeroize::Zeroizing;

use crate::{Error, Result, item::ItemDetails};

/// What the item's QR code holds: its network name, password and security,
/// found by their field labels (as saved in any of the apps' languages).
pub fn payload(details: &ItemDetails) -> Result<Zeroizing<String>> {
    let by_label = |names: &[&str]| {
        details
            .all_fields()
            .find(|f| names.iter().any(|n| f.label.eq_ignore_ascii_case(n)))
            .map(|f| f.value.clone())
            .unwrap_or_default()
    };
    let name = by_label(&["network name", "ssid", "nome da rede", "nombre de la red"]);
    if name.is_empty() {
        return Err(Error::Serialization("no network name".into()));
    }
    let password = Zeroizing::new(details.password().map(String::from).unwrap_or_else(|| by_label(&["wireless password"])));
    let security = by_label(&["security", "segurança", "seguridad"]);
    Ok(escaped_payload(&name, &password, &security))
}

/// What a Wi-Fi QR code holds; `;`, `,`, `:`, `\` and `"` are escaped.
fn escaped_payload(name: &str, password: &str, security: &str) -> Zeroizing<String> {
    let kind = if password.is_empty() {
        "nopass"
    } else if security.to_uppercase().contains("WEP") {
        "WEP"
    } else {
        "WPA"
    };
    let mut payload = Zeroizing::new(String::from("WIFI:S:"));
    let push_escaped = |out: &mut String, text: &str| {
        for c in text.chars() {
            if matches!(c, '\\' | ';' | ',' | ':' | '"') {
                out.push('\\');
            }
            out.push(c);
        }
    };
    push_escaped(&mut payload, name);
    payload.push_str(";T:");
    payload.push_str(kind);
    payload.push_str(";P:");
    push_escaped(&mut payload, password);
    payload.push_str(";;");
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_codes_escape_their_text() {
        assert_eq!(escaped_payload("Casa;1", r"a:b\c", "WPA2").as_str(), r"WIFI:S:Casa\;1;T:WPA;P:a\:b\\c;;");
        assert_eq!(escaped_payload("Guest", "", "").as_str(), "WIFI:S:Guest;T:nopass;P:;;");
        assert_eq!(escaped_payload("Old", "k", "wep").as_str(), "WIFI:S:Old;T:WEP;P:k;;");
    }
}

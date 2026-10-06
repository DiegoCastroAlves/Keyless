//! Base32 encodings: Crockford (human-typed Secret Keys) and RFC 4648 (TOTP
//! secrets).

use zeroize::Zeroizing;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RFC4648: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes bytes as Crockford base32 without padding (most significant bit
/// first). The last symbol is zero-padded on the right.
pub fn crockford_encode(data: &[u8]) -> Zeroizing<String> {
    encode(data, CROCKFORD)
}

/// Decodes Crockford base32, accepting the usual human typos: lowercase,
/// `O` for `0` and `I`/`L` for `1`. Returns `None` on invalid symbols or when
/// the padding bits are not zero.
pub fn crockford_decode(input: &str, byte_len: usize) -> Option<Zeroizing<Vec<u8>>> {
    let values = Zeroizing::new(
        input
            .chars()
            .map(|c| {
                let c = match c.to_ascii_uppercase() {
                    'O' => '0',
                    'I' | 'L' => '1',
                    other => other,
                };
                CROCKFORD.iter().position(|&s| s as char == c).map(|p| p as u8)
            })
            .collect::<Option<Vec<u8>>>()?,
    );
    decode_values(&values, byte_len)
}

/// Decodes RFC 4648 base32 (case-insensitive, padding and spaces ignored).
pub fn rfc4648_decode(input: &str) -> Option<Zeroizing<Vec<u8>>> {
    let values = Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
            .map(|c| {
                let c = c.to_ascii_uppercase();
                RFC4648.iter().position(|&s| s as char == c).map(|p| p as u8)
            })
            .collect::<Option<Vec<u8>>>()?,
    );
    let byte_len = values.len() * 5 / 8;
    decode_values_lenient(&values, byte_len)
}

fn encode(data: &[u8], alphabet: &[u8; 32]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(data.len().div_ceil(5) * 8));
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alphabet[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(alphabet[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn decode_values(values: &[u8], byte_len: usize) -> Option<Zeroizing<Vec<u8>>> {
    if values.len() != (byte_len * 8).div_ceil(5) {
        return None;
    }
    let out = decode_values_lenient(values, byte_len)?;
    // Reject non-canonical encodings (non-zero padding bits).
    let pad_bits = values.len() * 5 - byte_len * 8;
    let last = *values.last()?;
    if pad_bits > 0 && last & ((1 << pad_bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

fn decode_values_lenient(values: &[u8], byte_len: usize) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(byte_len));
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &v in values {
        buffer = (buffer << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out.len() < byte_len {
                out.push((buffer >> bits) as u8);
            }
        }
    }
    (out.len() == byte_len).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crockford_roundtrip() {
        for len in [1usize, 5, 16, 20] {
            let data: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37)).collect();
            let encoded = crockford_encode(&data);
            assert_eq!(crockford_decode(&encoded, len).unwrap().as_slice(), &data[..]);
        }
    }

    #[test]
    fn crockford_accepts_typos() {
        let data = [0u8, 1, 2, 3, 4];
        let encoded = crockford_encode(&data).to_lowercase().replace('0', "o").replace('1', "l");
        assert_eq!(crockford_decode(&encoded, 5).unwrap().as_slice(), &data);
    }

    #[test]
    fn crockford_rejects_noncanonical_padding() {
        // 1 byte = 8 bits -> 2 symbols with 2 padding bits.
        assert!(crockford_decode("01", 1).is_none());
        assert!(crockford_decode("00", 1).is_some());
        assert!(crockford_decode("0U", 1).is_none());
    }

    #[test]
    fn rfc4648_known_vector() {
        // RFC 4648 test vector: "foobar" -> "MZXW6YTBOI======"
        assert_eq!(rfc4648_decode("MZXW6YTBOI======").unwrap().as_slice(), b"foobar");
        assert_eq!(rfc4648_decode("mzxw 6ytb oi").unwrap().as_slice(), b"foobar");
        assert!(rfc4648_decode("MZXW1").is_none());
    }
}

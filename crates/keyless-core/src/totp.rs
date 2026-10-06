//! Time-based one-time passwords (RFC 6238), including Steam Guard codes.

use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::{Error, Result, encoding::rfc4648_decode};

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub steam: bool,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("steam", &self.steam)
            .finish_non_exhaustive()
    }
}

impl Totp {
    /// Accepts an `otpauth://totp/...` URI, a `steam://SECRET` URI, or a bare
    /// base32 secret.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if let Some(secret) = input.strip_prefix("steam://") {
            return Self::from_parts(secret, TotpAlgorithm::Sha1, 5, 30, None, None, true);
        }
        let Some(rest) = input.strip_prefix("otpauth://") else {
            return Self::from_parts(input, TotpAlgorithm::Sha1, 6, 30, None, None, false);
        };
        let (kind, rest) = rest
            .split_once('/')
            .ok_or_else(|| Error::InvalidTotp("malformed URI".into()))?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(Error::InvalidTotp("only time-based codes (TOTP) are supported".into()));
        }
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label);
        let (label_issuer, account) = match label.split_once(':') {
            Some((issuer, account)) => (Some(issuer.trim().to_string()), Some(account.trim().to_string())),
            None if label.is_empty() => (None, None),
            None => (None, Some(label.trim().to_string())),
        };

        let mut secret = None;
        let mut issuer = label_issuer;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        let mut steam = false;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value);
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(Zeroizing::new(value)),
                "issuer" if !value.is_empty() => issuer = Some(value),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        other => return Err(Error::InvalidTotp(format!("unknown algorithm {other}"))),
                    }
                }
                "digits" => {
                    digits = value
                        .parse()
                        .map_err(|_| Error::InvalidTotp("invalid digits".into()))?
                }
                "period" => {
                    period = value
                        .parse()
                        .map_err(|_| Error::InvalidTotp("invalid period".into()))?
                }
                "encoder" if value.eq_ignore_ascii_case("steam") => steam = true,
                _ => {}
            }
        }
        if issuer.as_deref().is_some_and(|i| i.eq_ignore_ascii_case("steam")) && digits == 5 {
            steam = true;
        }
        if steam {
            digits = 5;
        }
        let secret = secret.ok_or_else(|| Error::InvalidTotp("missing secret".into()))?;
        Self::from_parts(&secret, algorithm, digits, period, issuer, account, steam)
    }

    fn from_parts(
        secret: &str,
        algorithm: TotpAlgorithm,
        digits: u32,
        period: u64,
        issuer: Option<String>,
        account: Option<String>,
        steam: bool,
    ) -> Result<Self> {
        let secret = rfc4648_decode(secret).ok_or_else(|| Error::InvalidTotp("the secret is not valid base32".into()))?;
        if secret.is_empty() {
            return Err(Error::InvalidTotp("empty secret".into()));
        }
        if !(steam || (6..=10).contains(&digits)) {
            return Err(Error::InvalidTotp("digits must be between 6 and 10".into()));
        }
        if !(1..=300).contains(&period) {
            return Err(Error::InvalidTotp("period must be between 1 and 300 seconds".into()));
        }
        Ok(Self { secret, algorithm, digits, period, issuer, account, steam })
    }

    /// The code valid at `unix_time` (seconds).
    pub fn code_at(&self, unix_time: u64) -> Zeroizing<String> {
        let counter = (unix_time / self.period).to_be_bytes();
        let digest = Zeroizing::new(match self.algorithm {
            TotpAlgorithm::Sha1 => hmac::<Hmac<Sha1>>(&self.secret, &counter),
            TotpAlgorithm::Sha256 => hmac::<Hmac<Sha256>>(&self.secret, &counter),
            TotpAlgorithm::Sha512 => hmac::<Hmac<Sha512>>(&self.secret, &counter),
        });
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let mut value = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);

        if self.steam {
            let mut code = Zeroizing::new(String::with_capacity(5));
            for _ in 0..5 {
                code.push(STEAM_ALPHABET[(value as usize) % STEAM_ALPHABET.len()] as char);
                value /= STEAM_ALPHABET.len() as u32;
            }
            return code;
        }
        let modulus = 10u64.pow(self.digits);
        Zeroizing::new(format!("{:0width$}", value as u64 % modulus, width = self.digits as usize))
    }

    /// Seconds until the code at `unix_time` expires.
    pub fn seconds_remaining(&self, unix_time: u64) -> u64 {
        self.period - unix_time % self.period
    }
}

fn hmac<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base32(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::new();
        let (mut buffer, mut bits) = (0u32, 0);
        for &b in data {
            buffer = (buffer << 8) | b as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    #[test]
    fn rfc6238_vectors() {
        let sha1 = base32(b"12345678901234567890");
        let sha256 = base32(b"12345678901234567890123456789012");
        let sha512 = base32(b"1234567890123456789012345678901234567890123456789012345678901234");
        let cases: &[(&str, &str, u64, &str)] = &[
            (&sha1, "SHA1", 59, "94287082"),
            (&sha1, "SHA1", 1111111109, "07081804"),
            (&sha1, "SHA1", 1234567890, "89005924"),
            (&sha1, "SHA1", 20000000000, "65353130"),
            (&sha256, "SHA256", 59, "46119246"),
            (&sha256, "SHA256", 1111111111, "67062674"),
            (&sha512, "SHA512", 59, "90693936"),
            (&sha512, "SHA512", 2000000000, "38618901"),
        ];
        for (secret, alg, time, expected) in cases {
            let uri = format!("otpauth://totp/Test?secret={secret}&algorithm={alg}&digits=8");
            let totp = Totp::parse(&uri).unwrap();
            assert_eq!(totp.code_at(*time).as_str(), *expected, "{alg} at {time}");
        }
    }

    #[test]
    fn parses_label_and_issuer() {
        let totp = Totp::parse("otpauth://totp/ACME%20Co:john.doe%40email.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&period=60").unwrap();
        assert_eq!(totp.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(totp.account.as_deref(), Some("john.doe@email.com"));
        assert_eq!(totp.period, 60);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.code_at(0).len(), 6);
        assert_eq!(totp.seconds_remaining(61), 59);
    }

    #[test]
    fn bare_secret_and_steam() {
        assert_eq!(Totp::parse("jbsw y3dp ehpk 3pxp").unwrap().code_at(0).len(), 6);
        let steam = Totp::parse("steam://JBSWY3DPEHPK3PXP").unwrap();
        let code = steam.code_at(1_700_000_000);
        assert_eq!(code.len(), 5);
        assert!(code.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x",
            "otpauth://totp/x?secret=!!!",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=2",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        ] {
            assert!(Totp::parse(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn percent_decoding_is_safe() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%4"), "%4");
    }
}

//! End-to-end encryption between the browser extension and the app.
//!
//! Each side has a static X25519 key pair. After pairing (the user confirms
//! the same code in the app and in the extension) both derive:
//!
//! ```text
//! shared = X25519(own private, peer public)
//! key    = HKDF-SHA256(ikm = shared, salt = "keyless/bridge/v1", info = ext_pub || app_pub)[32]
//! ```
//!
//! Messages are AES-256-GCM with a random 96-bit nonce and the direction as
//! associated data, so a message cannot be reflected back to its sender. The
//! extension uses the same construction through WebCrypto.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const TO_APP: &[u8] = b"keyless-bridge-v1:to-app";
pub const TO_EXTENSION: &[u8] = b"keyless-bridge-v1:to-extension";

pub fn decode_public_key(encoded: &str) -> Option<PublicKey> {
    let bytes = STANDARD.decode(encoded).ok()?;
    let array: [u8; 32] = bytes.try_into().ok()?;
    Some(PublicKey::from(array))
}

pub fn encode_public_key(key: &PublicKey) -> String {
    STANDARD.encode(key.as_bytes())
}

pub struct Channel {
    cipher: Aes256Gcm,
}

impl Channel {
    pub fn new(app_secret: &StaticSecret, app_public: &PublicKey, extension_public: &PublicKey) -> Option<Self> {
        let shared = app_secret.diffie_hellman(extension_public);
        if !shared.was_contributory() {
            return None;
        }
        let mut info = Vec::with_capacity(64);
        info.extend_from_slice(extension_public.as_bytes());
        info.extend_from_slice(app_public.as_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(b"keyless/bridge/v1"), shared.as_bytes())
            .expand(&info, key.as_mut())
            .ok()?;
        Some(Self { cipher: Aes256Gcm::new_from_slice(key.as_ref()).ok()? })
    }

    pub fn open(&self, nonce: &str, ciphertext: &str) -> Option<Zeroizing<Vec<u8>>> {
        let nonce = STANDARD.decode(nonce).ok()?;
        let nonce = Nonce::try_from(nonce.as_slice()).ok()?;
        let ciphertext = STANDARD.decode(ciphertext).ok()?;
        self.cipher
            .decrypt(&nonce, Payload { msg: &ciphertext, aad: TO_APP })
            .ok()
            .map(Zeroizing::new)
    }

    pub fn seal(&self, plaintext: &[u8]) -> Option<(String, String)> {
        let mut nonce = [0u8; 12];
        keyless_core::crypto::random_bytes(&mut nonce).ok()?;
        let ciphertext = self
            .cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad: TO_EXTENSION })
            .ok()?;
        Some((STANDARD.encode(nonce), STANDARD.encode(ciphertext)))
    }
}

/// Short code both sides display during pairing: 8 digits from
/// SHA-256(ext_pub || app_pub).
pub fn pairing_code(extension_public: &PublicKey, app_public: &PublicKey) -> String {
    let digest = Sha256::new()
        .chain_update(b"keyless/bridge/v1/pairing")
        .chain_update(extension_public.as_bytes())
        .chain_update(app_public.as_bytes())
        .finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 100_000_000;
    format!("{:04}-{:04}", n / 10_000, n % 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_roundtrip_and_direction_binding() {
        let app = StaticSecret::from([1u8; 32]);
        let app_pub = PublicKey::from(&app);
        let ext = StaticSecret::from([2u8; 32]);
        let ext_pub = PublicKey::from(&ext);
        let channel = Channel::new(&app, &app_pub, &ext_pub).unwrap();

        // A message sealed by the app cannot be opened as if it came from the
        // extension (reflection).
        let (nonce, ct) = channel.seal(b"hello").unwrap();
        assert!(channel.open(&nonce, &ct).is_none());

        // Simulate the extension sealing with the to-app label.
        let mut info = ext_pub.as_bytes().to_vec();
        info.extend_from_slice(app_pub.as_bytes());
        let shared = ext.diffie_hellman(&app_pub);
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"keyless/bridge/v1"), shared.as_bytes()).expand(&info, &mut key).unwrap();
        let ext_cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = [9u8; 12];
        let ct = ext_cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: b"ping", aad: TO_APP })
            .unwrap();
        let opened = channel.open(&STANDARD.encode(nonce), &STANDARD.encode(ct)).unwrap();
        assert_eq!(opened.as_slice(), b"ping");
    }

    #[test]
    fn pairing_code_shape() {
        let a = PublicKey::from(&StaticSecret::from([3u8; 32]));
        let b = PublicKey::from(&StaticSecret::from([4u8; 32]));
        let code = pairing_code(&a, &b);
        assert_eq!(code.len(), 9);
        assert_ne!(code, pairing_code(&b, &a));
    }
}

//! Opening other password managers' encrypted export files: the primitives
//! their formats use (Bitwarden's password-protected JSON, KeePass's KDBX).
//! Keyless itself encrypts with XChaCha20-Poly1305 (see `crypto`); these are
//! only for reading what other apps wrote.

use aes::{
    Aes256,
    cipher::{BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher, block_padding::Pkcs7},
};
use cbc::cipher::BlockModeDecrypt;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

/// PBKDF2 with HMAC-SHA-256 (RFC 8018), one 32-byte block.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let prf = Hmac::<Sha256>::new_from_slice(password).expect("HMAC takes keys of any length");
    let mut block = prf.clone();
    block.update(salt);
    block.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = block.finalize().into_bytes().into();
    let mut out = Zeroizing::new(u);
    for _ in 1..iterations.max(1) {
        let mut next = prf.clone();
        next.update(&u);
        u = next.finalize().into_bytes().into();
        for (o, b) in out.iter_mut().zip(u.iter()) {
            *o ^= b;
        }
    }
    u.zeroize();
    out
}

/// AES-256-CBC with PKCS#7 padding. The formats authenticate the data
/// themselves (an HMAC, checked before this runs); a padding error means a
/// wrong key.
pub fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = cbc::Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| Error::InvalidKey)?;
    cipher.decrypt_padded_vec::<Pkcs7>(data).map(Zeroizing::new).map_err(|_| Error::Decryption)
}

/// KeePass's AES-KDF: the 32-byte key encrypted `rounds` times with
/// AES-256-ECB under `seed`.
pub fn aes_kdf(key: &[u8; 32], seed: &[u8], rounds: u64) -> Result<Zeroizing<[u8; 32]>> {
    let cipher = Aes256::new_from_slice(seed).map_err(|_| Error::InvalidKey)?;
    let mut out = Zeroizing::new(*key);
    let (first, second) = out.split_at_mut(16);
    let (first, second): (&mut [u8; 16], &mut [u8; 16]) = (first.try_into().expect("16 bytes"), second.try_into().expect("16 bytes"));
    for _ in 0..rounds {
        cipher.encrypt_block(first.into());
        cipher.encrypt_block(second.into());
    }
    Ok(out)
}

/// XORs `data` with ChaCha20's key stream (the IETF variant, 96-bit nonce).
pub fn chacha20_xor(key: &[u8], nonce: &[u8], data: &mut [u8]) -> Result<()> {
    let mut cipher = chacha20::ChaCha20::new_from_slices(key, nonce).map_err(|_| Error::InvalidKey)?;
    cipher.apply_keystream(data);
    Ok(())
}

/// Salsa20/20 (64-bit nonce), for the protected values of older KeePass
/// files: a key stream applied value after value, in file order.
pub struct Salsa20 {
    state: [u32; 16],
    block: [u8; 64],
    used: usize,
}

impl Salsa20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 8]) -> Self {
        let word = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        // "expand 32-byte k"
        let sigma = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
        let mut state = [0u32; 16];
        state[0] = sigma[0];
        for i in 0..4 {
            state[1 + i] = word(&key[i * 4..]);
            state[11 + i] = word(&key[16 + i * 4..]);
        }
        state[5] = sigma[1];
        state[6] = word(&nonce[0..]);
        state[7] = word(&nonce[4..]);
        state[10] = sigma[2];
        state[15] = sigma[3];
        Self { state, block: [0; 64], used: 64 }
    }

    fn next_block(&mut self) {
        let mut x = self.state;
        let quarter = |x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize| {
            x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
            x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
            x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
            x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
        };
        for _ in 0..10 {
            // Columns, then rows.
            quarter(&mut x, 0, 4, 8, 12);
            quarter(&mut x, 5, 9, 13, 1);
            quarter(&mut x, 10, 14, 2, 6);
            quarter(&mut x, 15, 3, 7, 11);
            quarter(&mut x, 0, 1, 2, 3);
            quarter(&mut x, 5, 6, 7, 4);
            quarter(&mut x, 10, 11, 8, 9);
            quarter(&mut x, 15, 12, 13, 14);
        }
        for (i, word) in x.iter().enumerate() {
            self.block[i * 4..i * 4 + 4].copy_from_slice(&word.wrapping_add(self.state[i]).to_le_bytes());
        }
        // The block counter (words 8 and 9).
        self.state[8] = self.state[8].wrapping_add(1);
        if self.state[8] == 0 {
            self.state[9] = self.state[9].wrapping_add(1);
        }
        x.zeroize();
        self.used = 0;
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.used == 64 {
                self.next_block();
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
    }
}

impl Drop for Salsa20 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.block.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn pbkdf2_matches_rfc_7914() {
        // RFC 7914 §11, PBKDF2-HMAC-SHA256("passwd", "salt", 1), first 32 bytes.
        let out = pbkdf2_sha256(b"passwd", b"salt", 1);
        assert_eq!(out.as_slice(), hex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc").as_slice());
    }

    #[test]
    fn salsa20_matches_the_reference() {
        // Salsa20 test vector (eSTREAM, 256-bit key, set 1, vector 0):
        // key 80 00..00, nonce 0, first 16 bytes of the key stream.
        let mut key = [0u8; 32];
        key[0] = 0x80;
        let mut stream = [0u8; 16];
        Salsa20::new(&key, &[0; 8]).apply(&mut stream);
        assert_eq!(stream.as_slice(), hex("e3be8fdd8beca2e3ea8ef9475b29a6e7").as_slice());
    }

    #[test]
    fn aes_cbc_round_trip() {
        use cbc::cipher::BlockModeEncrypt;
        let (key, iv) = ([7u8; 32], [9u8; 16]);
        let data = b"exported by another password manager".to_vec();
        let sealed = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv).unwrap().encrypt_padded_vec::<Pkcs7>(&data);
        assert_eq!(aes256_cbc_decrypt(&key, &iv, &sealed).unwrap().as_slice(), data.as_slice());
        assert!(aes256_cbc_decrypt(&[8u8; 32], &iv, &sealed).is_err());
    }
}

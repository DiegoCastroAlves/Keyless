//! Signing in on a new device by scanning the QR code it shows with a phone
//! already signed in: nothing to type but the master password.
//!
//! The new device shows a `keyless://sign-in` link as a QR code: a request
//! id, an X25519 public key and a random token. The phone that reads it
//! seals the account's email and Secret Key for that key, bound to the token,
//! and leaves them on the server under the request id:
//!
//! ```text
//! new device                                    signed-in device
//!   a, A = X25519;  T = 16 random bytes
//!   QR code: keyless://sign-in#id=…&key=A&token=T
//!                   ===== camera =====>
//!                                               b, B = X25519
//!   key = HKDF(X25519(a, B) = X25519(b, A), salt = "keyless/v1/qr-sign-in", info = A | B | T)
//!                   <--- B, seal(key, {email, Secret Key}, "qr-sign-in" | id) --- (server)
//! ```
//!
//! A and T travel only through the camera, so the server, which sees the
//! request id, B and the sealed payload, can neither read the payload nor
//! put one of its own in its place. Whoever else sees the QR code can at most
//! send the new device another account (whose email the new device shows)
//! or refuse the request; the new device polls with a secret that is not in
//! the code. What the phone sends is what an Emergency Kit holds: the master
//! password is still typed on the new device.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::{SymmetricKey, context, random_array},
    device_setup::SetupPayload,
};

const SCHEME: &str = "keyless://sign-in";
const TOKEN_LEN: usize = 16;
/// Longest link accepted (a real one is about 130 characters).
const MAX_LEN: usize = 256;

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|bytes| <[u8; N]>::try_from(bytes.as_slice()).ok())
        .ok_or(Error::InvalidKey)
}

fn derive(secret: &StaticSecret, peer: &[u8; 32], requester: &[u8; 32], approver: &[u8; 32], token: &[u8; TOKEN_LEN]) -> Result<SymmetricKey> {
    let shared = secret.diffie_hellman(&PublicKey::from(*peer));
    // A low-order public key would make the shared secret predictable.
    if !shared.was_contributory() {
        return Err(Error::InvalidKey);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(b"keyless/v1/qr-sign-in"), shared.as_bytes())
        .expand(&[requester.as_slice(), approver, token].concat(), key.as_mut())
        .map_err(|_| Error::Kdf)?;
    SymmetricKey::from_slice(key.as_ref())
}

fn payload_context(request_id: &str) -> Vec<u8> {
    context("qr-sign-in", &[request_id])
}

/// The new device's side: the QR code to show, and what the phone sent.
pub struct SignInRequest {
    id: String,
    secret: StaticSecret,
    public: [u8; 32],
    token: Zeroizing<[u8; TOKEN_LEN]>,
    poll_secret: Zeroizing<String>,
}

impl SignInRequest {
    pub fn new() -> Result<Self> {
        let secret = StaticSecret::from(*random_array::<32>()?);
        let public = PublicKey::from(&secret).to_bytes();
        let id = uuid::Builder::from_random_bytes(*random_array::<16>()?).into_uuid().to_string();
        Ok(Self { id, secret, public, token: random_array()?, poll_secret: Zeroizing::new(encode(random_array::<32>()?.as_ref())) })
    }

    /// The request's id, for the server.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// What the new device asks the server with (base64url): never in the
    /// QR code, so seeing the code is not enough to take the answer.
    pub fn poll_secret(&self) -> &str {
        &self.poll_secret
    }

    /// The link the QR code holds.
    pub fn link(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{SCHEME}#id={}&key={}&token={}", self.id, encode(&self.public), encode(self.token.as_ref())))
    }

    /// Opens what the phone sent: its public key and the sealed payload.
    pub fn open(&self, approver_key: &str, envelope: &str) -> Result<SetupPayload> {
        let approver = decode::<32>(approver_key.trim())?;
        let key = derive(&self.secret, &approver, &self.public, &approver, &self.token)?;
        let bytes = key.open(envelope, &payload_context(&self.id))?;
        serde_json::from_slice(&bytes).map_err(Error::from)
    }
}

/// Whether `text` is (or starts like) a sign-in link.
pub fn is_sign_in_link(text: &str) -> bool {
    text.trim().get(..SCHEME.len()).is_some_and(|head| head.eq_ignore_ascii_case(SCHEME))
}

/// A sign-in link read by the signed-in device.
pub struct SignInLink {
    id: String,
    requester: [u8; 32],
    token: Zeroizing<[u8; TOKEN_LEN]>,
}

impl SignInLink {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        if text.len() > MAX_LEN || !is_sign_in_link(text) {
            return Err(Error::InvalidKey);
        }
        let fragment = text.split_once('#').map(|(_, f)| f).ok_or(Error::InvalidKey)?;
        let (mut id, mut requester, mut token) = (None, None, None);
        for pair in fragment.split('&') {
            match pair.split_once('=') {
                Some(("id", value)) => id = uuid::Uuid::parse_str(value).ok().map(|u| u.to_string()),
                Some(("key", value)) => requester = Some(decode::<32>(value)?),
                Some(("token", value)) => token = Some(Zeroizing::new(decode::<TOKEN_LEN>(value)?)),
                _ => {}
            }
        }
        match (id, requester, token) {
            (Some(id), Some(requester), Some(token)) => Ok(Self { id, requester, token }),
            _ => Err(Error::InvalidKey),
        }
    }

    /// The request's id, as the server knows it.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Seals `payload` for the new device: this side's public key and the
    /// envelope, both base64url, for the server to pass on.
    pub fn seal(&self, payload: &SetupPayload) -> Result<(String, String)> {
        let secret = StaticSecret::from(*random_array::<32>()?);
        let public = PublicKey::from(&secret).to_bytes();
        let key = derive(&secret, &self.requester, &self.requester, &public, &self.token)?;
        let json = Zeroizing::new(serde_json::to_vec(payload)?);
        Ok((encode(&public), key.seal(&json, &payload_context(&self.id))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> SetupPayload {
        SetupPayload { email: "me@example.com".into(), secret_key: Zeroizing::new("K1-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE".into()) }
    }

    #[test]
    fn the_phone_seals_what_the_new_device_opens() {
        let request = SignInRequest::new().unwrap();
        let link = SignInLink::parse(&request.link()).unwrap();
        assert_eq!(link.id(), request.id());
        let (approver, envelope) = link.seal(&payload()).unwrap();
        let opened = request.open(&approver, &envelope).unwrap();
        assert_eq!(opened.email, "me@example.com");
        assert_eq!(opened.secret_key.as_str(), payload().secret_key.as_str());
    }

    #[test]
    fn the_poll_secret_and_private_key_stay_out_of_the_link() {
        let request = SignInRequest::new().unwrap();
        let link = request.link();
        assert!(link.len() < MAX_LEN);
        assert!(!link.contains(request.poll_secret()));
        assert!(!link.contains(&encode(request.secret.as_bytes())));
        assert_ne!(SignInRequest::new().unwrap().id(), request.id());
    }

    #[test]
    fn without_the_token_nobody_else_can_answer() {
        // The server knows the id; even with the public key it lacks the token.
        let request = SignInRequest::new().unwrap();
        let mut forged = SignInLink::parse(&request.link()).unwrap();
        forged.token = random_array().unwrap();
        let (approver, envelope) = forged.seal(&payload()).unwrap();
        assert!(request.open(&approver, &envelope).is_err());
        // Nor can it pass a real answer on as another request's.
        let other = SignInRequest::new().unwrap();
        let (approver, envelope) = SignInLink::parse(&request.link()).unwrap().seal(&payload()).unwrap();
        assert!(other.open(&approver, &envelope).is_err());
    }

    #[test]
    fn bad_links_and_keys_are_refused() {
        let request = SignInRequest::new().unwrap();
        let link = request.link();
        assert!(is_sign_in_link(&link));
        assert!(!is_sign_in_link("keyless://setup#email=a%40b.c&key=K1"));
        assert!(SignInLink::parse(&link.replace("id=", "di=")).is_err());
        assert!(SignInLink::parse(&link.replace("token=", "token=A")).is_err());
        assert!(SignInLink::parse(&format!("{}&{}", link.as_str(), "x".repeat(MAX_LEN))).is_err());
        assert!(SignInLink::parse("keyless://sign-in").is_err());
        // A low-order key (all zeros) makes no key on either side.
        let zero = format!("{SCHEME}#id={}&key={}&token={}", request.id(), encode(&[0u8; 32]), encode(&[1u8; TOKEN_LEN]));
        assert!(matches!(SignInLink::parse(&zero).unwrap().seal(&payload()), Err(Error::InvalidKey)));
        assert!(matches!(request.open(&encode(&[0u8; 32]), "k1.x"), Err(Error::InvalidKey)));
    }
}

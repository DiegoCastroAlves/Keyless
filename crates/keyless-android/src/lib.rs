//! The Android app's client (`keyless_client`) through JNI: one native
//! method, `Native.call(method, args)`, JSON in and out. The app talks to
//! the server, keeps files and draws the screens.

use std::sync::{Mutex, OnceLock};

use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JString},
    sys::{jint, jstring},
};
use keyless_client::Client;

fn client() -> &'static Mutex<Client> {
    static CLIENT: OnceLock<Mutex<Client>> = OnceLock::new();
    CLIENT.get_or_init(|| Mutex::new(Client::new()))
}

/// Runs a client method (see `keyless_client::Client::call`).
pub fn call(method: &str, args: &str) -> String {
    client().lock().unwrap_or_else(|e| e.into_inner()).call(method, args)
}

/// `io.github.diegocastroalves.keyless.Native.call(String, String): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_diegocastroalves_keyless_Native_call<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    method: JString<'local>,
    args: JString<'local>,
) -> jstring {
    let answer = match (env.get_string(&method), env.get_string(&args)) {
        (Ok(method), Ok(args)) => {
            let (method, args): (String, String) = (method.into(), args.into());
            call(&method, &args)
        }
        _ => r#"{"error":{"key":"invalid_request","message":"unreadable arguments"}}"#.to_string(),
    };
    env.new_string(answer).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// `io.github.diegocastroalves.keyless.Native.decodeQr(byte[], int, int, int): String`:
/// the QR codes in a greyscale frame, as a JSON array of their contents.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_diegocastroalves_keyless_Native_decodeQr<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pixels: JByteArray<'local>,
    width: jint,
    height: jint,
    stride: jint,
) -> jstring {
    let found = match env.convert_byte_array(&pixels) {
        Ok(bytes) if width > 0 && height > 0 && stride >= width => {
            keyless_client::qr::decode_grey(&bytes, width as usize, height as usize, stride as usize)
        }
        _ => Vec::new(),
    };
    let answer = serde_json::to_string(&found).unwrap_or_else(|_| "[]".into());
    env.new_string(answer).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    #[test]
    fn answers_in_json() {
        assert!(super::call("status", "").contains("\"unlocked\":false"));
        assert!(super::call("nope", "").contains("invalid_request"));
    }
}

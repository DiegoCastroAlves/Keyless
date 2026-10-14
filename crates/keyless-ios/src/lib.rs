//! The iOS app's client (`keyless_client`) through C: `keyless_call(method,
//! args)` with JSON in and out, and `keyless_free` for its answers. The app
//! talks to the server, keeps files and draws the screens.

use std::{
    ffi::{CStr, CString, c_char},
    sync::{Mutex, OnceLock},
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

/// # Safety
/// `text` is null or a NUL-terminated string valid for the call.
unsafe fn read(text: *const c_char) -> Option<String> {
    if text.is_null() {
        return None;
    }
    // SAFETY: per this function's contract.
    unsafe { CStr::from_ptr(text) }.to_str().ok().map(str::to_string)
}

/// Runs `method` with `args` (JSON); the answer must go back to `keyless_free`.
///
/// # Safety
/// Both are null or NUL-terminated strings valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keyless_call(method: *const c_char, args: *const c_char) -> *mut c_char {
    // SAFETY: per this function's contract.
    let answer = match unsafe { (read(method), read(args)) } {
        (Some(method), Some(args)) => call(&method, &args),
        _ => r#"{"error":{"key":"invalid_request","message":"unreadable arguments"}}"#.to_string(),
    };
    CString::new(answer).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// Frees an answer of `keyless_call`.
///
/// # Safety
/// `text` is null or an answer of `keyless_call`, not freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keyless_free(text: *mut c_char) {
    if !text.is_null() {
        // SAFETY: `text` came from `keyless_call` (CString::into_raw) and is freed once.
        drop(unsafe { CString::from_raw(text) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_through_c() {
        let method = CString::new("status").unwrap();
        let args = CString::new("").unwrap();
        unsafe {
            let answer = keyless_call(method.as_ptr(), args.as_ptr());
            let text = CStr::from_ptr(answer).to_str().unwrap().to_string();
            keyless_free(answer);
            assert!(text.contains("\"unlocked\":false"));
            let refused = keyless_call(std::ptr::null(), args.as_ptr());
            assert!(CStr::from_ptr(refused).to_str().unwrap().contains("invalid_request"));
            keyless_free(refused);
        }
    }
}

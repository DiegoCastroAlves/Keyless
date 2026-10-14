//! The Android app's client (`keyless_client`) through JNI: one native
//! method, `Native.call(method, args)`, JSON in and out. The app talks to
//! the server, keeps files and draws the screens.

use std::sync::{Mutex, OnceLock};

use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JObject, JString, JValue},
    sys::{jbyteArray, jint, jstring},
};
use keyless_client::Client;
use zeroize::Zeroizing;

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

/// `Native.attachmentSeal(String, int, byte[]): byte[]`: chunk `index` of
/// a new file (`attachmentNew`), encrypted; null if there is no such file.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_diegocastroalves_keyless_Native_attachmentSeal<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    attachment_id: JString<'local>,
    index: jint,
    plain: JByteArray<'local>,
) -> jbyteArray {
    let (Ok(id), Ok(plain)) = (env.get_string(&attachment_id).map(String::from), env.convert_byte_array(&plain)) else {
        return std::ptr::null_mut();
    };
    let plain = Zeroizing::new(plain);
    let sealed = client().lock().unwrap_or_else(|e| e.into_inner()).attachment_seal(&id, index as u32, &plain);
    match sealed {
        Ok(sealed) => env.byte_array_from_slice(&sealed).map(|a| a.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `Native.attachmentOpen(String, String, int, byte[]): byte[]`: chunk
/// `index` of an item's attachment, decrypted; null if it does not check out.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_diegocastroalves_keyless_Native_attachmentOpen<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    item_id: JString<'local>,
    attachment_id: JString<'local>,
    index: jint,
    raw: JByteArray<'local>,
) -> jbyteArray {
    let (Ok(item), Ok(id), Ok(raw)) =
        (env.get_string(&item_id).map(String::from), env.get_string(&attachment_id).map(String::from), env.convert_byte_array(&raw))
    else {
        return std::ptr::null_mut();
    };
    let plain = client().lock().unwrap_or_else(|e| e.into_inner()).attachment_open(&item, &id, index as u32, &raw);
    match plain {
        Ok(plain) => env.byte_array_from_slice(&plain).map(|a| a.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

fn answer(env: &mut JNIEnv, text: String) -> jstring {
    env.new_string(text).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

fn failed(key: &str, message: &str) -> String {
    serde_json::json!({ "error": { "key": key, "message": message } }).to_string()
}

/// `Native.importParse(String, byte[], byte[]): String`: reads an import
/// file (and a KeePass key file, or null); answers like `call`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_diegocastroalves_keyless_Native_importParse<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    args: JString<'local>,
    file: JByteArray<'local>,
    key_file: JByteArray<'local>,
) -> jstring {
    let key_file = if key_file.is_null() { Ok(None) } else { env.convert_byte_array(&key_file).map(|k| Some(Zeroizing::new(k))) };
    let text = match (env.get_string(&args).map(String::from), env.convert_byte_array(&file), key_file) {
        (Ok(args), Ok(file), Ok(key_file)) => client().lock().unwrap_or_else(|e| e.into_inner()).import_parse(&args, Zeroizing::new(file), key_file),
        _ => failed("file_too_large", "unreadable arguments"),
    };
    answer(&mut env, text)
}

/// `Native.importFile(String, ChunkSink): String`: reads, encrypts and
/// hands the import's file `attachmentId` to `sink.put(index, sealed)`, a
/// chunk at a time (without holding the client); answers like `call`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_diegocastroalves_keyless_Native_importFile<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    attachment_id: JString<'local>,
    sink: JObject<'local>,
) -> jstring {
    let Ok(id) = env.get_string(&attachment_id).map(String::from) else {
        return answer(&mut env, failed("invalid_request", "unreadable arguments"));
    };
    let source = client().lock().unwrap_or_else(|e| e.into_inner()).import_file_source(&id);
    let text = match source {
        Ok(source) => {
            let read = source.read(|index, sealed| {
                let Ok(bytes) = env.byte_array_from_slice(&sealed) else { return false };
                let put = env.call_method(&sink, "put", "(I[B)Z", &[JValue::Int(index as jint), JValue::Object(&bytes)]);
                let _ = env.delete_local_ref(bytes);
                match put.and_then(|v| v.z()) {
                    Ok(done) => done,
                    Err(_) => {
                        let _ = env.exception_clear();
                        false
                    }
                }
            });
            match read {
                Ok(()) => r#"{"ok":null}"#.to_string(),
                Err(failure) => failed(failure.key, &failure.message),
            }
        }
        Err(failure) => failed(failure.key, &failure.message),
    };
    answer(&mut env, text)
}

/// `Native.exportChunk(String, int, byte[]): String`: a downloaded chunk of
/// an attached file being exported; answers like `call`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_diegocastroalves_keyless_Native_exportChunk<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    attachment_id: JString<'local>,
    index: jint,
    raw: JByteArray<'local>,
) -> jstring {
    let text = match (env.get_string(&attachment_id).map(String::from), env.convert_byte_array(&raw)) {
        (Ok(id), Ok(raw)) => match client().lock().unwrap_or_else(|e| e.into_inner()).export_chunk(&id, index as u32, &raw) {
            Ok(()) => r#"{"ok":null}"#.to_string(),
            Err(failure) => failed(failure.key, &failure.message),
        },
        _ => failed("invalid_request", "unreadable arguments"),
    };
    answer(&mut env, text)
}

/// `Native.exportFinish(): byte[]`: the export's file; null if it failed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_diegocastroalves_keyless_Native_exportFinish<'local>(env: JNIEnv<'local>, _class: JClass<'local>) -> jbyteArray {
    let finished = client().lock().unwrap_or_else(|e| e.into_inner()).export_finish();
    match finished {
        Ok(bytes) => env.byte_array_from_slice(&bytes).map(|a| a.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn answers_in_json() {
        assert!(super::call("status", "").contains("\"unlocked\":false"));
        assert!(super::call("nope", "").contains("invalid_request"));
    }
}

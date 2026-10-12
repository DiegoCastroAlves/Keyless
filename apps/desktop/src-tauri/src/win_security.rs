//! Windows access control: objects only the current user can open (the
//! bridge pipe, the fallback secret files).

use std::path::Path;

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{
        Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        DACL_SECURITY_INFORMATION, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES, SetFileSecurityW, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// A security descriptor whose DACL grants full access to the current user
/// only, and does not inherit anything from the parent folder.
pub struct UserOnly {
    descriptor: PSECURITY_DESCRIPTOR,
}

// The descriptor is read-only once made.
unsafe impl Send for UserOnly {}
unsafe impl Sync for UserOnly {}

impl UserOnly {
    pub fn new() -> Option<UserOnly> {
        let sid = current_user_sid()?;
        let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})").encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is freed with
        // LocalFree on drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut descriptor, std::ptr::null_mut())
        };
        (ok != 0 && !descriptor.is_null()).then_some(UserOnly { descriptor })
    }

    /// Attributes for creating an object (such as a named pipe) with this
    /// descriptor. Valid while `self` lives.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        }
    }

    /// Replaces a file's permissions with this descriptor's.
    pub fn apply_to_file(&self, path: &Path) -> bool {
        let wide: Vec<u16> = path.as_os_str().to_string_lossy().encode_utf16().chain(Some(0)).collect();
        // SAFETY: a NUL-terminated path and a valid descriptor.
        unsafe { SetFileSecurityW(wide.as_ptr(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, self.descriptor) != 0 }
    }
}

impl Drop for UserOnly {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.descriptor) };
    }
}

/// Restricts a file to the current user (best effort).
pub fn restrict_file(path: &Path) {
    if !UserOnly::new().is_some_and(|d| d.apply_to_file(path)) {
        log::warn!("could not restrict the permissions of {}", path.display());
    }
}

/// The current user's SID, as a string ("S-1-5-21-…").
fn current_user_sid() -> Option<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: our own process's token, closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let mut buffer = vec![0u64; 64]; // 512 bytes, aligned for TOKEN_USER
    let mut len = 0u32;
    // SAFETY: the buffer and its size match.
    let ok = unsafe { GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), (buffer.len() * 8) as u32, &mut len) };
    // SAFETY: the token opened above.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return None;
    }
    // SAFETY: GetTokenInformation filled the buffer with a TOKEN_USER.
    let sid = unsafe { (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid };
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: a valid SID; the string is freed with LocalFree.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated string from the call above.
    let result = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
    };
    // SAFETY: allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(text.cast()) };
    Some(result)
}

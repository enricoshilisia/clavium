//! The whole native surface the Flutter app sees:
//!
//! ```c
//! char* clavium_invoke(const char* request_json);  // returns JSON, never NULL
//! void  clavium_free(char* response);
//! ```
//!
//! One process-wide session (the unlocked vault) behind a mutex. A panic
//! inside a command is caught and reported as an error response rather
//! than unwinding across the FFI boundary, which would be undefined
//! behaviour.

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};

use clavium_api::Session;

fn session() -> &'static Mutex<Session> {
    static SESSION: OnceLock<Mutex<Session>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(Session::new()))
}

fn to_c(s: String) -> *mut c_char {
    // Interior NULs cannot occur in serde_json output, but never panic here.
    CString::new(s)
        .unwrap_or_else(|_| CString::new(r#"{"error":"response contained a NUL byte"}"#).unwrap())
        .into_raw()
}

/// # Safety
/// `request` must be a valid NUL-terminated UTF-8 string (or NULL).
#[no_mangle]
pub unsafe extern "C" fn clavium_invoke(request: *const c_char) -> *mut c_char {
    if request.is_null() {
        return to_c(r#"{"error":"null request"}"#.into());
    }
    let req = match CStr::from_ptr(request).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return to_c(r#"{"error":"request is not UTF-8"}"#.into()),
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut guard = session().lock().unwrap_or_else(|p| p.into_inner());
        guard.handle(&req)
    }));
    to_c(result.unwrap_or_else(|_| r#"{"error":"internal error"}"#.into()))
}

/// # Safety
/// `response` must be a pointer returned by `clavium_invoke`, freed once.
#[no_mangle]
pub unsafe extern "C" fn clavium_free(response: *mut c_char) {
    if !response.is_null() {
        drop(CString::from_raw(response));
    }
}

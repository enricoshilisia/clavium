//! `invoke(requestJson) -> responseJson`, the same contract as the native
//! FFI. The unlocked vault lives in this module's memory; reloading the
//! page drops it, which is the browser's equivalent of locking.

use std::cell::RefCell;

use clavium_api::Session;
use wasm_bindgen::prelude::*;

thread_local! {
    static SESSION: RefCell<Session> = RefCell::new(Session::new());
}

#[wasm_bindgen]
pub fn invoke(request: &str) -> String {
    SESSION.with(|s| s.borrow_mut().handle(request))
}

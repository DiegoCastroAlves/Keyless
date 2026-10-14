//! The web vault's client (`keyless_client`) as WebAssembly: one function,
//! `call(method, args)`, JSON in and out. The page talks to the server.

#![forbid(unsafe_code)]

use std::cell::RefCell;

use keyless_client::Client;
use wasm_bindgen::prelude::*;

thread_local! {
    static CLIENT: RefCell<Client> = RefCell::new(Client::new());
}

#[wasm_bindgen]
pub fn call(method: &str, args: &str) -> String {
    CLIENT.with(|client| client.borrow_mut().call(method, args))
}

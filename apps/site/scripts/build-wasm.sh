#!/usr/bin/env bash
# Builds the web vault's client (crates/keyless-wasm) into vendor/keyless-wasm,
# which is committed: the site's own build (Cloudflare Pages) has no Rust.
# Needs the wasm32-unknown-unknown target and wasm-bindgen-cli of the same
# version as the wasm-bindgen crate in Cargo.lock.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/../../.."
cargo build -p keyless-wasm --target wasm32-unknown-unknown --profile wasm
wasm-bindgen --target web --out-dir apps/site/vendor/keyless-wasm \
  target/wasm32-unknown-unknown/wasm/keyless_wasm.wasm
ls -l apps/site/vendor/keyless-wasm

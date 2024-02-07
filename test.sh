#!/bin/sh
set -eox
cargo test --no-default-features
cargo test
cargo test --no-default-features --features std
cargo test --no-default-features --features tokio
cargo test --no-default-features --features build_server
cargo build --lib
cargo build --lib --features std
cargo build --lib --features tokio
cargo build --bin http_proof_gen --features build_server

#!/bin/sh
set -eox
cargo test
cargo test --features std
cargo test --features tokio
cargo test --features build_server
cargo build --lib
cargo build --lib --features std
cargo build --lib --features tokio
cargo build --bin http_proof_gen --features build_server

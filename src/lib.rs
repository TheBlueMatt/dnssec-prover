//! The DNS provides a single, global, hierarchical namespace with (when DNSSEC is used)
//! cryptographic guarantees on all of its data.
//!
//! This makes it incredibly powerful for resolving human-readable names into arbitrary, secured
//! data.
//!
//! Unlike TLS, this cryptographic security provides transferable proofs which can convince an
//! offline device, using simple cryptographic primitives and a single root trusted key, of the
//! validity of DNS data.
//!
//! This crate implements the creation and validation of such proofs, using the format from RFC
//! 9102 to create transferable proofs of DNS entries.
//!
//! It is no-std (but requires `alloc`) and seeks to have minimal dependencies and a reasonably
//! conservative MSRV policy, allowing it to be used in as many places as possible.
//!
//! Most of the crate's logic is feature-gated, and *all dependencies are optional*:
//!  * By default, the `validate` feature is set, using `ring` to validate DNSSEC signatures and
//!    proofs using the [`validation`] module.
//!  * The `std` feature enables the [`query`] module, allowing for the building of proofs by
//!    querying a recursive resolver over TCP.
//!  * The `tokio` feature further enables async versions of the [`query`] methods, doing the same
//!    querying async using `tokio`'s TCP streams.
//!  * Finally, the crate can be built as a binary using the `build_server` feature, responding to
//!    queries over HTTP GET calls to `/dnssecproof?d=domain.name.&t=RecordType` with DNSSEC
//!    proofs.
//!
//! Note that this library's MSRV is 1.64 for normal building, however builds fine on 1.63 (and
//! possibly earlier) when `RUSTC_BOOTSTRAP=1` is set, as it relies on the
//! `const_slice_from_raw_parts` feature.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

// const_slice_from_raw_parts was stabilized in 1.64, however we support building on 1.63 as well.
// Luckily, it seems to work fine in 1.63 with the feature flag (and RUSTC_BOOTSTRAP=1) enabled.
#![allow(stable_features)]
#![feature(const_slice_from_raw_parts)]

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

#[cfg(feature = "validation")]
mod base32;

#[cfg(all(feature = "validation", any(fuzzing, dnssec_validate_bench)))]
pub mod crypto;
#[cfg(all(feature = "validation", not(any(fuzzing, dnssec_validate_bench))))]
mod crypto;

pub mod rr;
pub mod ser;
pub mod query;

#[cfg(feature = "validation")]
pub mod validation;

#[cfg(all(feature = "std", feature = "validation", test))]
mod test;

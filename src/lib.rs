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

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod rr;
pub mod ser;
pub mod query;

#[cfg(feature = "validation")]
mod crypto;
#[cfg(feature = "validation")]
pub mod validation;

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

#![deny(missing_docs)]

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod rr;
pub mod validation;
mod ser;

#[cfg(feature = "std")]
pub mod query;

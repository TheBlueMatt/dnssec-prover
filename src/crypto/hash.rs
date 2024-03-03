//! Simple wrapper around various hash options to provide a single enum which can calculate
//! different hashes.

use bitcoin_hashes::Hash;
use bitcoin_hashes::HashEngine as _;
use bitcoin_hashes::sha1::Hash as Sha1;
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::sha512::Hash as Sha512;

pub(crate) enum Hasher {
	Sha1(<Sha1 as Hash>::Engine),
	Sha256(<Sha256 as Hash>::Engine),
	Sha512(<Sha512 as Hash>::Engine),
}

pub(crate) enum HashResult {
	Sha1(Sha1),
	Sha256(Sha256),
	Sha512(Sha512),
}

impl AsRef<[u8]> for HashResult {
	fn as_ref(&self) -> &[u8] {
		match self {
			HashResult::Sha1(hash) => hash.as_ref(),
			HashResult::Sha256(hash) => hash.as_ref(),
			HashResult::Sha512(hash) => hash.as_ref(),
		}
	}
}

impl Hasher {
	pub(crate) fn sha1() -> Hasher { Hasher::Sha1(Sha1::engine()) }
	pub(crate) fn sha256() -> Hasher { Hasher::Sha256(Sha256::engine()) }
	pub(crate) fn sha512() -> Hasher { Hasher::Sha512(Sha512::engine()) }

	pub(crate) fn update(&mut self, buf: &[u8]) {
		match self {
			Hasher::Sha1(hasher) => hasher.input(buf),
			Hasher::Sha256(hasher) => hasher.input(buf),
			Hasher::Sha512(hasher) => hasher.input(buf),
		}
	}

	pub(crate) fn finish(self) -> HashResult {
		match self {
			Hasher::Sha1(hasher) => HashResult::Sha1(Sha1::from_engine(hasher)),
			Hasher::Sha256(hasher) => HashResult::Sha256(Sha256::from_engine(hasher)),
			Hasher::Sha512(hasher) => HashResult::Sha512(Sha512::from_engine(hasher)),
		}
	}
}


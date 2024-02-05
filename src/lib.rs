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

#![allow(deprecated)] // XXX
#![deny(missing_docs)]

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use alloc::vec;
use alloc::string::String;
use alloc::borrow::ToOwned;

use ring::signature;

/// Gets the trusted root anchors
///
/// These are available at <https://data.iana.org/root-anchors/root-anchors.xml>
pub fn root_hints() -> Vec<DS> {
	#[allow(unused_mut)]
	let mut res = vec![DS {
		name: ".".try_into().unwrap(), key_tag: 19036, alg: 8, digest_type: 2,
		digest: hex_lit::hex!("49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5").to_vec(),
	}, DS {
		name: ".".try_into().unwrap(), key_tag: 20326, alg: 8, digest_type: 2,
		digest: hex_lit::hex!("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D").to_vec(),
	}];
	// In tests, add the trust anchor from RFC 9102
	#[cfg(test)]
	res.push(DS {
		name: ".".try_into().unwrap(), key_tag: 47005, alg: 13, digest_type: 2,
		digest: hex_lit::hex!("2eb6e9f2480126691594d649a5a613de3052e37861634641bb568746f2ffc4d4").to_vec(),
	});
	res
}

/// A valid domain name.
///
/// It must end with a ".", be no longer than 255 bytes, consist of only printable ASCII
/// characters and each label may be no longer than 63 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name(String);
impl core::ops::Deref for Name {
	type Target = str;
	fn deref(&self) -> &str { &self.0 }
}
impl TryFrom<String> for Name {
	type Error = ();
	fn try_from(s: String) -> Result<Name, ()> {
		if s.is_empty() { return Err(()); }
		if *s.as_bytes().last().unwrap_or(&0) != b"."[0] { return Err(()); }
		if s.len() > 255 { return Err(()); }
		if s.chars().any(|c| !c.is_ascii_graphic() && c != '.' && c != '-') { return Err(()); }
		for label in s.split(".") {
			if label.len() > 63 { return Err(()); }
		}

		Ok(Name(s))
	}
}
impl TryFrom<&str> for Name {
	type Error = ();
	fn try_from(s: &str) -> Result<Name, ()> {
		Self::try_from(s.to_owned())
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A supported Resource Record
///
/// Note that we only currently support a handful of RR types as needed to generate and validate
/// TXT or TLSA record proofs.
pub enum RR {
	/// A text resource record
	Txt(Txt),
	/// A TLS Certificate Association resource record
	TLSA(TLSA),
	/// A DNS (Public) Key resource record
	DnsKey(DnsKey),
	/// A Delegated Signer resource record
	DS(DS),
	/// A Resource Record Signature record
	RRSig(RRSig),
}
impl RR {
	/// Gets the name this record refers to.
	pub fn name(&self) -> &Name {
		match self {
			RR::Txt(rr) => &rr.name,
			RR::TLSA(rr) => &rr.name,
			RR::DnsKey(rr) => &rr.name,
			RR::DS(rr) => &rr.name,
			RR::RRSig(rr) => &rr.name,
		}
	}
	fn ty(&self) -> u16 {
		match self {
			RR::Txt(_) => Txt::TYPE,
			RR::TLSA(_) => TLSA::TYPE,
			RR::DnsKey(_) => DnsKey::TYPE,
			RR::DS(_) => DS::TYPE,
			RR::RRSig(_) => RRSig::TYPE,
		}
	}
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		match self {
			RR::Txt(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::TLSA(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::DnsKey(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::DS(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::RRSig(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
		}
	}
}
impl From<Txt> for RR { fn from(txt: Txt) -> RR { RR::Txt(txt) } }
impl From<TLSA> for RR { fn from(tlsa: TLSA) -> RR { RR::TLSA(tlsa) } }
impl From<DnsKey> for RR { fn from(dnskey: DnsKey) -> RR { RR::DnsKey(dnskey) } }
impl From<DS> for RR { fn from(ds: DS) -> RR { RR::DS(ds) } }
impl From<RRSig> for RR { fn from(rrsig: RRSig) -> RR { RR::RRSig(rrsig) } }

trait StaticRecord : Ord {
	// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
	const TYPE: u16;
	fn name(&self) -> &Name;
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>);
}
/// A trait describing a resource record (including the [`RR`] enum).
pub trait Record : Ord + {
	/// The resource record type, as maintained by IANA.
	///
	/// Current assignments can be found at
	/// <http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4>
	fn ty(&self) -> u16;
	/// The name this record is at.
	fn name(&self) -> &Name;
	/// Writes the data of this record, prefixed by a u16 length, to the given `Vec`.
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>);
}
impl<RR: StaticRecord> Record for RR {
	fn ty(&self) -> u16 { RR::TYPE }
	fn name(&self) -> &Name { RR::name(self) }
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		RR::write_u16_len_prefixed_data(self, out)
	}
}
impl Record for RR {
	fn ty(&self) -> u16 { self.ty() }
	fn name(&self) -> &Name { self.name() }
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		self.write_u16_len_prefixed_data(out)
	}
}

fn read_u8(inp: &mut &[u8]) -> Result<u8, ()> {
	let res = *inp.get(0).ok_or(())?;
	*inp = &inp[1..];
	Ok(res)
}
fn read_u16(inp: &mut &[u8]) -> Result<u16, ()> {
	if inp.len() < 2 { return Err(()); }
	let mut bytes = [0; 2];
	bytes.copy_from_slice(&inp[..2]);
	*inp = &inp[2..];
	Ok(u16::from_be_bytes(bytes))
}
fn read_u32(inp: &mut &[u8]) -> Result<u32, ()> {
	if inp.len() < 4 { return Err(()); }
	let mut bytes = [0; 4];
	bytes.copy_from_slice(&inp[..4]);
	*inp = &inp[4..];
	Ok(u32::from_be_bytes(bytes))
}

fn read_name(inp: &mut &[u8]) -> Result<Name, ()> {
	let mut name = String::with_capacity(1024);
	loop {
		let len = read_u8(inp)? as usize;
		if len == 0 {
			if name.is_empty() { name += "."; }
			break;
		}
		if inp.len() <= len { return Err(()); }
		name += core::str::from_utf8(&inp[..len]).map_err(|_| ())?;
		name += ".";
		*inp = &inp[len..];
		if name.len() > 1024 { return Err(()); }
	}
	Ok(name.try_into()?)
}

trait Writer { fn write(&mut self, buf: &[u8]); }
impl Writer for Vec<u8> { fn write(&mut self, buf: &[u8]) { self.extend_from_slice(buf); } }
impl Writer for ring::digest::Context { fn write(&mut self, buf: &[u8]) { self.update(buf); } }
fn write_name<W: Writer>(out: &mut W, name: &str) {
	let canonical_name = name.to_ascii_lowercase();
	if canonical_name == "." {
		out.write(&[0]);
	} else {
		for label in canonical_name.split(".") {
			out.write(&(label.len() as u8).to_be_bytes());
			out.write(label.as_bytes());
		}
	}
}
fn name_len(name: &Name) -> u16 {
	if name.0 == "." {
		1
	} else {
		let mut res = 0;
		for label in name.split(".") {
			res += 1 + label.len();
		}
		res as u16
	}
}

fn parse_rr(inp: &mut &[u8]) -> Result<RR, ()> {
	let name = read_name(inp)?;
	let ty = read_u16(inp)?;
	let class = read_u16(inp)?;
	if class != 1 { return Err(()); } // We only support the INternet
	let _ttl = read_u32(inp)?;
	let data_len = read_u16(inp)? as usize;
	if inp.len() < data_len { return Err(()); }
	let mut data = &inp[..data_len];
	*inp = &inp[data_len..];

	match ty {
		Txt::TYPE => {
			let mut parsed_data = Vec::with_capacity(data_len - 1);
			while !data.is_empty() {
				let len = read_u8(&mut data)? as usize;
				if data.len() < len { return Err(()); }
				parsed_data.extend_from_slice(&data[..len]);
				data = &data[len..];
			}
			Ok(RR::Txt(Txt { name, data: parsed_data }))
		}
		TLSA::TYPE => {
			if data_len <= 3 { return Err(()); }
			Ok(RR::TLSA(TLSA {
				name, cert_usage: read_u8(&mut data)?, selector: read_u8(&mut data)?,
				data_ty: read_u8(&mut data)?, data: data.to_vec(),
			}))
		},
		DnsKey::TYPE => {
			Ok(RR::DnsKey(DnsKey {
				name, flags: read_u16(&mut data)?, protocol: read_u8(&mut data)?,
				alg: read_u8(&mut data)?, pubkey: data.to_vec(),
			}))
		},
		DS::TYPE => {
			Ok(RR::DS(DS {
				name, key_tag: read_u16(&mut data)?, alg: read_u8(&mut data)?,
				digest_type: read_u8(&mut data)?, digest: data.to_vec(),
			}))
		},
		RRSig::TYPE => {
			Ok(RR::RRSig(RRSig {
				name, ty: read_u16(&mut data)?, alg: read_u8(&mut data)?,
				labels: read_u8(&mut data)?, orig_ttl: read_u32(&mut data)?,
				expiration: read_u32(&mut data)?, inception: read_u32(&mut data)?,
				key_tag: read_u16(&mut data)?, key_name: read_name(&mut data)?,
				signature: data.to_vec(),
			}))
		},
		_ => Err(()),
	}
}
/// Parse a stream of [`RR`]s from the format described in [RFC 9102](https://www.rfc-editor.org/rfc/rfc9102.html).
///
/// Note that this is only the series of `AuthenticationChain` records, and does not read the
/// `ExtSupportLifetime` field at the start of a `DnssecChainExtension`.
pub fn parse_rr_stream(mut inp: &[u8]) -> Result<Vec<RR>, ()> {
	let mut res = Vec::with_capacity(32);
	while !inp.is_empty() {
		res.push(parse_rr(&mut inp)?);
	}
	Ok(res)
}

/// Writes the given resource record in its wire encoding to the given `Vec`.
///
/// An [RFC 9102](https://www.rfc-editor.org/rfc/rfc9102.html) `AuthenticationChain` is simply a
/// series of such records with no additional bytes in between.
pub fn write_rr<RR: Record>(rr: &RR, ttl: u32, out: &mut Vec<u8>) {
	write_name(out, rr.name());
	out.extend_from_slice(&rr.ty().to_be_bytes());
	out.extend_from_slice(&1u16.to_be_bytes()); // The INternet class
	out.extend_from_slice(&ttl.to_be_bytes());
	rr.write_u16_len_prefixed_data(out);
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)] // TODO: ord is wrong cause need to consider len first, maybe
/// A text resource record, containing arbitrary text data
pub struct Txt {
	/// The name this record is at.
	pub name: Name,
	/// The text record itself.
	///
	/// While this is generally UTF-8-valid, there is no specific requirement that it be, and thus
	/// is an arbitrary series of bytes here.
	data: Vec<u8>,
}
impl StaticRecord for Txt {
	const TYPE: u16 = 16;
	fn name(&self) -> &Name { &self.name }
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		let len = (self.data.len() + self.data.len() / 255 + 1) as u16;
		out.extend_from_slice(&len.to_be_bytes());

		let mut data_write = &self.data[..];
		out.extend_from_slice(&[data_write.len().try_into().unwrap_or(255)]);
		while !data_write.is_empty() {
			let split_pos = core::cmp::min(255, data_write.len());
			out.extend_from_slice(&data_write[..split_pos]);
			data_write = &data_write[split_pos..];
			if !data_write.is_empty() {
				out.extend_from_slice(&[data_write.len().try_into().unwrap_or(255)]);
			}
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A TLS Certificate Association resource record containing information about the TLS certificate
/// which should be expected when communicating with the host at the given name.
///
/// See <https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities#TLSA_RR> for more
/// info.
pub struct TLSA {
	/// The name this record is at.
	pub name: Name,
	/// The type of constraint on the TLS certificate(s) used which should be enforced by this
	/// record.
	pub cert_usage: u8,
	/// Whether to match on the full certificate, or only the public key.
	pub selector: u8,
	/// The type of data included which is used to match the TLS certificate(s).
	pub data_ty: u8,
	/// The certificate data or hash of the certificate data itself.
	pub data: Vec<u8>,
}
impl StaticRecord for TLSA {
	const TYPE: u16 = 52;
	fn name(&self) -> &Name { &self.name }
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		let len = 3 + self.data.len();
		out.extend_from_slice(&(len as u16).to_be_bytes());
		out.extend_from_slice(&[self.cert_usage, self.selector, self.data_ty]);
		out.extend_from_slice(&self.data);
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A public key resource record which can be used to validate [`RRSig`]s.
pub struct DnsKey {
	/// The name this record is at.
	pub name: Name,
	/// Flags which constrain the usage of this public key.
	pub flags: u16,
	/// The protocol this key is used for (protocol `3` is DNSSEC). 
	pub protocol: u8,
	/// The algorithm which this public key uses to sign data.
	pub alg: u8,
	/// The public key itself.
	pub pubkey: Vec<u8>,
}
impl StaticRecord for DnsKey {
	const TYPE: u16 = 48;
	fn name(&self) -> &Name { &self.name }
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		let len = 2 + 1 + 1 + self.pubkey.len();
		out.extend_from_slice(&(len as u16).to_be_bytes());
		out.extend_from_slice(&self.flags.to_be_bytes());
		out.extend_from_slice(&self.protocol.to_be_bytes());
		out.extend_from_slice(&self.alg.to_be_bytes());
		out.extend_from_slice(&self.pubkey);
	}
}
impl DnsKey {
	/// A short (non-cryptographic) digest which can be used to refer to this [`DnsKey`].
	pub fn key_tag(&self) -> u16 {
		let mut res = u32::from(self.flags);
		res += u32::from(self.protocol) << 8;
		res += u32::from(self.alg);
		for (idx, b) in self.pubkey.iter().enumerate() {
			if idx % 2 == 0 {
				res += u32::from(*b) << 8;
			} else {
				res += u32::from(*b);
			}
		}
		res += (res >> 16) & 0xffff;
		(res & 0xffff) as u16
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A Delegation Signer resource record which indicates that some alternative [`DnsKey`] can sign
/// for records in the zone which matches [`DS::name`].
pub struct DS {
	/// The name this record is at.
	///
	/// This is also the zone that a [`DnsKey`] which matches the [`Self::digest`] can sign for.
	pub name: Name,
	/// A short tag which describes the matching [`DnsKey`].
	///
	/// This matches the [`DnsKey::key_tag`] for the [`DnsKey`] which is referred to by this
	/// [`DS`].
	pub key_tag: u16,
	/// The algorithm which the [`DnsKey`] referred to by this [`DS`] uses.
	///
	/// This matches the [`DnsKey::alg`] field in the referred-to [`DnsKey`].
	pub alg: u8,
	/// The type of digest used to hash the referred-to [`DnsKey`].
	pub digest_type: u8,
	/// The digest itself.
	pub digest: Vec<u8>,
}
impl StaticRecord for DS {
	const TYPE: u16 = 43;
	fn name(&self) -> &Name { &self.name }
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		let len = 2 + 1 + 1 + self.digest.len();
		out.extend_from_slice(&(len as u16).to_be_bytes());
		out.extend_from_slice(&self.key_tag.to_be_bytes());
		out.extend_from_slice(&self.alg.to_be_bytes());
		out.extend_from_slice(&self.digest_type.to_be_bytes());
		out.extend_from_slice(&self.digest);
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A Resource Record (set) Signature resource record. This contains a signature over all the
/// resources records of the given type at the given name.
pub struct RRSig {
	/// The name this record is at.
	///
	/// This is also the name of any records which this signature is covering (ignoring wildcards).
	pub name: Name,
	/// The resource record type which this [`RRSig`] is signing.
	///
	/// All resources records of this type at the same name as [`Self::name`] must be signed by
	/// this [`RRSig`].
	pub ty: u16,
	/// The algorithm which is being used to sign.
	///
	/// This must match the [`DnsKey::alg`] field in the [`DnsKey`] being used to sign.
	pub alg: u8,
	/// The number of labels in the name of the records that this signature is signing.
	// TODO: Describe this better in terms of wildcards
	pub labels: u8,
	/// The TTL of the records which this [`RRSig`] is signing.
	pub orig_ttl: u32,
	/// The expiration (as a UNIX timestamp) of this signature.
	pub expiration: u32,
	/// The time (as a UNIX timestamp) at which this signature becomes valid.
	pub inception: u32,
	/// A short tag which describes the matching [`DnsKey`].
	///
	/// This matches the [`DnsKey::key_tag`] for the [`DnsKey`] which created this signature.
	pub key_tag: u16,
	/// The [`DnsKey::name`] in the [`DnsKey`] which created this signature.
	///
	/// This must be a parent of the [`Self::name`].
	pub key_name: Name,
	/// The signature itself.
	pub signature: Vec<u8>,
}
impl StaticRecord for RRSig {
	const TYPE: u16 = 46;
	fn name(&self) -> &Name { &self.name }
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		let len = 2 + 1 + 1 + 4*3 + 2 + name_len(&self.key_name) + self.signature.len() as u16;
		out.extend_from_slice(&len.to_be_bytes());
		out.extend_from_slice(&self.ty.to_be_bytes());
		out.extend_from_slice(&self.alg.to_be_bytes());
		out.extend_from_slice(&self.labels.to_be_bytes());
		out.extend_from_slice(&self.orig_ttl.to_be_bytes());
		out.extend_from_slice(&self.expiration.to_be_bytes());
		out.extend_from_slice(&self.inception.to_be_bytes());
		out.extend_from_slice(&self.key_tag.to_be_bytes());
		write_name(out, &self.key_name);
		out.extend_from_slice(&self.signature);
	}
}

#[derive(Debug, PartialEq)]
/// An error when validating DNSSEC signatures or other data
pub enum ValidationError {
	/// An algorithm used in signing was not supported.
	///
	/// In general DNS usage the resulting data should be used anyway, as we were able to verify
	/// that a zone wished to use the unsupported algorithm.
	///
	/// However, in cases where signing is mandatory, this can be treated as an error.
	UnsupportedAlgorithm,
	/// The provided data was invalid or signatures did not validate.
	Invalid,
}

fn bytes_to_rsa_pk<'a>(pubkey: &'a [u8])
-> Result<signature::RsaPublicKeyComponents<&'a [u8]>, ValidationError> {
	if pubkey.len() <= 3 { return Err(ValidationError::Invalid); }

	let mut pos = 0;
	let exponent_length;
	if pubkey[0] == 0 {
		exponent_length = ((pubkey[1] as usize) << 8) | (pubkey[2] as usize);
		pos += 3;
	} else {
		exponent_length = pubkey[0] as usize;
		pos += 1;
	}

	if pubkey.len() <= pos + exponent_length { return Err(ValidationError::Invalid); }
	Ok(signature::RsaPublicKeyComponents {
		n: &pubkey[pos + exponent_length..],
		e: &pubkey[pos..pos + exponent_length]
	})
}

// TODO: return the validity period
fn verify_rrsig<'a, RR: Record, Keys>(sig: &RRSig, dnskeys: Keys, mut records: Vec<&RR>)
-> Result<(), ValidationError>
where Keys: IntoIterator<Item = &'a DnsKey> {
	for record in records.iter() {
		if sig.ty != record.ty() { return Err(ValidationError::Invalid); }
	}
	for dnskey in dnskeys.into_iter() {
		if dnskey.key_tag() == sig.key_tag {
			// Protocol must be 3, otherwise its not DNSSEC
			if dnskey.protocol != 3 { continue; }
			// The ZONE flag must be set if we're going to validate RRs with this key.
			if dnskey.flags & 0b1_0000_0000 == 0 { continue; }
			if dnskey.alg != sig.alg { continue; }

			// TODO: Check orig_ttl somehow?

			let mut signed_data = Vec::with_capacity(2048);
			signed_data.extend_from_slice(&sig.ty.to_be_bytes());
			signed_data.extend_from_slice(&sig.alg.to_be_bytes());
			signed_data.extend_from_slice(&sig.labels.to_be_bytes()); // Check this somehow?
			signed_data.extend_from_slice(&sig.orig_ttl.to_be_bytes());
			signed_data.extend_from_slice(&sig.expiration.to_be_bytes()); // Return this and inception
			signed_data.extend_from_slice(&sig.inception.to_be_bytes());
			signed_data.extend_from_slice(&sig.key_tag.to_be_bytes());
			write_name(&mut signed_data, &sig.key_name);

			records.sort();

			for record in records.iter() {
				// TODO: Handle wildcards
				write_name(&mut signed_data, record.name());
				signed_data.extend_from_slice(&record.ty().to_be_bytes());
				signed_data.extend_from_slice(&1u16.to_be_bytes()); // The INternet class
				signed_data.extend_from_slice(&sig.orig_ttl.to_be_bytes());
				record.write_u16_len_prefixed_data(&mut signed_data);
			}

			match sig.alg {
				8|10 => {
					let alg = if sig.alg == 8 {
						&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
					} else {
						&signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
					};
					bytes_to_rsa_pk(&dnskey.pubkey)?
						.verify(alg, &signed_data, &sig.signature)
						.map_err(|_| ValidationError::Invalid)?;
				},
				13|14 => {
					let alg = if sig.alg == 13 {
						&signature::ECDSA_P256_SHA256_FIXED
					} else {
						&signature::ECDSA_P384_SHA384_FIXED
					};

					// Add 0x4 identifier to the ECDSA pubkey as expected by ring.
					let mut key = Vec::with_capacity(dnskey.pubkey.len() + 1);
					key.push(0x4);
					key.extend_from_slice(&dnskey.pubkey);

					signature::UnparsedPublicKey::new(alg, &key)
						.verify(&signed_data, &sig.signature)
						.map_err(|_| ValidationError::Invalid)?;
				},
				15 => {
					signature::UnparsedPublicKey::new(&signature::ED25519, &dnskey.pubkey)
						.verify(&signed_data, &sig.signature)
						.map_err(|_| ValidationError::Invalid)?;
				},
				_ => return Err(ValidationError::UnsupportedAlgorithm),
			}

			return Ok(());
		}
	}
	Err(ValidationError::Invalid)
}

fn verify_dnskey_rrsig<'a, T, I>(sig: &RRSig, dses: T, records: Vec<&DnsKey>)
-> Result<(), ValidationError>
where T: IntoIterator<IntoIter = I>, I: Iterator<Item = &'a DS> + Clone {
	let mut validated_dnskeys = Vec::with_capacity(records.len());
	let dses = dses.into_iter();

	let mut had_known_digest_type = false;
	let mut had_ds = false;
	for ds in dses.clone() {
		had_ds = true;
		if ds.digest_type == 2 || ds.digest_type == 4 {
			had_known_digest_type = true;
			break;
		}
	}
	if !had_ds { return Err(ValidationError::Invalid); }
	if !had_known_digest_type { return Err(ValidationError::UnsupportedAlgorithm); }

	for dnskey in records.iter() {
		for ds in dses.clone() {
			if ds.digest_type != 2 && ds.digest_type != 4 { continue; }
			if ds.alg != dnskey.alg { continue; }
			if dnskey.key_tag() == ds.key_tag {
				let alg = match ds.digest_type {
					2 => &ring::digest::SHA256,
					4 => &ring::digest::SHA384,
					_ => continue,
				};
				let mut ctx = ring::digest::Context::new(alg);
				write_name(&mut ctx, &dnskey.name);
				ctx.update(&dnskey.flags.to_be_bytes());
				ctx.update(&dnskey.protocol.to_be_bytes());
				ctx.update(&dnskey.alg.to_be_bytes());
				ctx.update(&dnskey.pubkey);
				let hash = ctx.finish();
				if hash.as_ref() == &ds.digest {
					validated_dnskeys.push(*dnskey);
					break;
				}
			}
		}
	}
	verify_rrsig(sig, validated_dnskeys.iter().map(|k| *k), records)
}

/// Verifies the given set of resource records.
///
/// Given a set of arbitrary records, this attempts to validate DNSSEC data from the [`root_hints`]
/// through to any supported non-DNSSEC record types.
///
/// All records which could be validated are returned.
pub fn verify_rr_stream<'a>(inp: &'a [RR]) -> Result<Vec<&'a RR>, ValidationError> {
	let mut zone = ".";
	let mut res = Vec::new();
	let mut next_ds_set = None;
	'next_zone: while zone == "." || next_ds_set.is_some() {
		let mut found_unsupported_alg = false;
		for rrsig in inp.iter()
			.filter_map(|rr| if let RR::RRSig(sig) = rr { Some(sig) } else { None })
			.filter(|rrsig| rrsig.name.0 == zone && rrsig.ty == DnsKey::TYPE)
		{
			let dnskeys = inp.iter()
				.filter_map(|rr| if let RR::DnsKey(dnskey) = rr { Some(dnskey) } else { None })
				.filter(move |dnskey| dnskey.name.0 == zone);
			let dnskeys_verified = if zone == "." {
				verify_dnskey_rrsig(rrsig, &root_hints(), dnskeys.clone().collect())
			} else {
				debug_assert!(next_ds_set.is_some());
				if next_ds_set.is_none() { break 'next_zone; }
				verify_dnskey_rrsig(rrsig, next_ds_set.clone().unwrap(), dnskeys.clone().collect())
			};
			if dnskeys_verified.is_ok() {
				let mut last_validated_type = None;
				next_ds_set = None;
				for rrsig in inp.iter()
					.filter_map(|rr| if let RR::RRSig(sig) = rr { Some(sig) } else { None })
					.filter(move |rrsig| rrsig.key_name.0 == zone && rrsig.name.0 != zone)
				{
					if !rrsig.name.ends_with(zone) { return Err(ValidationError::Invalid); }
					if last_validated_type == Some(rrsig.ty) {
						// If we just validated all the RRs for this type, go ahead and skip it. We
						// may end up double-validating some RR Sets if there's multiple RRSigs for
						// the same sets interwoven with other RRSets, but that's okay.
						continue;
					}
					let signed_records = inp.iter()
						.filter(|rr| rr.name() == &rrsig.name && rr.ty() == rrsig.ty);
					verify_rrsig(rrsig, dnskeys.clone(), signed_records.clone().collect())?;
					match rrsig.ty {
						// RRSigs shouldn't cover child `DnsKey`s or other `RRSig`s
						RRSig::TYPE|DnsKey::TYPE => return Err(ValidationError::Invalid),
						DS::TYPE => {
							next_ds_set = Some(signed_records.filter_map(|rr|
								if let RR::DS(ds) = rr { Some(ds) }
								else { debug_assert!(false, "We already filtered by type"); None }));
							zone = &rrsig.name;
						},
						_ => {
							for record in signed_records { res.push(record); }
							last_validated_type = Some(rrsig.ty);
						},
					}
				}
				if next_ds_set.is_none() { break 'next_zone; }
				else { continue 'next_zone; }
			} else if dnskeys_verified == Err(ValidationError::UnsupportedAlgorithm) {
				// There may be redundant signatures by different keys, where one we don't supprt
				// and another we do. Ignore ones we don't support, but if there are no more,
				// return UnsupportedAlgorithm
				found_unsupported_alg = true;
			} else {
				// We don't explicitly handle invalid signatures here, instead we move on to the
				// next RRSig (if there is one) and return `Invalid` if no `RRSig`s match.
			}
		}
		// No RRSigs were able to verify our DnsKey set
		if found_unsupported_alg {
			return Err(ValidationError::UnsupportedAlgorithm);
		} else {
			return Err(ValidationError::Invalid);
		}
	}
	if res.is_empty() { Err(ValidationError::Invalid) }
	else { Ok(res) }
}

#[cfg(test)]
mod tests {
	use super::*;

	use hex_conservative::FromHex;
	use rand::seq::SliceRandom;

	fn root_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let dnskeys = vec![DnsKey {
			name: ".".try_into().unwrap(), flags: 256, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAentCcIEndLh2QSK+pHFq/PkKCwioxt75d7qNOUuTPMo0Fcte/NbwDPbocvbZ/eNb5RV/xQdapaJASQ/oDLsqzD0H1+JkHNuuKc2JLtpMxg4glSE4CnRXT2CnFTW5IwOREL+zeqZHy68OXy5ngW5KALbevRYRg/q2qFezRtCSQ0knmyPwgFsghVYLKwi116oxwEU5yZ6W7npWMxt5Z+Qs8diPNWrS5aXLgJtrWUGIIuFfuZwXYziGRP/z3o1EfMo9zZU19KLopkoLXX7Ls/diCXdSEdJXTtFA8w0/OKQviuJebfKscoElCTswukVZ1VX5gbaFEo2xWhHJ9Uo63wYaTk=").unwrap(),
		}, DnsKey {
			name: ".".try_into().unwrap(), flags: 257, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: ".".try_into().unwrap(), ty: DnsKey::TYPE, alg: 8, labels: 0, orig_ttl: 172800,
			expiration: 1708473600, inception: 1706659200, key_tag: 20326, key_name: ".".try_into().unwrap(),
			signature: base64::decode("ZO8LbjtwAiVkkBzOnGbiI/3ilGUPmmJpagsLSBVbIZRG6o/8a+hUZpIPTvk5ERZ1rAW4x0YxKAU8qtaHQpKIp3qYA6u97DYytVD7RdtXKHmGYAvR6QbD5eVTkCw1Sz705rJxbwt6+YM5OBweSUAy5Glo6JSQPDQwRDwj/bV2fLRhJbvfsBgxqaXJA0SaE/ceyvK8gB2NIaguTJNrztr2TENrHxi86OKOuHYDHthOW0TFoPfr19qj/P2eEC6dYniTVovUwHT7e+Hqrb05dJF4mI4ZjaIb5mFf8i5RehT1aRlnb3CLiwJ01bEjrRBo3xUn5I3PkCnglHhx3EvkO73OzA==").unwrap(),
		};
		let root_hints = root_hints();
		verify_dnskey_rrsig(&dnskey_rrsig, &root_hints, dnskeys.iter().collect()).unwrap();
		let rrs = vec![dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn com_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let root_dnskeys = root_dnskey().0;
		let mut com_ds = vec![DS {
			name: "com.".try_into().unwrap(), key_tag: 19718, alg: 13, digest_type: 2,
			digest: Vec::from_hex("8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "com.".try_into().unwrap(), ty: DS::TYPE, alg: 8, labels: 1, orig_ttl: 86400,
			expiration: 1708189200, inception: 1707062400, key_tag: 30903, key_name: ".".try_into().unwrap(),
			signature: base64::decode("vwMOBBwqRBdlmGZB+0FKfyMSignEtpYW9sD4TzPW2E+wdbF7O7epR5cmKmvcv0RUJdM0dGC/QmhCfgf/yqw1Xp7TpmPaYzaruW70hjGXZJO2nY3G6stUVe4S7lM2CzHL7nbbpaB5B+iSu6Ua9dZ+nyKrxfB7855HBLCLrHrkMGxWQiEPTallXXS8tEM1Y2XrsuzAQu2vZ2D2ClhFspFbPwwOdw+G6+NsZ8PnIfTkCj6DuKcgbdxjmGaYmw/6hVt9OU3kGCOBaJaEy4LrD8Kwzfu4S7axMwTKP4y4c5Y/E4k/mVAW0cuUtv549HaDfD2V0CvW1bDl6PqRkOiVsqM/lA==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &root_dnskeys, com_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "com.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("5i9qjJgyH+9MBz7VO269/srLQB/xRRllyUoVq8oLBZshPe4CGzDSFGnXAM3L/QPzB9ULpJuuy7jcxmBZ5Ebo7A==").unwrap(),
		}, DnsKey {
			name: "com.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("tx8EZRAd2+K/DJRV0S+hbBzaRPS/G6JVNBitHzqpsGlz8huE61Ms9ANe6NSDLKJtiTBqfTJWDAywEp1FCsEINQ==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "com.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 13, labels: 1, orig_ttl: 86400,
			expiration: 1707750155, inception: 1706453855, key_tag: 19718, key_name: "com.".try_into().unwrap(),
			signature: base64::decode("ZFGChM7QfJt0QSqVWerWnG5pMjpL1pXyJAmuHe8dHI/olmaNCxm+mqNHv9i3AploFY6JoNtiHmeBiC6zuFj/ZQ==").unwrap(),
		};
		verify_dnskey_rrsig(&dnskey_rrsig, &com_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![com_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn mattcorallo_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let com_dnskeys = com_dnskey().0;
		let mut mattcorallo_ds = vec![DS {
			name: "mattcorallo.com.".try_into().unwrap(), key_tag: 25630, alg: 13, digest_type: 2,
			digest: Vec::from_hex("DC608CA62BE89B3B9DB1593F9A59930D24FBA79D486E19C88A7792711EC00735").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "mattcorallo.com.".try_into().unwrap(), ty: DS::TYPE, alg: 13, labels: 2, orig_ttl: 86400,
			expiration: 1707631252, inception: 1707022252, key_tag: 4534, key_name: "com.".try_into().unwrap(),
			signature: base64::decode("M7Fk+CjfLz6hRsY5iSuw5bwc2OqlS3XtKH8FDs7lcbhEiR63n+DzOF0I8L+3k06SXFnE89uuofQECzWmAyef6Q==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &com_dnskeys, mattcorallo_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "mattcorallo.com.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("8BP51Etiu4V6cHvGCYqwNqCip4pvHChjEgkgG4zpdDvO9YRcTGuV/p71hAUut2/qEdxqXfUOT/082BJ/Z089DA==").unwrap(),
		}, DnsKey {
			name: "mattcorallo.com.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("AhUlQ8qk7413R0m4zKfTDHb/FQRlKag+ncGXxNxT+qTzSZTb9E5IGjo9VCEp6+IMqqpkd4GrXpN9AzDvlcU9Ig==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "mattcorallo.com.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 13, labels: 2, orig_ttl: 604800,
			expiration: 1708278650, inception: 1707063650, key_tag: 25630, key_name: "mattcorallo.com.".try_into().unwrap(),
			signature: base64::decode("nyVDwG+la8d5dyWgB7m+H3BQwCvTWLQ/kAqNruMzdLmn9B3VC9u/rvM/ortEu0WPbA1FZWJbRKpF1Ohkj3ltNw==").unwrap(),
		};
		verify_dnskey_rrsig(&dnskey_rrsig, &mattcorallo_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![mattcorallo_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn mattcorallo_txt_record() -> (Txt, RRSig) {
		let txt_resp = Txt {
			name: "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap(),
			data: "bitcoin:?b12=lno1qsgqmqvgm96frzdg8m0gc6nzeqffvzsqzrxqy32afmr3jn9ggkwg3egfwch2hy0l6jut6vfd8vpsc3h89l6u3dm4q2d6nuamav3w27xvdmv3lpgklhg7l5teypqz9l53hj7zvuaenh34xqsz2sa967yzqkylfu9xtcd5ymcmfp32h083e805y7jfd236w9afhavqqvl8uyma7x77yun4ehe9pnhu2gekjguexmxpqjcr2j822xr7q34p078gzslf9wpwz5y57alxu99s0z2ql0kfqvwhzycqq45ehh58xnfpuek80hw6spvwrvttjrrq9pphh0dpydh06qqspp5uq4gpyt6n9mwexde44qv7lstzzq60nr40ff38u27un6y53aypmx0p4qruk2tf9mjwqlhxak4znvna5y".to_owned().into_bytes(),
		};
		let txt_rrsig = RRSig {
			name: "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 3600, expiration: 1708123318,
			inception: 1706908318, key_tag: 47959, key_name: "mattcorallo.com.".try_into().unwrap(),
			signature: base64::decode("mgU6iwyMWO0w9nj2Gmt1+RmaIJIU3KO7DWVZiCD1bmU9e9zNefXCtnWOC2HtwjUsn/QYkWluvuSfYpBrt1IjpQ==").unwrap(),
		};
		(txt_resp, txt_rrsig)
	}

	#[test]
	fn check_txt_record() {
		let dnskeys = mattcorallo_dnskey().0;
		let (txt, txt_rrsig) = mattcorallo_txt_record();
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_txt_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in com_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in mattcorallo_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txt, txt_rrsig) = mattcorallo_txt_record();
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert_eq!(verified_rrs.len(), 1);
		if let RR::Txt(txt) = &verified_rrs[0] {
			assert_eq!(txt.name.0, "matt.user._bitcoin-payment.mattcorallo.com.");
			assert_eq!(txt.data, b"bitcoin:?b12=lno1qsgqmqvgm96frzdg8m0gc6nzeqffvzsqzrxqy32afmr3jn9ggkwg3egfwch2hy0l6jut6vfd8vpsc3h89l6u3dm4q2d6nuamav3w27xvdmv3lpgklhg7l5teypqz9l53hj7zvuaenh34xqsz2sa967yzqkylfu9xtcd5ymcmfp32h083e805y7jfd236w9afhavqqvl8uyma7x77yun4ehe9pnhu2gekjguexmxpqjcr2j822xr7q34p078gzslf9wpwz5y57alxu99s0z2ql0kfqvwhzycqq45ehh58xnfpuek80hw6spvwrvttjrrq9pphh0dpydh06qqspp5uq4gpyt6n9mwexde44qv7lstzzq60nr40ff38u27un6y53aypmx0p4qruk2tf9mjwqlhxak4znvna5y");
		} else { panic!(); }
	}

	#[test]
	fn rfc9102_parse_test() {
		// Note that this is the `AuthenticationChain` field only, and ignores the
		// `ExtSupportLifetime` field (stripping the top two 0 bytes from the front).
let rfc9102_test_vector = Vec::from_hex("045f343433045f74637003777777076578616d706c6503636f6d000034000100000e1000230301018bd1da95272f7fa4ffb24137fc0ed03aae67e5c4d8b3c50734e1050a7920b922045f343433045f74637003777777076578616d706c6503636f6d00002e000100000e10005f00340d0500000e105fc6d9005bfdda80074e076578616d706c6503636f6d00ce1d3adeb7dc7cee656d61cfb472c5977c8c9caeae9b765155c518fb107b6a1fe0355fbaaf753c192832fa621fa73a8b85ed79d374117387598fcc812e1ef3fb076578616d706c6503636f6d000030000100000e1000440101030d2670355e0c894d9cfea6c5af6eb7d458b57a50ba88272512d8241d8541fd54adf96ec956789a51ceb971094b3bb3f4ec49f64c686595be5b2e89e8799c7717cc076578616d706c6503636f6d00002e000100000e10005f00300d0200000e105fc6d9005bfdda80074e076578616d706c6503636f6d004628383075b8e34b743a209b27ae148d110d4e1a246138a91083249cb4a12a2d9bc4c2d7ab5eb3afb9f5d1037e4d5da8339c162a9298e9be180741a8ca74accc076578616d706c6503636f6d00002b00010002a3000024074e0d02e9b533a049798e900b5c29c90cd25a986e8a44f319ac3cd302bafc08f5b81e16076578616d706c6503636f6d00002e00010002a3000057002b0d020002a3005fc6d9005bfdda80861703636f6d00a203e704a6facbeb13fc9384fdd6de6b50de5659271f38ce81498684e6363172d47e2319fdb4a22a58a231edc2f1ff4fb2811a1807be72cb5241aa26fdaee03903636f6d00003000010002a30000440100030dec8204e43a25f2348c52a1d3bce3a265aa5d11b43dc2a471162ff341c49db9f50a2e1a41caf2e9cd20104ea0968f7511219f0bdc56b68012cc3995336751900b03636f6d00003000010002a30000440101030d45b91c3bef7a5d99a7a7c8d822e33896bc80a777a04234a605a4a8880ec7efa4e6d112c73cd3d4c65564fa74347c873723cc5f643370f166b43dedff836400ff03636f6d00003000010002a30000440101030db3373b6e22e8e49e0e1e591a9f5bd9ac5e1a0f86187fe34703f180a9d36c958f71c4af48ce0ebc5c792a724e11b43895937ee53404268129476eb1aed323939003636f6d00002e00010002a300005700300d010002a3005fc6d9005bfdda8049f303636f6d0018a948eb23d44f80abc99238fcb43c5a18debe57004f7343593f6deb6ed71e04654a433f7aa1972130d9bd921c73dcf63fcf665f2f05a0aaebafb059dc12c96503636f6d00002e00010002a300005700300d010002a3005fc6d9005bfdda80708903636f6d006170e6959bd9ed6e575837b6f580bd99dbd24a44682b0a359626a246b1812f5f9096b75e157e77848f068ae0085e1a609fc19298c33b736863fbccd4d81f5eb203636f6d00002b000100015180002449f30d0220f7a9db42d0e2042fbbb9f9ea015941202f9eabb94487e658c188e7bcb5211503636f6d00002b000100015180002470890d02ad66b3276f796223aa45eda773e92c6d98e70643bbde681db342a9e5cf2bb38003636f6d00002e0001000151800053002b0d01000151805fc6d9005bfdda807cae00122e276d45d9e9816f7922ad6ea2e73e82d26fce0a4b718625f314531ac92f8ae82418df9b898f989d32e80bc4deaba7c4a7c8f172adb57ced7fb5e77a784b0700003000010001518000440100030dccacfe0c25a4340fefba17a254f706aac1f8d14f38299025acc448ca8ce3f561f37fc3ec169fe847c8fcbe68e358ff7c71bb5ee1df0dbe518bc736d4ce8dfe1400003000010001518000440100030df303196789731ddc8a6787eff24cacfeddd032582f11a75bb1bcaa5ab321c1d7525c2658191aec01b3e98ab7915b16d571dd55b4eae51417110cc4cdd11d171100003000010001518000440101030dcaf5fe54d4d48f16621afb6bd3ad2155bacf57d1faad5bac42d17d948c421736d9389c4c4011666ea95cf17725bd0fa00ce5e714e4ec82cfdfacc9b1c863ad4600002e000100015180005300300d00000151805fc6d9005bfdda80b79d00de7a6740eeecba4bda1e5c2dd4899b2c965893f3786ce747f41e50d9de8c0a72df82560dfb48d714de3283ae99a49c0fcb50d3aaadb1a3fc62ee3a8a0988b6be").unwrap();

		let mut rrs = parse_rr_stream(&rfc9102_test_vector).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert_eq!(verified_rrs.len(), 1);
		if let RR::TLSA(tlsa) = &verified_rrs[0] {
			assert_eq!(tlsa.cert_usage, 3);
			assert_eq!(tlsa.selector, 1);
			assert_eq!(tlsa.data_ty, 1);
			assert_eq!(tlsa.data, Vec::from_hex("8bd1da95272f7fa4ffb24137fc0ed03aae67e5c4d8b3c50734e1050a7920b922").unwrap());
		} else { panic!(); }
	}
}

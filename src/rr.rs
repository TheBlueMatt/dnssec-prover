//! Resource Records are the fundamental type in the DNS - individual records mapping a name to
//! some data.
//!
//! This module holds structs and utilities for the Resource Records supported by this crate.

use alloc::vec::Vec;
use alloc::string::String;
use alloc::borrow::ToOwned;

use crate::ser::*;

/// A valid domain name.
///
/// It must end with a ".", be no longer than 255 bytes, consist of only printable ASCII
/// characters and each label may be no longer than 63 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name(String);
impl Name {
	/// Gets the underlying human-readable domain name
	pub fn as_str(&self) -> &str { &self.0 }
}
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
	/// An IPv4 resource record
	A(A),
	/// An IPv6 resource record
	AAAA(AAAA),
	/// A name server resource record
	NS(NS),
	/// A text resource record
	Txt(Txt),
	/// A TLS Certificate Association resource record
	TLSA(TLSA),
	/// A Canonical Name record
	CName(CName),
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
			RR::A(rr) => &rr.name,
			RR::AAAA(rr) => &rr.name,
			RR::NS(rr) => &rr.name,
			RR::Txt(rr) => &rr.name,
			RR::CName(rr) => &rr.name,
			RR::TLSA(rr) => &rr.name,
			RR::DnsKey(rr) => &rr.name,
			RR::DS(rr) => &rr.name,
			RR::RRSig(rr) => &rr.name,
		}
	}
	fn ty(&self) -> u16 {
		match self {
			RR::A(_) => A::TYPE,
			RR::AAAA(_) => AAAA::TYPE,
			RR::NS(_) => NS::TYPE,
			RR::Txt(_) => Txt::TYPE,
			RR::CName(_) => CName::TYPE,
			RR::TLSA(_) => TLSA::TYPE,
			RR::DnsKey(_) => DnsKey::TYPE,
			RR::DS(_) => DS::TYPE,
			RR::RRSig(_) => RRSig::TYPE,
		}
	}
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		match self {
			RR::A(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::AAAA(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::NS(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::Txt(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::CName(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::TLSA(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::DnsKey(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::DS(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::RRSig(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
		}
	}
}
impl From<A> for RR { fn from(a: A) -> RR { RR::A(a) } }
impl From<AAAA> for RR { fn from(aaaa: AAAA) -> RR { RR::AAAA(aaaa) } }
impl From<NS> for RR { fn from(ns: NS) -> RR { RR::NS(ns) } }
impl From<Txt> for RR { fn from(txt: Txt) -> RR { RR::Txt(txt) } }
impl From<CName> for RR { fn from(cname: CName) -> RR { RR::CName(cname) } }
impl From<TLSA> for RR { fn from(tlsa: TLSA) -> RR { RR::TLSA(tlsa) } }
impl From<DnsKey> for RR { fn from(dnskey: DnsKey) -> RR { RR::DnsKey(dnskey) } }
impl From<DS> for RR { fn from(ds: DS) -> RR { RR::DS(ds) } }
impl From<RRSig> for RR { fn from(rrsig: RRSig) -> RR { RR::RRSig(rrsig) } }

pub(crate) trait StaticRecord : Ord + Sized {
	// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
	const TYPE: u16;
	fn name(&self) -> &Name;
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>);
	fn read_from_data(name: Name, data: &[u8], wire_packet: &[u8]) -> Result<Self, ()>;
}
/// A trait describing a resource record (including the [`RR`] enum).
pub trait Record : Ord {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)] // TODO: ord is wrong cause need to consider len first, maybe
/// A text resource record, containing arbitrary text data
pub struct Txt {
	/// The name this record is at.
	pub name: Name,
	/// The text record itself.
	///
	/// While this is generally UTF-8-valid, there is no specific requirement that it be, and thus
	/// is an arbitrary series of bytes here.
	pub data: Vec<u8>,
}
impl StaticRecord for Txt {
	const TYPE: u16 = 16;
	fn name(&self) -> &Name { &self.name }
	fn read_from_data(name: Name, mut data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		let mut parsed_data = Vec::with_capacity(data.len() - 1);
		while !data.is_empty() {
			let len = read_u8(&mut data)? as usize;
			if data.len() < len { return Err(()); }
			parsed_data.extend_from_slice(&data[..len]);
			data = &data[len..];
		}
		Ok(Txt { name, data: parsed_data })
	}
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
	fn read_from_data(name: Name, mut data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		Ok(TLSA {
			name, cert_usage: read_u8(&mut data)?, selector: read_u8(&mut data)?,
			data_ty: read_u8(&mut data)?, data: data.to_vec(),
		})
	}
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		let len = 3 + self.data.len();
		out.extend_from_slice(&(len as u16).to_be_bytes());
		out.extend_from_slice(&[self.cert_usage, self.selector, self.data_ty]);
		out.extend_from_slice(&self.data);
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A Canonical Name resource record, referring all queries for this name to another name.
pub struct CName {
	/// The name this record is at.
	pub name: Name,
	/// The canonical name.
	///
	/// A resolver should use this name when looking up any further records for [`Self::name`].
	pub canonical_name: Name,
}
impl StaticRecord for CName {
	const TYPE: u16 = 5;
	fn name(&self) -> &Name { &self.name }
	fn read_from_data(name: Name, mut data: &[u8], wire_packet: &[u8]) -> Result<Self, ()> {
		Ok(CName { name, canonical_name: read_wire_packet_name(&mut data, wire_packet)? })
	}
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		let len: u16 = name_len(&self.canonical_name);
		out.extend_from_slice(&len.to_be_bytes());
		write_name(out, &self.canonical_name);
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
	fn read_from_data(name: Name, mut data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		Ok(DnsKey {
			name, flags: read_u16(&mut data)?, protocol: read_u8(&mut data)?,
			alg: read_u8(&mut data)?, pubkey: data.to_vec(),
		})
	}
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
	fn read_from_data(name: Name, mut data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		Ok(DS {
			name, key_tag: read_u16(&mut data)?, alg: read_u8(&mut data)?,
			digest_type: read_u8(&mut data)?, digest: data.to_vec(),
		})
	}
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
	fn read_from_data(name: Name, mut data: &[u8], wire_packet: &[u8]) -> Result<Self, ()> {
		Ok(RRSig {
			name, ty: read_u16(&mut data)?, alg: read_u8(&mut data)?,
			labels: read_u8(&mut data)?, orig_ttl: read_u32(&mut data)?,
			expiration: read_u32(&mut data)?, inception: read_u32(&mut data)?,
			key_tag: read_u16(&mut data)?,
			key_name: read_wire_packet_name(&mut data, wire_packet)?,
			signature: data.to_vec(),
		})
	}
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// An IPv4 Address resource record
pub struct A {
	/// The name this record is at.
	pub name: Name,
	/// The bytes of the IPv4 address.
	pub address: [u8; 4],
}
impl StaticRecord for A {
	const TYPE: u16 = 1;
	fn name(&self) -> &Name { &self.name }
	fn read_from_data(name: Name, data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		if data.len() != 4 { return Err(()); }
		let mut address = [0; 4];
		address.copy_from_slice(&data);
		Ok(A { name, address })
	}
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		out.extend_from_slice(&4u16.to_be_bytes());
		out.extend_from_slice(&self.address);
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// An IPv6 Address resource record
pub struct AAAA {
	/// The name this record is at.
	pub name: Name,
	/// The bytes of the IPv6 address.
	pub address: [u8; 16],
}
impl StaticRecord for AAAA {
	const TYPE: u16 = 28;
	fn name(&self) -> &Name { &self.name }
	fn read_from_data(name: Name, data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		if data.len() != 16 { return Err(()); }
		let mut address = [0; 16];
		address.copy_from_slice(&data);
		Ok(AAAA { name, address })
	}
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		out.extend_from_slice(&16u16.to_be_bytes());
		out.extend_from_slice(&self.address);
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A Name Server resource record, which indicates the server responsible for handling queries for
/// a zone.
pub struct NS {
	/// The name this record is at.
	///
	/// This is also the zone which the server at [`Self::name_server`] is responsible for handling
	/// queries for.
	pub name: Name,
	/// The name of the server which is responsible for handling queries for the [`Self::name`]
	/// zone.
	pub name_server: Name,
}
impl StaticRecord for NS {
	const TYPE: u16 = 2;
	fn name(&self) -> &Name { &self.name }
	fn read_from_data(name: Name, mut data: &[u8], wire_packet: &[u8]) -> Result<Self, ()> {
		Ok(NS { name, name_server: read_wire_packet_name(&mut data, wire_packet)? })
	}
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		out.extend_from_slice(&name_len(&self.name_server).to_be_bytes());
		write_name(out, &self.name_server);
	}
}

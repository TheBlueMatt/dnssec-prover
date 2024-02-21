//! Resource Records are the fundamental type in the DNS - individual records mapping a name to
//! some data.
//!
//! This module holds structs and utilities for the Resource Records supported by this crate.

use alloc::vec::Vec;
use alloc::string::String;
use alloc::borrow::ToOwned;
use alloc::format;

use core::cmp::{self, Ordering};
use core::fmt;
use core::fmt::Write;

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
	/// Gets the number of labels in this name
	pub fn labels(&self) -> u8 {
		if self.as_str() == "." {
			0
		} else {
			self.as_str().chars().filter(|c| *c == '.').count() as u8
		}
	}
	/// Gets a string containing the last `n` labels in this [`Name`] (which is also a valid name).
	pub fn trailing_n_labels(&self, n: u8) -> Option<&str> {
		let labels = self.labels();
		if n > labels {
			None
		} else if n == labels {
			Some(self.as_str())
		} else if n == 0 {
			Some(".")
		} else {
			self.as_str().splitn(labels as usize - n as usize + 1, ".").last()
		}
	}
}
impl core::ops::Deref for Name {
	type Target = str;
	fn deref(&self) -> &str { &self.0 }
}
impl fmt::Display for Name {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		self.0.fmt(f)
	}
}
impl TryFrom<String> for Name {
	type Error = ();
	fn try_from(s: String) -> Result<Name, ()> {
		if s.is_empty() { return Err(()); }
		if *s.as_bytes().last().unwrap_or(&0) != b"."[0] { return Err(()); }
		if s.len() > 255 { return Err(()); }
		if s.chars().any(|c| !c.is_ascii_graphic() || c == '"') { return Err(()); }
		for label in s.split(".") {
			if label.len() > 63 { return Err(()); }
		}

		Ok(Name(s.to_ascii_lowercase()))
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
	/// A Delegation Name record
	DName(DName),
	/// A DNS (Public) Key resource record
	DnsKey(DnsKey),
	/// A Delegated Signer resource record
	DS(DS),
	/// A Resource Record Signature record
	RRSig(RRSig),
	/// A Next Secure Record record
	NSec(NSec),
	/// A Next Secure Record version 3 record
	NSec3(NSec3),
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
			RR::DName(rr) => &rr.name,
			RR::TLSA(rr) => &rr.name,
			RR::DnsKey(rr) => &rr.name,
			RR::DS(rr) => &rr.name,
			RR::RRSig(rr) => &rr.name,
			RR::NSec(rr) => &rr.name,
			RR::NSec3(rr) => &rr.name,
		}
	}
	/// Gets a JSON encoding of this record
	pub fn json(&self) -> String {
		match self {
			RR::A(rr) => StaticRecord::json(rr),
			RR::AAAA(rr) => StaticRecord::json(rr),
			RR::NS(rr) => StaticRecord::json(rr),
			RR::Txt(rr) => StaticRecord::json(rr),
			RR::CName(rr) => StaticRecord::json(rr),
			RR::DName(rr) => StaticRecord::json(rr),
			RR::TLSA(rr) => StaticRecord::json(rr),
			RR::DnsKey(rr) => StaticRecord::json(rr),
			RR::DS(rr) => StaticRecord::json(rr),
			RR::RRSig(rr) => StaticRecord::json(rr),
			RR::NSec(rr) => StaticRecord::json(rr),
			RR::NSec3(rr) => StaticRecord::json(rr),
		}
	}
	fn ty(&self) -> u16 {
		match self {
			RR::A(_) => A::TYPE,
			RR::AAAA(_) => AAAA::TYPE,
			RR::NS(_) => NS::TYPE,
			RR::Txt(_) => Txt::TYPE,
			RR::CName(_) => CName::TYPE,
			RR::DName(_) => DName::TYPE,
			RR::TLSA(_) => TLSA::TYPE,
			RR::DnsKey(_) => DnsKey::TYPE,
			RR::DS(_) => DS::TYPE,
			RR::RRSig(_) => RRSig::TYPE,
			RR::NSec(_) => NSec::TYPE,
			RR::NSec3(_) => NSec3::TYPE,
		}
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		match self {
			RR::A(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::AAAA(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::NS(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::Txt(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::CName(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::DName(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::TLSA(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::DnsKey(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::DS(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::RRSig(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::NSec(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
			RR::NSec3(rr) => StaticRecord::write_u16_len_prefixed_data(rr, out),
		}
	}
	fn ty_to_rr_name(ty: u16) -> Option<&'static str> {
		match ty {
			A::TYPE => Some("A"),
			AAAA::TYPE => Some("AAAA"),
			NS::TYPE => Some("NS"),
			Txt::TYPE => Some("TXT"),
			CName::TYPE => Some("CNAME"),
			DName::TYPE => Some("DNAME"),
			TLSA::TYPE => Some("TLSA"),
			DnsKey::TYPE => Some("DNSKEY"),
			DS::TYPE => Some("DS"),
			RRSig::TYPE => Some("RRSIG"),
			NSec::TYPE => Some("NSEC"),
			NSec3::TYPE => Some("NSEC3"),
			_ => None,
		}
	}
}
impl From<A> for RR { fn from(a: A) -> RR { RR::A(a) } }
impl From<AAAA> for RR { fn from(aaaa: AAAA) -> RR { RR::AAAA(aaaa) } }
impl From<NS> for RR { fn from(ns: NS) -> RR { RR::NS(ns) } }
impl From<Txt> for RR { fn from(txt: Txt) -> RR { RR::Txt(txt) } }
impl From<CName> for RR { fn from(cname: CName) -> RR { RR::CName(cname) } }
impl From<DName> for RR { fn from(cname: DName) -> RR { RR::DName(cname) } }
impl From<TLSA> for RR { fn from(tlsa: TLSA) -> RR { RR::TLSA(tlsa) } }
impl From<DnsKey> for RR { fn from(dnskey: DnsKey) -> RR { RR::DnsKey(dnskey) } }
impl From<DS> for RR { fn from(ds: DS) -> RR { RR::DS(ds) } }
impl From<RRSig> for RR { fn from(rrsig: RRSig) -> RR { RR::RRSig(rrsig) } }
impl From<NSec> for RR { fn from(nsec: NSec) -> RR { RR::NSec(nsec) } }
impl From<NSec3> for RR { fn from(nsec3: NSec3) -> RR { RR::NSec3(nsec3) } }

pub(crate) trait StaticRecord : Ord + Sized {
	// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
	const TYPE: u16;
	fn name(&self) -> &Name;
	fn json(&self) -> String;
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W);
	fn read_from_data(name: Name, data: &[u8], wire_packet: &[u8]) -> Result<Self, ()>;
}

/// A record that can be written to a generic [`Writer`]
pub(crate) trait WriteableRecord : Record {
	fn serialize_u16_len_prefixed<W: Writer>(&self, out: &mut W);
}
impl<RR: StaticRecord> WriteableRecord for RR {
	fn serialize_u16_len_prefixed<W: Writer>(&self, out: &mut W) {
		RR::write_u16_len_prefixed_data(self, out)
	}
}
impl WriteableRecord for RR {
	fn serialize_u16_len_prefixed<W: Writer>(&self, out: &mut W) {
		RR::write_u16_len_prefixed_data(self, out)
	}
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
	/// Gets a JSON encoding of this record.
	fn json(&self) -> String;
	/// Writes the data of this record, prefixed by a u16 length, to the given `Vec`.
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>);
}
impl<RR: StaticRecord> Record for RR {
	fn ty(&self) -> u16 { RR::TYPE }
	fn name(&self) -> &Name { RR::name(self) }
	fn json(&self) -> String { RR::json(self) }
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		RR::write_u16_len_prefixed_data(self, out)
	}
}
impl Record for RR {
	fn ty(&self) -> u16 { self.ty() }
	fn name(&self) -> &Name { self.name() }
	fn json(&self) -> String { self.json() }
	fn write_u16_len_prefixed_data(&self, out: &mut Vec<u8>) {
		self.write_u16_len_prefixed_data(out)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Ord)]
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
/// The wire type for TXT records
pub const TXT_TYPE: u16 = 16;
impl PartialOrd for Txt {
	fn partial_cmp(&self, o: &Txt) -> Option<Ordering> {
		Some(self.name.cmp(&o.name)
			.then_with(|| {
				// Compare in wire encoding form, i.e. compare in 255-byte chunks
				for i in 1..(self.data.len() / 255) + 2 {
					let start = (i - 1)*255;
					let self_len = cmp::min(i * 255, self.data.len());
					let o_len = cmp::min(i * 255, o.data.len());
					let slice_cmp = self_len.cmp(&o_len)
						.then_with(|| self.data[start..self_len].cmp(&o.data[start..o_len]));
					if !slice_cmp.is_eq() { return slice_cmp; }
				}
				Ordering::Equal
			}))
	}
}
impl StaticRecord for Txt {
	const TYPE: u16 = TXT_TYPE;
	fn name(&self) -> &Name { &self.name }
	fn json(&self) -> String {
		if let Ok(s) = core::str::from_utf8(&self.data) {
			if s.chars().all(|c| !c.is_control() && c != '"' && c != '\\') {
				return format!("{{\"type\":\"txt\",\"name\":\"{}\",\"contents\":\"{}\"}}", self.name.0, s);
			}
		}
		format!("{{\"type\":\"txt\",\"name\":\"{}\",\"contents\":{:?}}}", self.name.0, &self.data[..])
	}
	fn read_from_data(name: Name, mut data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		let mut parsed_data = Vec::with_capacity(data.len().saturating_sub(1));
		while !data.is_empty() {
			let len = read_u8(&mut data)? as usize;
			if data.len() < len { return Err(()); }
			parsed_data.extend_from_slice(&data[..len]);
			data = &data[len..];
		}
		debug_assert!(data.is_empty());
		Ok(Txt { name, data: parsed_data })
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		let len = (self.data.len() + (self.data.len() + 254) / 255) as u16;
		out.write(&len.to_be_bytes());

		let mut data_write = &self.data[..];
		out.write(&[data_write.len().try_into().unwrap_or(255)]);
		while !data_write.is_empty() {
			let split_pos = core::cmp::min(255, data_write.len());
			out.write(&data_write[..split_pos]);
			data_write = &data_write[split_pos..];
			if !data_write.is_empty() {
				out.write(&[data_write.len().try_into().unwrap_or(255)]);
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
/// The wire type for TLSA records
pub const TLSA_TYPE: u16 = 52;
impl StaticRecord for TLSA {
	const TYPE: u16 = TLSA_TYPE;
	fn name(&self) -> &Name { &self.name }
	fn json(&self) -> String {
		let mut out = String::with_capacity(128+self.data.len()*2);
		write!(&mut out,
			"{{\"type\":\"tlsa\",\"name\":\"{}\",\"usage\":{},\"selector\":{},\"data_ty\":{},\"data\":\"",
			self.name.0, self.cert_usage, self.selector, self.data_ty
		).expect("Write to a String shouldn't fail");
		for c in self.data.iter() {
			write!(&mut out, "{:02X}", c)
				.expect("Write to a String shouldn't fail");
		}
		out += "\"}";
		out
	}
	fn read_from_data(name: Name, mut data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		Ok(TLSA {
			name, cert_usage: read_u8(&mut data)?, selector: read_u8(&mut data)?,
			data_ty: read_u8(&mut data)?, data: data.to_vec(),
		})
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		let len = 3 + self.data.len();
		out.write(&(len as u16).to_be_bytes());
		out.write(&[self.cert_usage, self.selector, self.data_ty]);
		out.write(&self.data);
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A Canonical Name resource record, referring all queries for this name to another name.
pub struct CName {
	/// The name this record is at.
	pub name: Name,
	/// The canonical name.
	///
	/// A resolver should use this name when looking up any further records for [`self.name`].
	pub canonical_name: Name,
}
impl StaticRecord for CName {
	const TYPE: u16 = 5;
	fn name(&self) -> &Name { &self.name }
	fn json(&self) -> String {
		format!("{{\"type\":\"cname\",\"name\":\"{}\",\"canonical_name\":\"{}\"}}",
			self.name.0, self.canonical_name.0)
	}
	fn read_from_data(name: Name, mut data: &[u8], wire_packet: &[u8]) -> Result<Self, ()> {
		let res = CName { name, canonical_name: read_wire_packet_name(&mut data, wire_packet)? };
		debug_assert!(data.is_empty());
		Ok(res)
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		let len: u16 = name_len(&self.canonical_name);
		out.write(&len.to_be_bytes());
		write_name(out, &self.canonical_name);
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A Delegation Name resource record, referring all queries for subdomains of this name to another
/// subtree of the DNS.
pub struct DName {
	/// The name this record is at.
	pub name: Name,
	/// The delegation name.
	///
	/// A resolver should use this domain name tree when looking up any further records for
	/// subdomains of [`self.name`].
	pub delegation_name: Name,
}
impl StaticRecord for DName {
	const TYPE: u16 = 39;
	fn name(&self) -> &Name { &self.name }
	fn json(&self) -> String {
		format!("{{\"type\":\"dname\",\"name\":\"{}\",\"delegation_name\":\"{}\"}}",
			self.name.0, self.delegation_name.0)
	}
	fn read_from_data(name: Name, mut data: &[u8], wire_packet: &[u8]) -> Result<Self, ()> {
		let res = DName { name, delegation_name: read_wire_packet_name(&mut data, wire_packet)? };
		debug_assert!(data.is_empty());
		Ok(res)
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		let len: u16 = name_len(&self.delegation_name);
		out.write(&len.to_be_bytes());
		write_name(out, &self.delegation_name);
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
	fn json(&self) -> String {
		let mut out = String::with_capacity(128+self.pubkey.len()*2);
		write!(&mut out,
			"{{\"type\":\"dnskey\",\"name\":\"{}\",\"flags\":{},\"protocol\":{},\"alg\":{},\"pubkey\":\"",
			self.name.0, self.flags, self.protocol, self.alg
		).expect("Write to a String shouldn't fail");
		for c in self.pubkey.iter() {
			write!(&mut out, "{:02X}", c)
				.expect("Write to a String shouldn't fail");
		}
		out += "\"}";
		out
	}
	fn read_from_data(name: Name, mut data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		Ok(DnsKey {
			name, flags: read_u16(&mut data)?, protocol: read_u8(&mut data)?,
			alg: read_u8(&mut data)?, pubkey: data.to_vec(),
		})
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		let len = 2 + 1 + 1 + self.pubkey.len();
		out.write(&(len as u16).to_be_bytes());
		out.write(&self.flags.to_be_bytes());
		out.write(&self.protocol.to_be_bytes());
		out.write(&self.alg.to_be_bytes());
		out.write(&self.pubkey);
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
/// for records in the zone which matches [`self.name`].
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
	fn json(&self) -> String {
		let mut out = String::with_capacity(128+self.digest.len()*2);
		write!(&mut out,
			"{{\"type\":\"ds\",\"name\":\"{}\",\"key_tag\":{},\"alg\":{},\"digest_type\":{},\"digest\":\"",
			self.name.0, self.key_tag, self.alg, self.digest_type
		).expect("Write to a String shouldn't fail");
		for c in self.digest.iter() {
			write!(&mut out, "{:02X}", c)
				.expect("Write to a String shouldn't fail");
		}
		out += "\"}";
		out
	}
	fn read_from_data(name: Name, mut data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		Ok(DS {
			name, key_tag: read_u16(&mut data)?, alg: read_u8(&mut data)?,
			digest_type: read_u8(&mut data)?, digest: data.to_vec(),
		})
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		let len = 2 + 1 + 1 + self.digest.len();
		out.write(&(len as u16).to_be_bytes());
		out.write(&self.key_tag.to_be_bytes());
		out.write(&self.alg.to_be_bytes());
		out.write(&self.digest_type.to_be_bytes());
		out.write(&self.digest);
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
	/// All resources records of this type at the same name as [`self.name`] must be signed by
	/// this [`RRSig`].
	pub ty: u16,
	/// The algorithm which is being used to sign.
	///
	/// This must match the [`DnsKey::alg`] field in the [`DnsKey`] being used to sign.
	pub alg: u8,
	/// The number of labels in the name of the records that this signature is signing.
	///
	/// If this is less than the number of labels in [`self.name`], this signature is covering a
	/// wildcard entry.
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
	/// This must be a parent of [`self.name`].
	///
	/// [`DnsKey::name`]: Record::name
	// We'd like to just link to the `DnsKey` member variable called `name`, but there doesn't
	// appear to be a way to actually do that, so instead we have to link to the trait method.
	pub key_name: Name,
	/// The signature itself.
	pub signature: Vec<u8>,
}
impl StaticRecord for RRSig {
	const TYPE: u16 = 46;
	fn name(&self) -> &Name { &self.name }
	fn json(&self) -> String {
		let mut out = String::with_capacity(256 + self.signature.len()*2);
		write!(&mut out,
			"{{\"type\":\"ds\",\"name\":\"{}\",\"signed_record_type\":{},\"alg\":{},\"signed_labels\":{},\"orig_ttl\":{},\"expiration\"{},\"inception\":{},\"key_tag\":{},\"key_name\":\"{}\",\"signature\":\"",
			self.name.0, self.ty, self.alg, self.labels, self.orig_ttl, self.expiration, self.inception, self.key_tag, self.key_name.0
		).expect("Write to a String shouldn't fail");
		for c in self.signature.iter() {
			write!(&mut out, "{:02X}", c)
				.expect("Write to a String shouldn't fail");
		}
		out += "\"}";
		out
	}
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
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		let len = 2 + 1 + 1 + 4*3 + 2 + name_len(&self.key_name) + self.signature.len() as u16;
		out.write(&len.to_be_bytes());
		out.write(&self.ty.to_be_bytes());
		out.write(&self.alg.to_be_bytes());
		out.write(&self.labels.to_be_bytes());
		out.write(&self.orig_ttl.to_be_bytes());
		out.write(&self.expiration.to_be_bytes());
		out.write(&self.inception.to_be_bytes());
		out.write(&self.key_tag.to_be_bytes());
		write_name(out, &self.key_name);
		out.write(&self.signature);
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A mask used in [`NSec`] and [`NSec3`] records which indicates the resource record types which
/// exist at the (hash of the) name described in [`Record::name`].
pub struct NSecTypeMask([u8; 8192]);
impl NSecTypeMask {
	/// Constructs a new, empty, type mask.
	pub fn new() -> Self { Self([0; 8192]) }
	/// Builds a new type mask with the given types set
	pub fn from_types(types: &[u16]) -> Self {
		let mut flags = [0; 8192];
		for t in types {
			flags[*t as usize >> 3] |= 1 << (7 - (*t as usize % 8));
		}
		let res = Self(flags);
		for t in types {
			debug_assert!(res.contains_type(*t));
		}
		res
	}
	/// Checks if the given type (from [`Record::ty`]) is set, indicating a record of this type
	/// exists.
	pub fn contains_type(&self, ty: u16) -> bool {
		let f = self.0[(ty >> 3) as usize];
		// DNSSEC's bit fields are in wire order, so the high bit is type 0, etc.
		f & (1 << (7 - (ty % 8))) != 0
	}
	fn write_json(&self, s: &mut String) {
		*s += "[";
		let mut have_written = false;
		for (idx, mask) in self.0.iter().enumerate() {
			if *mask == 0 { continue; }
			for b in 0..8 {
				if *mask & (1 << b) != 0 {
					if have_written {
						*s += ",";
					}
					have_written = true;
					let ty = ((idx as u16) << 3) | (7 - b);
					match RR::ty_to_rr_name(ty) {
						Some(name) => write!(s, "\"{}\"", name).expect("Writes to a string shouldn't fail"),
						_ => write!(s, "{}", ty).expect("Writes to a string shouldn't fail"),
					}
				}
			}
		}
		*s += "]";
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A Next Secure Record resource record. This indicates a range of possible names for which there
/// is no such record.
pub struct NSec {
	/// The name this record is at.
	pub name: Name,
	/// The next name which contains a record. There are no names between `name` and
	/// [`Self::next_name`].
	pub next_name: Name,
	/// The set of record types which exist at `name`. Any other record types do not exist at
	/// `name`.
	pub types: NSecTypeMask,
}
impl StaticRecord for NSec {
	const TYPE: u16 = 47;
	fn name(&self) -> &Name { &self.name }
	fn json(&self) -> String {
		let mut out = String::with_capacity(256 + self.next_name.len());
		write!(&mut out,
			"{{\"type\":\"nsec\",\"name\":\"{}\",\"next_name\":\"{}\",\"types\":",
			self.name.0, self.next_name.0,
		).expect("Write to a String shouldn't fail");
		self.types.write_json(&mut out);
		out += "}";
		out
	}
	fn read_from_data(name: Name, mut data: &[u8], wire_packet: &[u8]) -> Result<Self, ()> {
		let res = NSec {
			name, next_name: read_wire_packet_name(&mut data, wire_packet)?,
			types: NSecTypeMask(read_nsec_types_bitmap(&mut data)?),
		};
		debug_assert!(data.is_empty());
		Ok(res)
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		let len = name_len(&self.next_name) + nsec_types_bitmap_len(&self.types.0);
		out.write(&len.to_be_bytes());
		write_name(out, &self.next_name);
		write_nsec_types_bitmap(out, &self.types.0);
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A Next Secure Record resource record. This indicates a range of possible names for which there
/// is no such record.
pub struct NSec3 {
	/// The name this record is at.
	pub name: Name,
	/// The hash algorithm used to hash the `name` and [`Self::next_name_hash`]. Currently only 1
	/// (SHA-1) is defined.
	pub hash_algo: u8,
	/// Flags for this record. Currently only bit 0 (the "opt-out" bit) is defined.
	pub flags: u8,
	/// The number of hash iterations required.
	///
	/// As of RFC 9276 this MUST be set to 0, but sadly is often still set higher in the wild. A
	/// hard cap is applied in validation.
	pub hash_iterations: u16,
	/// The salt included in the hash.
	///
	/// As of RFC 9276 this SHOULD be empty, but often isn't in the wild.
	pub salt: Vec<u8>,
	/// The hash of the next name which contains a record. There are no records who's name's hash
	/// lies between `name` and [`Self::next_name_hash`].
	pub next_name_hash: Vec<u8>,
	/// The set of record types which exist at `name`. Any other record types do not exist at
	/// `name`.
	pub types: NSecTypeMask,
}
impl StaticRecord for NSec3 {
	const TYPE: u16 = 50;
	fn name(&self) -> &Name { &self.name }
	fn json(&self) -> String {
		let mut out = String::with_capacity(256);
		write!(&mut out,
			"{{\"type\":\"nsec3\",\"name\":\"{}\",\"hash_algo\":{},\"flags\":{},\"hash_iterations\":{},\"salt\":{:?},\"next_name_hash\":{:?},\"types\":",
			self.name.0, self.hash_algo, self.flags, self.hash_iterations, &self.salt[..], &self.next_name_hash[..]
		).expect("Write to a String shouldn't fail");
		self.types.write_json(&mut out);
		out += "}";
		out
	}
	fn read_from_data(name: Name, mut data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		let res = NSec3 {
			name, hash_algo: read_u8(&mut data)?, flags: read_u8(&mut data)?,
			hash_iterations: read_u16(&mut data)?, salt: read_u8_len_prefixed_bytes(&mut data)?,
			next_name_hash: read_u8_len_prefixed_bytes(&mut data)?,
			types: NSecTypeMask(read_nsec_types_bitmap(&mut data)?),
		};
		debug_assert!(data.is_empty());
		Ok(res)
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		let len = 4 + 2 + self.salt.len() as u16 + self.next_name_hash.len() as u16 +
			nsec_types_bitmap_len(&self.types.0);
		out.write(&len.to_be_bytes());
		out.write(&self.hash_algo.to_be_bytes());
		out.write(&self.flags.to_be_bytes());
		out.write(&self.hash_iterations.to_be_bytes());
		out.write(&(self.salt.len() as u8).to_be_bytes());
		out.write(&self.salt);
		out.write(&(self.next_name_hash.len() as u8).to_be_bytes());
		out.write(&self.next_name_hash);
		write_nsec_types_bitmap(out, &self.types.0);
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
/// The wire type for A records
pub const A_TYPE: u16 = 1;
impl StaticRecord for A {
	const TYPE: u16 = A_TYPE;
	fn name(&self) -> &Name { &self.name }
	fn json(&self) -> String {
		format!("{{\"type\":\"a\",\"name\":\"{}\",\"address\":{:?}}}", self.name.0, self.address)
	}
	fn read_from_data(name: Name, data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		if data.len() != 4 { return Err(()); }
		let mut address = [0; 4];
		address.copy_from_slice(&data);
		Ok(A { name, address })
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		out.write(&4u16.to_be_bytes());
		out.write(&self.address);
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
/// The wire type for AAAA records
pub const AAAA_TYPE: u16 = 28;
impl StaticRecord for AAAA {
	const TYPE: u16 = AAAA_TYPE;
	fn name(&self) -> &Name { &self.name }
	fn json(&self) -> String {
		format!("{{\"type\":\"aaaa\",\"name\":\"{}\",\"address\":{:?}}}", self.name.0, self.address)
	}
	fn read_from_data(name: Name, data: &[u8], _wire_packet: &[u8]) -> Result<Self, ()> {
		if data.len() != 16 { return Err(()); }
		let mut address = [0; 16];
		address.copy_from_slice(&data);
		Ok(AAAA { name, address })
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		out.write(&16u16.to_be_bytes());
		out.write(&self.address);
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
	/// The name of the server which is responsible for handling queries for the [`self.name`]
	/// zone.
	pub name_server: Name,
}
impl StaticRecord for NS {
	const TYPE: u16 = 2;
	fn name(&self) -> &Name { &self.name }
	fn json(&self) -> String {
		format!("{{\"type\":\"ns\",\"name\":\"{}\",\"ns\":\"{}\"}}", self.name.0, self.name_server.0)
	}
	fn read_from_data(name: Name, mut data: &[u8], wire_packet: &[u8]) -> Result<Self, ()> {
		let res = NS { name, name_server: read_wire_packet_name(&mut data, wire_packet)? };
		debug_assert!(data.is_empty());
		Ok(res)
	}
	fn write_u16_len_prefixed_data<W: Writer>(&self, out: &mut W) {
		out.write(&name_len(&self.name_server).to_be_bytes());
		write_name(out, &self.name_server);
	}
}

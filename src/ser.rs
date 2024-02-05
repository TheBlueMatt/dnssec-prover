//! Serialization/Deserialization logic lives here

use alloc::vec::Vec;
use alloc::string::String;

use ring::signature;

use crate::rr::*;

pub(crate) fn read_u8(inp: &mut &[u8]) -> Result<u8, ()> {
	let res = *inp.get(0).ok_or(())?;
	*inp = &inp[1..];
	Ok(res)
}
pub(crate) fn read_u16(inp: &mut &[u8]) -> Result<u16, ()> {
	if inp.len() < 2 { return Err(()); }
	let mut bytes = [0; 2];
	bytes.copy_from_slice(&inp[..2]);
	*inp = &inp[2..];
	Ok(u16::from_be_bytes(bytes))
}
pub(crate) fn read_u32(inp: &mut &[u8]) -> Result<u32, ()> {
	if inp.len() < 4 { return Err(()); }
	let mut bytes = [0; 4];
	bytes.copy_from_slice(&inp[..4]);
	*inp = &inp[4..];
	Ok(u32::from_be_bytes(bytes))
}

pub(crate) fn read_name(inp: &mut &[u8]) -> Result<Name, ()> {
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

pub(crate) trait Writer { fn write(&mut self, buf: &[u8]); }
impl Writer for Vec<u8> { fn write(&mut self, buf: &[u8]) { self.extend_from_slice(buf); } }
impl Writer for ring::digest::Context { fn write(&mut self, buf: &[u8]) { self.update(buf); } }
pub(crate) fn write_name<W: Writer>(out: &mut W, name: &str) {
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
pub(crate) fn name_len(name: &Name) -> u16 {
	if name.as_str() == "." {
		1
	} else {
		let mut res = 0;
		for label in name.split(".") {
			res += 1 + label.len();
		}
		res as u16
	}
}

pub(crate) fn parse_rr(inp: &mut &[u8]) -> Result<RR, ()> {
	let name = read_name(inp)?;
	let ty = read_u16(inp)?;
	let class = read_u16(inp)?;
	if class != 1 { return Err(()); } // We only support the INternet
	let _ttl = read_u32(inp)?;
	let data_len = read_u16(inp)? as usize;
	if inp.len() < data_len { return Err(()); }
	let data = &inp[..data_len];
	*inp = &inp[data_len..];

	match ty {
		Txt::TYPE => {
			Ok(RR::Txt(Txt::read_from_data(name, data)?))
		}
		CName::TYPE => {
			Ok(RR::CName(CName::read_from_data(name, data)?))
		}
		TLSA::TYPE => {
			Ok(RR::TLSA(TLSA::read_from_data(name, data)?))
		},
		DnsKey::TYPE => {
			Ok(RR::DnsKey(DnsKey::read_from_data(name, data)?))
		},
		DS::TYPE => {
			Ok(RR::DS(DS::read_from_data(name, data)?))
		},
		RRSig::TYPE => {
			Ok(RR::RRSig(RRSig::read_from_data(name, data)?))
		},
		_ => Err(()),
	}
}

pub(crate) fn bytes_to_rsa_pk<'a>(pubkey: &'a [u8])
-> Result<signature::RsaPublicKeyComponents<&'a [u8]>, ()> {
	if pubkey.len() <= 3 { return Err(()); }

	let mut pos = 0;
	let exponent_length;
	if pubkey[0] == 0 {
		exponent_length = ((pubkey[1] as usize) << 8) | (pubkey[2] as usize);
		pos += 3;
	} else {
		exponent_length = pubkey[0] as usize;
		pos += 1;
	}

	if pubkey.len() <= pos + exponent_length { return Err(()); }
	Ok(signature::RsaPublicKeyComponents {
		n: &pubkey[pos + exponent_length..],
		e: &pubkey[pos..pos + exponent_length]
	})
}

//! This module exposes utilities for building DNSSEC proofs by directly querying a recursive
//! resolver.

use std::net::{SocketAddr, TcpStream};
use std::io::{Read, Write, Error, ErrorKind};

use crate::write_rr;
use crate::rr::*;
use crate::ser::*;

// We don't care about transaction IDs as we're only going to accept signed data. Thus, we use
// this constant instead of a random value.
const TXID: u16 = 0x4242;

fn emap<V>(v: Result<V, ()>) -> Result<V, Error> {
	v.map_err(|_| Error::new(ErrorKind::Other, "Bad Response"))
}

fn send_query(stream: &mut TcpStream, domain: Name, ty: u16) -> Result<(), Error> {
	let mut query = Vec::with_capacity(1024);
	let query_msg_len: u16 = 2 + 2 + 8 + 2 + 2 + name_len(&domain) + 11;
	query.extend_from_slice(&query_msg_len.to_be_bytes());
	query.extend_from_slice(&TXID.to_be_bytes());
	query.extend_from_slice(&[0x01, 0x20]); // Flags: Recursive, Authenticated Data
	query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // One question, One additional
	write_name(&mut query, &domain);
	query.extend_from_slice(&ty.to_be_bytes());
	query.extend_from_slice(&1u16.to_be_bytes()); // INternet class
	query.extend_from_slice(&[0, 0, 0x29]); // . OPT
	query.extend_from_slice(&0u16.to_be_bytes()); // 0 UDP payload size
	query.extend_from_slice(&[0, 0]); // EDNS version 0
	query.extend_from_slice(&0x8000u16.to_be_bytes()); // Accept DNSSEC RRs
	query.extend_from_slice(&0u16.to_be_bytes()); // No additional data
	stream.write_all(&query)?;
	Ok(())
}

fn read_response(stream: &mut TcpStream) -> Result<Vec<RR>, Error> {
	let mut len = [0; 2];
	stream.read_exact(&mut len)?;
	let mut resp = vec![0; u16::from_be_bytes(len) as usize];
	stream.read_exact(&mut resp)?;

	let mut read: &[u8] = &resp;
	if emap(read_u16(&mut read))? != TXID { return Err(Error::new(ErrorKind::Other, "bad txid")); }
	// 2 byte transaction ID
	let flags = emap(read_u16(&mut read))?;
	if flags & 0b1000_0000_0000_0000 == 0 {
		return Err(Error::new(ErrorKind::Other, "Missing response flag"));
	}
	if flags & 0b0111_1010_0000_0111 != 0 {
		return Err(Error::new(ErrorKind::Other, "Server indicated error or provided bunk flags"));
	}
	if flags & 0b10_0000 == 0 {
		return Err(Error::new(ErrorKind::Other, "Server indicated data could not be authenticated"));
	}
	let questions = emap(read_u16(&mut read))?;
	if questions != 1 { return Err(Error::new(ErrorKind::Other, "server responded to multiple Qs")); }
	let answers = emap(read_u16(&mut read))?;
	let _authorities = emap(read_u16(&mut read))?;
	let _additional = emap(read_u16(&mut read))?;

	for _ in 0..questions {
		emap(read_name(&mut read))?;
		emap(read_u16(&mut read))?; // type
		emap(read_u16(&mut read))?; // class
	}

	// Only read the answers (skip authorities and additional) as that's all we care about.
	let mut res = Vec::new();
	for _ in 0..answers {
		res.push(emap(parse_wire_packet_rr(&mut read, &resp))?);
	}
	Ok(res)
}

fn build_proof(resolver: SocketAddr, domain: Name, ty: u16) -> Result<Vec<u8>, Error> {
	let mut stream = TcpStream::connect(resolver)?;
	let mut res = Vec::new();
	send_query(&mut stream, domain, ty)?;
	let mut reached_root = false;
	for _ in 0..10 {
		let resp = read_response(&mut stream)?;
		for rr in resp {
			write_rr(&rr, 0, &mut res);
			if rr.name().as_str() == "." {
				reached_root = true;
			} else {
				if let RR::RRSig(rrsig) = rr {
					if rrsig.name == rrsig.key_name {
						send_query(&mut stream, rrsig.key_name, DS::TYPE)?;
					} else {
						send_query(&mut stream, rrsig.key_name, DnsKey::TYPE)?;
					}
				}
			}
		}
		if reached_root { break; }
	}

	if !reached_root { Err(Error::new(ErrorKind::Other, "Too many requests required")) }
	else { Ok(res) }
}

/// Builds a DNSSEC proof for an A record by querying a recursive resolver
pub fn build_a_proof(resolver: SocketAddr, domain: Name) -> Result<Vec<u8>, Error> {
	build_proof(resolver, domain, A::TYPE)
}

/// Builds a DNSSEC proof for an AAAA record by querying a recursive resolver
pub fn build_aaaa_proof(resolver: SocketAddr, domain: Name) -> Result<Vec<u8>, Error> {
	build_proof(resolver, domain, AAAA::TYPE)
}

/// Builds a DNSSEC proof for a TXT record by querying a recursive resolver
pub fn build_txt_proof(resolver: SocketAddr, domain: Name) -> Result<Vec<u8>, Error> {
	build_proof(resolver, domain, Txt::TYPE)
}

/// Builds a DNSSEC proof for a TLSA record by querying a recursive resolver
pub fn build_tlsa_proof(resolver: SocketAddr, domain: Name) -> Result<Vec<u8>, Error> {
	build_proof(resolver, domain, TLSA::TYPE)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	use rand::seq::SliceRandom;

	use std::net::ToSocketAddrs;

	#[test]
	fn test_txt_query() {
		let sockaddr = "8.8.8.8:53".to_socket_addrs().unwrap().next().unwrap();
		let query_name = "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap();
		let proof = build_txt_proof(sockaddr, query_name).unwrap();

		let mut rrs = parse_rr_stream(&proof).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert_eq!(verified_rrs.len(), 1);
	}
}

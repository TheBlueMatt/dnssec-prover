//! Utilities to deserialize and validate RFC 9102 proofs

use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use alloc::vec;
use core::cmp;

use ring::signature;

use crate::rr::*;
use crate::ser::write_name;

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

			let mut signed_data = Vec::with_capacity(2048);
			signed_data.extend_from_slice(&sig.ty.to_be_bytes());
			signed_data.extend_from_slice(&sig.alg.to_be_bytes());
			signed_data.extend_from_slice(&sig.labels.to_be_bytes());
			signed_data.extend_from_slice(&sig.orig_ttl.to_be_bytes());
			signed_data.extend_from_slice(&sig.expiration.to_be_bytes());
			signed_data.extend_from_slice(&sig.inception.to_be_bytes());
			signed_data.extend_from_slice(&sig.key_tag.to_be_bytes());
			write_name(&mut signed_data, &sig.key_name);

			records.sort_unstable();

			for record in records.iter() {
				let periods = record.name().as_str().chars().filter(|c| *c == '.').count();
				let labels = sig.labels.into();
				if periods != 1 && periods != labels {
					if periods < labels { return Err(ValidationError::Invalid); }
					let signed_name = record.name().as_str().splitn(periods - labels + 1, ".").last();
					debug_assert!(signed_name.is_some());
					if let Some(name) = signed_name {
						signed_data.extend_from_slice(b"\x01*");
						write_name(&mut signed_data, name);
					} else { return Err(ValidationError::Invalid); }
				} else {
					write_name(&mut signed_data, record.name());
				}
				signed_data.extend_from_slice(&record.ty().to_be_bytes());
				signed_data.extend_from_slice(&1u16.to_be_bytes()); // The INternet class
				signed_data.extend_from_slice(&sig.orig_ttl.to_be_bytes());
				record.write_u16_len_prefixed_data(&mut signed_data);
			}

			let sig_validation = match sig.alg {
				8|10 => {
					let alg = if sig.alg == 8 {
						&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
					} else {
						&signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
					};
					bytes_to_rsa_pk(&dnskey.pubkey).map_err(|_| ValidationError::Invalid)?
						.verify(alg, &signed_data, &sig.signature)
						.map_err(|_| ValidationError::Invalid)
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
						.map_err(|_| ValidationError::Invalid)
				},
				15 => {
					signature::UnparsedPublicKey::new(&signature::ED25519, &dnskey.pubkey)
						.verify(&signed_data, &sig.signature)
						.map_err(|_| ValidationError::Invalid)
				},
				_ => return Err(ValidationError::UnsupportedAlgorithm),
			};
			#[cfg(fuzzing)] {
				// When fuzzing, treat any signature starting with a 1 as valid, but only after
				// parsing and checking signatures to give that code a chance to panic.
				if sig.signature.get(0) == Some(&1) {
					return Ok(());
				}
			}
			sig_validation?;

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
		if ds.digest_type == 1 || ds.digest_type == 2 || ds.digest_type == 4 {
			had_known_digest_type = true;
			break;
		}
	}
	if !had_ds { return Err(ValidationError::Invalid); }
	if !had_known_digest_type { return Err(ValidationError::UnsupportedAlgorithm); }

	for dnskey in records.iter() {
		// Only use SHA1 DS records if we don't have any SHA256/SHA384 DS RRs.
		let trust_sha1 = dses.clone().all(|ds| ds.digest_type != 2 && ds.digest_type != 4);
		for ds in dses.clone() {
			if ds.alg != dnskey.alg { continue; }
			if dnskey.key_tag() == ds.key_tag {
				let alg = match ds.digest_type {
					1 if trust_sha1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
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

/// Given a set of [`RR`]s, [`verify_rr_stream`] checks what it can and returns the set of
/// non-[`RRSig`]/[`DnsKey`]/[`DS`] records which it was able to verify using this struct.
///
/// It also contains signing and expiry times, which must be validated before considering the
/// contained records verified.
#[derive(Debug, Clone)]
pub struct VerifiedRRStream<'a> {
	/// The set of verified [`RR`]s.
	///
	/// These are not valid unless the current UNIX time is between [`Self::valid_from`] and
	/// [`Self::expires`].
	pub verified_rrs: Vec<&'a RR>,
	/// The latest [`RRSig::inception`] of all the [`RRSig`]s validated to verify
	/// [`Self::verified_rrs`].
	///
	/// Any records in [`Self::verified_rrs`] should not be considered valid unless this is before
	/// the current UNIX time.
	///
	/// While the field here is a u64, the algorithm used to identify rollovers will fail in 2133.
	pub valid_from: u64,
	/// The earliest [`RRSig::expiration`] of all the [`RRSig`]s validated to verify
	/// [`Self::verified_rrs`].
	///
	/// Any records in [`Self::verified_rrs`] should not be considered valid unless this is after
	/// the current UNIX time.
	///
	/// While the field here is a u64, the algorithm used to identify rollovers will fail in 2133.
	pub expires: u64,
	/// The minimum [`RRSig::orig_ttl`] of all the [`RRSig`]s validated to verify
	/// [`Self::verified_rrs`].
	///
	/// Any caching of [`Self::verified_rrs`] must not last longer than this value, in seconds.
	pub max_cache_ttl: u32,
}

fn resolve_time(time: u32) -> u64 {
	// RFC 2065 was published in January 1997, so we arbitrarily use that as a cutoff and assume
	// any timestamps before then are actually past 2106 instead.
	// We ignore leap years for simplicity.
	if time < 60*60*24*365*27 {
		(time as u64) + (u32::MAX as u64)
	} else {
		time.into()
	}
}

/// Verifies the given set of resource records.
///
/// Given a set of arbitrary records, this attempts to validate DNSSEC data from the [`root_hints`]
/// through to any supported non-DNSSEC record types.
///
/// All records which could be validated are returned, though if an error is found validating any
/// contained record, only `Err` will be returned.
///
/// You MUST check that the current UNIX time is between [`VerifiedRRStream::valid_from`] and
/// [`VerifiedRRStream::expires`].
pub fn verify_rr_stream<'a>(inp: &'a [RR]) -> Result<VerifiedRRStream<'a>, ValidationError> {
	let mut zone = ".";
	let mut res = Vec::new();
	let mut pending_ds_sets = Vec::with_capacity(1);
	let mut latest_inception = 0;
	let mut earliest_expiry = u64::MAX;
	let mut min_ttl = u32::MAX;
	'next_zone: while zone == "." || !pending_ds_sets.is_empty() {
		let mut found_unsupported_alg = false;
		let next_ds_set;
		if let Some((next_zone, ds_set)) = pending_ds_sets.pop() {
			next_ds_set = Some(ds_set);
			zone = next_zone;
		} else {
			debug_assert_eq!(zone, ".");
			next_ds_set = None;
		}

		for rrsig in inp.iter()
			.filter_map(|rr| if let RR::RRSig(sig) = rr { Some(sig) } else { None })
			.filter(|rrsig| rrsig.name.as_str() == zone && rrsig.ty == DnsKey::TYPE)
		{
			let dnskeys = inp.iter()
				.filter_map(|rr| if let RR::DnsKey(dnskey) = rr { Some(dnskey) } else { None })
				.filter(move |dnskey| dnskey.name.as_str() == zone);
			let dnskeys_verified = if zone == "." {
				verify_dnskey_rrsig(rrsig, &root_hints(), dnskeys.clone().collect())
			} else {
				debug_assert!(next_ds_set.is_some());
				if next_ds_set.is_none() { break 'next_zone; }
				verify_dnskey_rrsig(rrsig, next_ds_set.clone().unwrap(), dnskeys.clone().collect())
			};
			if dnskeys_verified.is_ok() {
				latest_inception = cmp::max(latest_inception, resolve_time(rrsig.inception));
				earliest_expiry = cmp::min(earliest_expiry, resolve_time(rrsig.expiration));
				min_ttl = cmp::min(min_ttl, rrsig.orig_ttl);
				for rrsig in inp.iter()
					.filter_map(|rr| if let RR::RRSig(sig) = rr { Some(sig) } else { None })
					.filter(move |rrsig| rrsig.key_name.as_str() == zone && rrsig.ty != DnsKey::TYPE)
				{
					if !rrsig.name.ends_with(zone) { return Err(ValidationError::Invalid); }
					let signed_records = inp.iter()
						.filter(|rr| rr.name() == &rrsig.name && rr.ty() == rrsig.ty);
					verify_rrsig(rrsig, dnskeys.clone(), signed_records.clone().collect())?;
					latest_inception = cmp::max(latest_inception, resolve_time(rrsig.inception));
					earliest_expiry = cmp::min(earliest_expiry, resolve_time(rrsig.expiration));
					min_ttl = cmp::min(min_ttl, rrsig.orig_ttl);
					match rrsig.ty {
						// RRSigs shouldn't cover child `DnsKey`s or other `RRSig`s
						RRSig::TYPE|DnsKey::TYPE => return Err(ValidationError::Invalid),
						DS::TYPE => {
							if !pending_ds_sets.iter().any(|(pending_zone, _)| pending_zone == &rrsig.name.as_str()) {
								pending_ds_sets.push((
									&rrsig.name,
									signed_records.filter_map(|rr|
										if let RR::DS(ds) = rr { Some(ds) }
										else { debug_assert!(false, "We already filtered by type"); None })
								));
							}
						},
						_ => {
							for record in signed_records {
								if !res.contains(&record) { res.push(record); }
							}
						},
					}
				}
				continue 'next_zone;
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
	else if latest_inception >= earliest_expiry { Err(ValidationError::Invalid) }
	else {
		Ok(VerifiedRRStream {
			verified_rrs: res, valid_from: latest_inception, expires: earliest_expiry,
			max_cache_ttl: min_ttl,
		})
	}
}

impl<'a> VerifiedRRStream<'a> {
	/// Given a name, resolve any [`CName`] records and return any verified records which were
	/// pointed to by the original name.
	///
	/// Note that because of [`CName`]s, the [`RR::name`] in the returned records may or may not be
	/// equal to `name`.
	///
	/// You MUST still check that the current UNIX time is between
	/// [`VerifiedRRStream::valid_from`] and [`VerifiedRRStream::expires`] before
	/// using any records returned here.
	pub fn resolve_name<'b>(&self, name_param: &'b Name) -> Vec<&'a RR> where 'a: 'b {
		let mut dname_name;
		let mut name = name_param;
		loop {
			let mut cname_search = self.verified_rrs.iter()
				.filter(|rr| rr.name() == name)
				.filter_map(|rr| if let RR::CName(cn) = rr { Some(cn) } else { None });
			if let Some(cname) = cname_search.next() {
				name = &cname.canonical_name;
				continue;
			}

			let mut dname_search = self.verified_rrs.iter()
				.filter(|rr| name.ends_with(&**rr.name()))
				.filter_map(|rr| if let RR::DName(dn) = rr { Some(dn) } else { None });
			if let Some(dname) = dname_search.next() {
				let prefix = name.strip_suffix(&*dname.name).expect("We just filtered for this");
				let resolved_name = prefix.to_owned() + &dname.delegation_name;
				dname_name = if let Ok(name) = resolved_name.try_into() {
					name
				} else {
					// This should only happen if the combined name ended up being too long
					return Vec::new();
				};
				name = &dname_name;
				continue;
			}

			return self.verified_rrs.iter().filter(|rr| rr.name() == name).map(|rr| *rr).collect();
		}
	}
}

#[cfg(test)]
mod tests {
	#![allow(deprecated)]

	use super::*;

	use alloc::borrow::ToOwned;

	use crate::ser::{parse_rr_stream, write_rr};

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
			expiration: 1709337600, inception: 1707523200, key_tag: 20326, key_name: ".".try_into().unwrap(),
			signature: base64::decode("QXPpi2A4jXgS6/aH5ZPCT/iOr75XYdk9kxemYrLaVaUAiaOVLDcArPOC8vyv6BKrK0Mq/lht2ql/XARVokC97n1W7B7tpzTpsZle7Z9cTSvbQefI/vVmFZwp+4+mad2f+Tqa0ApQLWaFXEdrJ4IThswbIwpNp8e1w9HwTZHT/B5Jve+v3CLf8o73ScYaVebC5c76Ifh6M5lAknazUWJ9/j5vQ6yInQpcUR3t520HL+KPEcDfmDXB6GOLr/Psdk8QCfB3LJ4heDCaI0H+ae/YPzedpnihAVP+hzhlOzZ0vpj7QOh4lTQjN7UzWNY9XbK+EhZHXRQmCmYydAUP6FpMmQ==").unwrap(),
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
			expiration: 1708794000, inception: 1707667200, key_tag: 30903, key_name: ".".try_into().unwrap(),
			signature: base64::decode("RT9N7xNToOdDHGw+/gvWCeEk+HXR/VBlAymFR2OWaYCVD6FUXlAw4OZkvJPqpsA465R1+CApbWu0vsG3Op949QNqU0tDOZcnO3+dyf0vimQX8pI0XMwtrUM/KHkHHb+EWKywNHsMqOo83+b428YHtkidVXeToz/xjFTJLbAlgNJCAiq3FGuHo/x2fnccBiZB2spfW7Og6nhOBqAy5tUualgaCxMX3j5ZDoQ259HhVgbYdQvjd7H9sj0C4UHxm8Y0XY5J1gRnWIuylN1oLzwIqizGFPbknvFXA/GXfk3KInlpQoCnXWwHe8ZBEgxqcgJ8YLRDU8bj+bJ4nol53yntcA==").unwrap(),
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
			expiration: 1708614155, inception: 1707317855, key_tag: 19718, key_name: "com.".try_into().unwrap(),
			signature: base64::decode("z1l579YFyZ1bD345+zwNUiGJQ9SAoSBdhfelmo9+cLFHF9wwtr/rJnsHt/T/75zCxzAXZGHw6FFcH5ZCe/mH4A==").unwrap(),
		};
		verify_dnskey_rrsig(&dnskey_rrsig, &com_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![com_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn ninja_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let root_dnskeys = root_dnskey().0;
		let mut ninja_ds = vec![DS {
			name: "ninja.".try_into().unwrap(), key_tag: 46082, alg: 8, digest_type: 2,
			digest: Vec::from_hex("C8F816A7A575BDB2F997F682AAB2653BA2CB5EDDB69B036A30742A33BEFAF141").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "ninja.".try_into().unwrap(), ty: DS::TYPE, alg: 8, labels: 1, orig_ttl: 86400,
			expiration: 1708794000, inception: 1707667200, key_tag: 30903, key_name: ".".try_into().unwrap(),
			signature: base64::decode("FO6kj+2lJF/VSDwkwh+h8NpkCzk9x7DES/3LQFnJf4NOnY7W+m86Usy79CP5t8YMiKZweOlUd8rmd1PkrX1zf0sQxqdWFPpKiDxh/tyhkyV/FiN8vvtXMaIUeDFWXTBM/Rap2oHigiRDsHwOd8fnG1+8bkY7HtXx54EZvieRZAvZd17wBj3L75UQHwIxJwpzbeZOF3583wcWoPOX70pp4Xzeryok0P++Qr7VPUpzEHAe4v4JePlODau38qyI1Bzr2pBQiTSgpBUI5vTtoGC4+aEMXjc0OBt6kMjncQA6B8GNqUqnBgfTdNNhXYFTWekBAres5w5SvVOKeS3no1eIRw==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &root_dnskeys, ninja_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAZlkeshgX2Q9i/X4zZMc2ciKO2a3+mOiOCuYHYbwt/43XXdcHdjtOUrWFFJkGBBWsHQZ/Bg0CeUGqvUGywd3ndY5IAX+e7PnuIUlhKDcNmntcQbxhrH+cpmOoB3Xo/96JoVjurPxTuJE23I1oA+0aESc581f4pKEbTp4WI7m5xNn").unwrap(),
		}, DnsKey {
			name: "ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAb6FWe0O0qxUkA+LghF71OPWt0WNqBaCi34HCV6Agjz70RN/j7yGi3xCExM8MkzyrbXd5yYFP4X7TCGEzI5ofLNq7GVIj9laZO0WYS8DNdCMN7qkVVaYeR2UeeGsdvIJqRWzlynABAKnCzX+y5np77FBsle4cAIGxJE/0F5kn61F").unwrap(),
		}, DnsKey {
			name: "ninja.".try_into().unwrap(), flags: 257, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAcceTJ3Ekkmiez70L8uNVrTDrHZxXHrQHEHQ1DJZDRXDxizuSy0prDXy1yybMqcKAkPL0IruvJ9vHg5j2eHN/hM8RVqCQ1wHgLdQASyUL37VtmLuyNmuiFpYmT+njXVh/tzRHZ4cFxrLAtACWDe6YaPApnVkJ0FEcMnKCQaymBaLX02WQOYuG3XdBr5mQQTtMs/kR/oh83QBcSxyCg3KS7G8IPP6MQPK0za94gsW9zlI5rgN2gpSjbU2qViGjDhw7N3PsC37PLTSLirUmkufeMkP9sfhDjAbP7Nv6FmpTDAIRmBmV0HBT/YNBTUBP89DmEDsrYL8knjkrOaLqV5wgkk=").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "ninja.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 8, labels: 1, orig_ttl: 3600,
			expiration: 1709309122, inception: 1707491122, key_tag: 46082, key_name: "ninja.".try_into().unwrap(),
			signature: base64::decode("tZjyFUaRDCFZ8heFd5qWQs5CKAZHEzdv3OcR3IRcyfIebRkpPjXM/Wi/0cPnKkEh7PQx+GK3ZRsSz8Sd0VEmmH/DapTh5Fn+ZR7znnGVGDU7xvHRQZaIB33MMTqLBkKkjDkWi+G7cYe7PbfWRh5JOvcyUSZ21eKlAInaOJYrc9WNydN6EnXhDoMZJK8GWrM8AJdKJjpopqH3iEuu73WI9JZJQtzo4vdGyYwHvYAu9x14zCY1uKcBoCaohjP4K7KRvl+aRQETY175yFBfeCneExb2SJI6wMVEWwlQbeMImn2jmPjGcm0cZjYL6v+jj4T7Yq2xZirdvHoCtIeCXwv5Dg==").unwrap(),
		};
		verify_dnskey_rrsig(&dnskey_rrsig, &ninja_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![ninja_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskeys[2].clone().into(),
			dnskey_rrsig.into()];
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
			expiration: 1707976967, inception: 1707367967, key_tag: 4534, key_name: "com.".try_into().unwrap(),
			signature: base64::decode("QtgzO1czEOcGxvjuSqW4AlEMYr1gDSPRwYPvhmZOe06QU3dfXppv/+wEr1DNKY6BCjQ7fVXx0YFb7T3NfmLbHQ==").unwrap(),
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
			expiration: 1708794127, inception: 1707579127, key_tag: 25630, key_name: "mattcorallo.com.".try_into().unwrap(),
			signature: base64::decode("aYgXNubpwB8RJMiE+pFl1/p40gfE6ov9riMGdIl+H7Ys+hvX+NYR+cJNBpfSeqOIXqPJqxnbEyZ1HE8LvK7i8g==").unwrap(),
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
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 3600, expiration: 1708638126,
			inception: 1707423126, key_tag: 47959, key_name: "mattcorallo.com.".try_into().unwrap(),
			signature: base64::decode("DsVKNjv4e3m2sJyTPw9b4tpoDW/o/TrwLfFEQe1zOUn43kGqqCNUX1DqsaAtOeLlBuCVWEo1uT2qVc8MijH5ig==").unwrap(),
		};
		(txt_resp, txt_rrsig)
	}

	fn bitcoin_ninja_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let ninja_dnskeys = ninja_dnskey().0;
		let mut bitcoin_ninja_ds = vec![DS {
			name: "bitcoin.ninja.".try_into().unwrap(), key_tag: 63175, alg: 13, digest_type: 2,
			digest: Vec::from_hex("D554267D7F730B9602BF4436F46BB967EFE3C4202CA7F082F2D5DD24DF4EBDED").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "bitcoin.ninja.".try_into().unwrap(), ty: DS::TYPE, alg: 8, labels: 2, orig_ttl: 3600,
			expiration: 1709309122, inception: 1707491122, key_tag: 34164, key_name: "ninja.".try_into().unwrap(),
			signature: base64::decode("QDFgNQkC5IWkMH8VaOifnIbA+K/OnrPwQwAEwlTTtvXwElC+spF6rKSE1O26+vAIiGbY3LkwcVQHf3pQcgwS3gR3jbzaxyDAQ2RjshLaBJ/gA5BJA0lWyHKsQpmzBpcKf2XnRK6ZY6sUDrWURMoZp3+8qhWJux/3X3aKkr7ADU0=").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &ninja_dnskeys, bitcoin_ninja_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "bitcoin.ninja.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("0lIZI5BH7kk75R/+1RMReQE0J2iQw0lY2aQ6eCM7F1E9ZMNcIGC1cDl5+FcAU1mP8F3Ws2FjgvCC0S2q8OBF2Q==").unwrap(),
		}, DnsKey {
			name: "bitcoin.ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("zbm2rKgzXDtRFV0wFmnlUMdOXWcNKEjGIHsZ7bAnTzbh7TJEzPctSttCaTvdaORxLL4AiOk+VG2iXnL2UuC/xQ==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "bitcoin.ninja.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 13, labels: 2, orig_ttl: 604800,
			expiration: 1708917507, inception: 1707702507, key_tag: 63175, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("h969M0tQu+hRyxhJi5aXroNIiyy2BbKpryAoMxZonuYC+orG6R5rIDE1EUzrp7rTZBKnykgHqkSF1klUK/OMyQ==").unwrap(),
		};
		verify_dnskey_rrsig(&dnskey_rrsig, &bitcoin_ninja_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![bitcoin_ninja_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn bitcoin_ninja_txt_record() -> (Txt, RRSig) {
		let txt_resp = Txt {
			name: "txt_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "dnssec_prover_test".to_owned().into_bytes(),
		};
		let txt_rrsig = RRSig {
			name: "txt_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1708920243,
			inception: 1707705243, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("CTAs/BSUfZP6+L0MRBVigK03q3M/2APkWlI9gJFkcwFKtDG53c9vcqSqLvv/IMIulDb3pNIj5UpxoRYNAJcVkA==").unwrap(),
		};
		(txt_resp, txt_rrsig)
	}

	fn bitcoin_ninja_cname_record() -> (CName, RRSig) {
		let cname_resp = CName {
			name: "cname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			canonical_name: "txt_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
		};
		let cname_rrsig = RRSig {
			name: "cname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: CName::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1708920243,
			inception: 1707705243, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("/xlq2qPB/BaXrUgpz66iIIVh6u2Qsg5oTE8LbDr01D6uvufVJZOl4qvSwbMpYw/+8Lv26etrT1xP53bc/7OyoA==").unwrap(),
		};
		(cname_resp, cname_rrsig)
	}

	fn bitcoin_ninja_wildcard_record() -> (Txt, RRSig) {
		let txt_resp = Txt {
			name: "test.wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "wildcard_test".to_owned().into_bytes(),
		};
		let txt_rrsig = RRSig {
			name: "test.wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1708920243,
			inception: 1707705243, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("GznihIpcboZZXG2wf/yyq1TVcNAl9iHiQeI7H6v15VzZFYhzljWFLolZPB86lKGywYC7PRH4OL0wNvrknJpp/g==").unwrap(),
		};
		(txt_resp, txt_rrsig)
	}

	fn bitcoin_ninja_cname_wildcard_record() -> (CName, RRSig, Txt, RRSig) {
		let cname_resp = CName {
			name: "test.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			canonical_name: "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
		};
		let txt_resp = Txt {
			name: "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "wildcard_test".to_owned().into_bytes(),
		};
		let cname_rrsig = RRSig {
			name: "test.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: CName::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1708920243,
			inception: 1707705243, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("PrII3i0K7H8RKoAmBSgSrPSmrNVNDmEf/d2h//zIKW0LE4gtt85mXP8pwEl8Ar5CbObAsWgmGI16/MMgQtqVZA==").unwrap(),
		};
		let txt_rrsig = RRSig {
			name: "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1708920243,
			inception: 1707705243, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("GznihIpcboZZXG2wf/yyq1TVcNAl9iHiQeI7H6v15VzZFYhzljWFLolZPB86lKGywYC7PRH4OL0wNvrknJpp/g==").unwrap(),
		};
		(cname_resp, cname_rrsig, txt_resp, txt_rrsig)
	}

	fn bitcoin_ninja_txt_sort_edge_cases_records() -> (Vec<Txt>, RRSig) {
		let txts = vec![Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabaa".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaba".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaba".to_owned().into_bytes(),
		}];
		let rrsig = RRSig {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1708920243,
			inception: 1707705243, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("C6myk1EJZ6/y4wClGp201y5EsqrAg4W/oybJ1/P0ss7sYraJC6BNApvHKEHpSBGgF1eJ/NCtpVFeD7+xgU0t3Q==").unwrap(),
		};
		(txts, rrsig)
	}

	#[test]
	fn check_txt_record_a() {
		let dnskeys = mattcorallo_dnskey().0;
		let (txt, txt_rrsig) = mattcorallo_txt_record();
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_single_txt_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in com_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in mattcorallo_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txt, txt_rrsig) = mattcorallo_txt_record();
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert_eq!(verified_rrs.verified_rrs.len(), 1);
		if let RR::Txt(txt) = &verified_rrs.verified_rrs[0] {
			assert_eq!(txt.name.as_str(), "matt.user._bitcoin-payment.mattcorallo.com.");
			assert_eq!(txt.data, b"bitcoin:?b12=lno1qsgqmqvgm96frzdg8m0gc6nzeqffvzsqzrxqy32afmr3jn9ggkwg3egfwch2hy0l6jut6vfd8vpsc3h89l6u3dm4q2d6nuamav3w27xvdmv3lpgklhg7l5teypqz9l53hj7zvuaenh34xqsz2sa967yzqkylfu9xtcd5ymcmfp32h083e805y7jfd236w9afhavqqvl8uyma7x77yun4ehe9pnhu2gekjguexmxpqjcr2j822xr7q34p078gzslf9wpwz5y57alxu99s0z2ql0kfqvwhzycqq45ehh58xnfpuek80hw6spvwrvttjrrq9pphh0dpydh06qqspp5uq4gpyt6n9mwexde44qv7lstzzq60nr40ff38u27un6y53aypmx0p4qruk2tf9mjwqlhxak4znvna5y");
		} else { panic!(); }
		assert_eq!(verified_rrs.valid_from, 1707667200); // The com. DS RRSig was created last
		assert_eq!(verified_rrs.expires, 1707976967); // The mattcorallo.com DS RRSig expires first
		assert_eq!(verified_rrs.max_cache_ttl, 3600); // The TXT record had the shortest TTL
	}

	#[test]
	fn check_txt_record_b() {
		let dnskeys = bitcoin_ninja_dnskey().0;
		let (txt, txt_rrsig) = bitcoin_ninja_txt_record();
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_cname_record() {
		let dnskeys = bitcoin_ninja_dnskey().0;
		let (cname, cname_rrsig) = bitcoin_ninja_cname_record();
		let cname_resp = [cname];
		verify_rrsig(&cname_rrsig, &dnskeys, cname_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_multi_zone_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in com_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in mattcorallo_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txt, txt_rrsig) = mattcorallo_txt_record();
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txt, txt_rrsig) = bitcoin_ninja_txt_record();
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		let (cname, cname_rrsig) = bitcoin_ninja_cname_record();
		for rr in [RR::CName(cname), RR::RRSig(cname_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let mut verified_rrs = verify_rr_stream(&rrs).unwrap();
		verified_rrs.verified_rrs.sort();
		assert_eq!(verified_rrs.verified_rrs.len(), 3);
		if let RR::Txt(txt) = &verified_rrs.verified_rrs[0] {
			assert_eq!(txt.name.as_str(), "matt.user._bitcoin-payment.mattcorallo.com.");
			assert_eq!(txt.data, b"bitcoin:?b12=lno1qsgqmqvgm96frzdg8m0gc6nzeqffvzsqzrxqy32afmr3jn9ggkwg3egfwch2hy0l6jut6vfd8vpsc3h89l6u3dm4q2d6nuamav3w27xvdmv3lpgklhg7l5teypqz9l53hj7zvuaenh34xqsz2sa967yzqkylfu9xtcd5ymcmfp32h083e805y7jfd236w9afhavqqvl8uyma7x77yun4ehe9pnhu2gekjguexmxpqjcr2j822xr7q34p078gzslf9wpwz5y57alxu99s0z2ql0kfqvwhzycqq45ehh58xnfpuek80hw6spvwrvttjrrq9pphh0dpydh06qqspp5uq4gpyt6n9mwexde44qv7lstzzq60nr40ff38u27un6y53aypmx0p4qruk2tf9mjwqlhxak4znvna5y");
		} else { panic!(); }
		if let RR::Txt(txt) = &verified_rrs.verified_rrs[1] {
			assert_eq!(txt.name.as_str(), "txt_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data, b"dnssec_prover_test");
		} else { panic!(); }
		if let RR::CName(cname) = &verified_rrs.verified_rrs[2] {
			assert_eq!(cname.name.as_str(), "cname_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(cname.canonical_name.as_str(), "txt_test.dnssec_proof_tests.bitcoin.ninja.");
		} else { panic!(); }

		let filtered_rrs =
			verified_rrs.resolve_name(&"cname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap());
		assert_eq!(filtered_rrs.len(), 1);
		if let RR::Txt(txt) = &filtered_rrs[0] {
			assert_eq!(txt.name.as_str(), "txt_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data, b"dnssec_prover_test");
		} else { panic!(); }
	}

	#[test]
	fn check_wildcard_record() {
		let dnskeys = bitcoin_ninja_dnskey().0;
		let (txt, txt_rrsig) = bitcoin_ninja_wildcard_record();
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_wildcard_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (cname, cname_rrsig, txt, txt_rrsig) = bitcoin_ninja_cname_wildcard_record();
		for rr in [RR::CName(cname), RR::RRSig(cname_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let mut verified_rrs = verify_rr_stream(&rrs).unwrap();
		verified_rrs.verified_rrs.sort();
		assert_eq!(verified_rrs.verified_rrs.len(), 2);
		if let RR::Txt(txt) = &verified_rrs.verified_rrs[0] {
			assert_eq!(txt.name.as_str(), "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data, b"wildcard_test");
		} else { panic!(); }
		if let RR::CName(cname) = &verified_rrs.verified_rrs[1] {
			assert_eq!(cname.name.as_str(), "test.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(cname.canonical_name.as_str(), "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
		} else { panic!(); }

		let filtered_rrs =
			verified_rrs.resolve_name(&"test.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap());
		assert_eq!(filtered_rrs.len(), 1);
		if let RR::Txt(txt) = &filtered_rrs[0] {
			assert_eq!(txt.name.as_str(), "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data, b"wildcard_test");
		} else { panic!(); }
	}

	#[test]
	fn check_txt_sort_order() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (mut txts, rrsig) = bitcoin_ninja_txt_sort_edge_cases_records();
		write_rr(&rrsig, 1, &mut rr_stream);
		for txt in txts.iter() { write_rr(txt, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		let mut verified_txts = verified_rrs.verified_rrs
			.iter().map(|rr| if let RR::Txt(txt) = rr { txt.clone() } else { panic!(); })
			.collect::<Vec<_>>();
		verified_txts.sort();
		txts.sort();
		assert_eq!(verified_txts, txts);
	}

	#[test]
	fn rfc9102_parse_test() {
		// Note that this is the `AuthenticationChain` field only, and ignores the
		// `ExtSupportLifetime` field (stripping the top two 0 bytes from the front).
let rfc9102_test_vector = Vec::from_hex("045f343433045f74637003777777076578616d706c6503636f6d000034000100000e1000230301018bd1da95272f7fa4ffb24137fc0ed03aae67e5c4d8b3c50734e1050a7920b922045f343433045f74637003777777076578616d706c6503636f6d00002e000100000e10005f00340d0500000e105fc6d9005bfdda80074e076578616d706c6503636f6d00ce1d3adeb7dc7cee656d61cfb472c5977c8c9caeae9b765155c518fb107b6a1fe0355fbaaf753c192832fa621fa73a8b85ed79d374117387598fcc812e1ef3fb076578616d706c6503636f6d000030000100000e1000440101030d2670355e0c894d9cfea6c5af6eb7d458b57a50ba88272512d8241d8541fd54adf96ec956789a51ceb971094b3bb3f4ec49f64c686595be5b2e89e8799c7717cc076578616d706c6503636f6d00002e000100000e10005f00300d0200000e105fc6d9005bfdda80074e076578616d706c6503636f6d004628383075b8e34b743a209b27ae148d110d4e1a246138a91083249cb4a12a2d9bc4c2d7ab5eb3afb9f5d1037e4d5da8339c162a9298e9be180741a8ca74accc076578616d706c6503636f6d00002b00010002a3000024074e0d02e9b533a049798e900b5c29c90cd25a986e8a44f319ac3cd302bafc08f5b81e16076578616d706c6503636f6d00002e00010002a3000057002b0d020002a3005fc6d9005bfdda80861703636f6d00a203e704a6facbeb13fc9384fdd6de6b50de5659271f38ce81498684e6363172d47e2319fdb4a22a58a231edc2f1ff4fb2811a1807be72cb5241aa26fdaee03903636f6d00003000010002a30000440100030dec8204e43a25f2348c52a1d3bce3a265aa5d11b43dc2a471162ff341c49db9f50a2e1a41caf2e9cd20104ea0968f7511219f0bdc56b68012cc3995336751900b03636f6d00003000010002a30000440101030d45b91c3bef7a5d99a7a7c8d822e33896bc80a777a04234a605a4a8880ec7efa4e6d112c73cd3d4c65564fa74347c873723cc5f643370f166b43dedff836400ff03636f6d00003000010002a30000440101030db3373b6e22e8e49e0e1e591a9f5bd9ac5e1a0f86187fe34703f180a9d36c958f71c4af48ce0ebc5c792a724e11b43895937ee53404268129476eb1aed323939003636f6d00002e00010002a300005700300d010002a3005fc6d9005bfdda8049f303636f6d0018a948eb23d44f80abc99238fcb43c5a18debe57004f7343593f6deb6ed71e04654a433f7aa1972130d9bd921c73dcf63fcf665f2f05a0aaebafb059dc12c96503636f6d00002e00010002a300005700300d010002a3005fc6d9005bfdda80708903636f6d006170e6959bd9ed6e575837b6f580bd99dbd24a44682b0a359626a246b1812f5f9096b75e157e77848f068ae0085e1a609fc19298c33b736863fbccd4d81f5eb203636f6d00002b000100015180002449f30d0220f7a9db42d0e2042fbbb9f9ea015941202f9eabb94487e658c188e7bcb5211503636f6d00002b000100015180002470890d02ad66b3276f796223aa45eda773e92c6d98e70643bbde681db342a9e5cf2bb38003636f6d00002e0001000151800053002b0d01000151805fc6d9005bfdda807cae00122e276d45d9e9816f7922ad6ea2e73e82d26fce0a4b718625f314531ac92f8ae82418df9b898f989d32e80bc4deaba7c4a7c8f172adb57ced7fb5e77a784b0700003000010001518000440100030dccacfe0c25a4340fefba17a254f706aac1f8d14f38299025acc448ca8ce3f561f37fc3ec169fe847c8fcbe68e358ff7c71bb5ee1df0dbe518bc736d4ce8dfe1400003000010001518000440100030df303196789731ddc8a6787eff24cacfeddd032582f11a75bb1bcaa5ab321c1d7525c2658191aec01b3e98ab7915b16d571dd55b4eae51417110cc4cdd11d171100003000010001518000440101030dcaf5fe54d4d48f16621afb6bd3ad2155bacf57d1faad5bac42d17d948c421736d9389c4c4011666ea95cf17725bd0fa00ce5e714e4ec82cfdfacc9b1c863ad4600002e000100015180005300300d00000151805fc6d9005bfdda80b79d00de7a6740eeecba4bda1e5c2dd4899b2c965893f3786ce747f41e50d9de8c0a72df82560dfb48d714de3283ae99a49c0fcb50d3aaadb1a3fc62ee3a8a0988b6be").unwrap();

		let mut rrs = parse_rr_stream(&rfc9102_test_vector).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert_eq!(verified_rrs.verified_rrs.len(), 1);
		if let RR::TLSA(tlsa) = &verified_rrs.verified_rrs[0] {
			assert_eq!(tlsa.cert_usage, 3);
			assert_eq!(tlsa.selector, 1);
			assert_eq!(tlsa.data_ty, 1);
			assert_eq!(tlsa.data, Vec::from_hex("8bd1da95272f7fa4ffb24137fc0ed03aae67e5c4d8b3c50734e1050a7920b922").unwrap());
		} else { panic!(); }
	}
}

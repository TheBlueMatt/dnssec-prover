//! Utilities to deserialize and validate RFC 9102 proofs

use alloc::vec::Vec;
use alloc::vec;
use core::cmp;

use ring::signature;

use crate::rr::*;
use crate::ser::{bytes_to_rsa_pk, parse_rr, write_name};

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

			records.sort();

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

			match sig.alg {
				8|10 => {
					let alg = if sig.alg == 8 {
						&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
					} else {
						&signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
					};
					bytes_to_rsa_pk(&dnskey.pubkey).map_err(|_| ValidationError::Invalid)?
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

/// Given a set of [`RR`]s, [`verify_rr_stream`] checks what it can and returns the set of
/// non-[`RRSig`]/[`DnsKey`]/[`DS`] records which it was able to verify using this struct.
///
/// It also contains
#[derive(Debug, Clone)]
pub struct VerifiedRRStream<'a> {
	/// The set of verified [`RR`]s.
	///
	/// These are not valid unless the current UNIX time is between [`Self::valid_from`] and
	/// [`Self::expiration`].
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
/// You MUST check that the current UNIX time is between [`VerifiedRRStream::latest_inception`] and
/// [`VerifiedRRStream::earliest_expiry`].
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

#[cfg(test)]
mod tests {
	#![allow(deprecated)]

	use super::*;

	use alloc::borrow::ToOwned;

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

	fn matcorallo_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let com_dnskeys = com_dnskey().0;
		let mut matcorallo_ds = vec![DS {
			name: "matcorallo.com.".try_into().unwrap(), key_tag: 24930, alg: 13, digest_type: 2,
			digest: Vec::from_hex("693E990CBB1CE1095E387092D3C04BCE907C008891F32A88D41D3ECB129E5E23").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "matcorallo.com.".try_into().unwrap(), ty: DS::TYPE, alg: 13, labels: 2, orig_ttl: 86400,
			expiration: 1707628636, inception: 1707019636, key_tag: 4534, key_name: "com.".try_into().unwrap(),
			signature: base64::decode("l9b+DhtnJSIzR6y4Bwx+0L9kep77UNCBoTg74RTSL6oMrQd8w4OobHxzwDyXqnLfyxVP18V+AnQp4DdJ2nUW1g==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &com_dnskeys, matcorallo_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "matcorallo.com.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("pfO3ow3SrKhLS7AMEi3b5W9P28nCOB9vryxfSXhqMcXFP1x9V4xAt0/JLr0zNodsqRD/8d9Yhu4Wf3hnSlaavw==").unwrap(),
		}, DnsKey {
			name: "matcorallo.com.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("OO6LQTV1mnRsFgn6YQoyeo/SDqS3eajfVv8WGQVnuSYO/bTS9St1tJiox2fgU6wRWDU3chhjz1Pj0unKUAQKig==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "matcorallo.com.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 13, labels: 2, orig_ttl: 604800,
			expiration: 1708309135, inception: 1707094135, key_tag: 24930, key_name: "matcorallo.com.".try_into().unwrap(),
			signature: base64::decode("2MKg3bTn9zf4ThwCoKRFadqD6l1D6SuLksRieKxFC0QQnzUOCRgZSK2/IlT0DMEoM0+mGrJZo7UG79UILMGUyg==").unwrap(),
		};
		verify_dnskey_rrsig(&dnskey_rrsig, &matcorallo_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![matcorallo_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn matcorallo_txt_record() -> (Txt, RRSig) {
		let txt_resp = Txt {
			name: "txt_test.matcorallo.com.".try_into().unwrap(),
			data: "dnssec_prover_test".to_owned().into_bytes(),
		};
		let txt_rrsig = RRSig {
			name: "txt_test.matcorallo.com.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 3, orig_ttl: 30, expiration: 1708319203,
			inception: 1707104203, key_tag: 34530, key_name: "matcorallo.com.".try_into().unwrap(),
			signature: base64::decode("4vaE5Jex2VvIT39JpuMNT7Ds7O0OfzTik5f8WcRRxO0IJnGAO16syAsNUkNkNqsMYknnjHDF0lI4agszgzdpsw==").unwrap(),
		};
		(txt_resp, txt_rrsig)
	}

	fn matcorallo_cname_record() -> (CName, RRSig) {
		let cname_resp = CName {
			name: "cname_test.matcorallo.com.".try_into().unwrap(),
			canonical_name: "txt_test.matcorallo.com.".try_into().unwrap(),
		};
		let cname_rrsig = RRSig {
			name: "cname_test.matcorallo.com.".try_into().unwrap(),
			ty: CName::TYPE, alg: 13, labels: 3, orig_ttl: 30, expiration: 1708319203,
			inception: 1707104203, key_tag: 34530, key_name: "matcorallo.com.".try_into().unwrap(),
			signature: base64::decode("5HIrmEotbVb95umE6SX3NrPboKsthdcY8b7DdaYQZzm0Nj5m2VgcfOmEPJYS8o1xE4GvGGF4sdfSy3Uw7TibBg==").unwrap(),
		};
		(cname_resp, cname_rrsig)
	}

	fn matcorallo_wildcard_record() -> (Txt, RRSig) {
		let txt_resp = Txt {
			name: "test.wildcard_test.matcorallo.com.".try_into().unwrap(),
			data: "wildcard_test".to_owned().into_bytes(),
		};
		let txt_rrsig = RRSig {
			name: "test.wildcard_test.matcorallo.com.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 3, orig_ttl: 30, expiration: 1708321778,
			inception: 1707106778, key_tag: 34530, key_name: "matcorallo.com.".try_into().unwrap(),
			signature: base64::decode("vdnXunPY4CnbW/BL8VOOR9o33+dqyKA/4h+u5VM7NjB30Shp8L8gL5UwE0k7TKRNgHC8j3TqEPEmNMIHz87Z4Q==").unwrap(),
		};
		(txt_resp, txt_rrsig)
	}

	fn matcorallo_cname_wildcard_record() -> (CName, RRSig, Txt, RRSig) {
		let cname_resp = CName {
			name: "test.cname_wildcard_test.matcorallo.com.".try_into().unwrap(),
			canonical_name: "cname.wildcard_test.matcorallo.com.".try_into().unwrap(),
		};
		let txt_resp = Txt {
			name: "cname.wildcard_test.matcorallo.com.".try_into().unwrap(),
			data: "wildcard_test".to_owned().into_bytes(),
		};
		let cname_rrsig = RRSig {
			name: "test.cname_wildcard_test.matcorallo.com.".try_into().unwrap(),
			ty: CName::TYPE, alg: 13, labels: 3, orig_ttl: 30, expiration: 1708322050,
			inception: 1707107050, key_tag: 34530, key_name: "matcorallo.com.".try_into().unwrap(),
			signature: base64::decode("JfJuSemF5dtQYxEw6eKL4IRP8BaDt6FtbtdpZ6HjODTDflhKQRhBEbwT7kwceKPAq18q5sWHFV1bMTqE/F3WLw==").unwrap(),
		};
		let txt_rrsig = RRSig {
			name: "cname.wildcard_test.matcorallo.com.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 3, orig_ttl: 30, expiration: 1708321778,
			inception: 1707106778, key_tag: 34530, key_name: "matcorallo.com.".try_into().unwrap(),
			signature: base64::decode("vdnXunPY4CnbW/BL8VOOR9o33+dqyKA/4h+u5VM7NjB30Shp8L8gL5UwE0k7TKRNgHC8j3TqEPEmNMIHz87Z4Q==").unwrap(),
		};
		(cname_resp, cname_rrsig, txt_resp, txt_rrsig)
	}

	fn matcorallo_txt_sort_edge_cases_records() -> (Vec<Txt>, RRSig) {
		let txts = vec![Txt {
			name: "txt_sort_order.matcorallo.com.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.matcorallo.com.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.matcorallo.com.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabaa".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.matcorallo.com.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaba".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.matcorallo.com.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.matcorallo.com.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.matcorallo.com.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned().into_bytes(),
		}, Txt {
			name: "txt_sort_order.matcorallo.com.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaba".to_owned().into_bytes(),
		}];
		let rrsig = RRSig {
			name: "txt_sort_order.matcorallo.com.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 3, orig_ttl: 30, expiration: 1708449632,
			inception: 1707234632, key_tag: 34530, key_name: "matcorallo.com.".try_into().unwrap(),
			signature: base64::decode("elAhELwzkGpUMvzeiYZpg1+yRFPjmOeEd1ir1vYx2Dku9kzsXmAlejOYDPWdaJ6ekvHdMejCN/MtyI+iFAYqsw==").unwrap(),
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
		assert_eq!(verified_rrs.valid_from, 1707063650); // The TXT record RRSig was created last
		assert_eq!(verified_rrs.expires, 1707631252); // The mattcorallo.com DS RRSig expires first
		assert_eq!(verified_rrs.max_cache_ttl, 3600); // The TXT record had the shortest TTL
	}

	#[test]
	fn check_txt_record_b() {
		let dnskeys = matcorallo_dnskey().0;
		let (txt, txt_rrsig) = matcorallo_txt_record();
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_cname_record() {
		let dnskeys = matcorallo_dnskey().0;
		let (cname, cname_rrsig) = matcorallo_cname_record();
		let cname_resp = [cname];
		verify_rrsig(&cname_rrsig, &dnskeys, cname_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_multi_zone_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in com_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in mattcorallo_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txt, txt_rrsig) = mattcorallo_txt_record();
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		for rr in matcorallo_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txt, txt_rrsig) = matcorallo_txt_record();
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		let (cname, cname_rrsig) = matcorallo_cname_record();
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
			assert_eq!(txt.name.as_str(), "txt_test.matcorallo.com.");
			assert_eq!(txt.data, b"dnssec_prover_test");
		} else { panic!(); }
		if let RR::CName(cname) = &verified_rrs.verified_rrs[2] {
			assert_eq!(cname.name.as_str(), "cname_test.matcorallo.com.");
			assert_eq!(cname.canonical_name.as_str(), "txt_test.matcorallo.com.");
		} else { panic!(); }
	}

	#[test]
	fn check_wildcard_record() {
		let dnskeys = matcorallo_dnskey().0;
		let (txt, txt_rrsig) = matcorallo_wildcard_record();
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_wildcard_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in com_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in matcorallo_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (cname, cname_rrsig, txt, txt_rrsig) = matcorallo_cname_wildcard_record();
		for rr in [RR::CName(cname), RR::RRSig(cname_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let mut verified_rrs = verify_rr_stream(&rrs).unwrap();
		verified_rrs.verified_rrs.sort();
		assert_eq!(verified_rrs.verified_rrs.len(), 2);
		if let RR::Txt(txt) = &verified_rrs.verified_rrs[0] {
			assert_eq!(txt.name.as_str(), "cname.wildcard_test.matcorallo.com.");
			assert_eq!(txt.data, b"wildcard_test");
		} else { panic!(); }
		if let RR::CName(cname) = &verified_rrs.verified_rrs[1] {
			assert_eq!(cname.name.as_str(), "test.cname_wildcard_test.matcorallo.com.");
			assert_eq!(cname.canonical_name.as_str(), "cname.wildcard_test.matcorallo.com.");
		} else { panic!(); }
	}

	#[test]
	fn check_txt_sort_order() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in com_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in matcorallo_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (mut txts, rrsig) = matcorallo_txt_sort_edge_cases_records();
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

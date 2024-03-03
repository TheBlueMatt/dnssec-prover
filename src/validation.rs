//! Utilities to deserialize and validate RFC 9102 proofs

use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use alloc::vec;
use core::cmp::{self, Ordering};

use ring::signature;

use crate::base32;
use crate::crypto;
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

			let mut hash_ctx = match sig.alg {
				8 => crypto::hash::Hasher::sha256(),
				10 => crypto::hash::Hasher::sha512(),
				13 => crypto::hash::Hasher::sha256(),
				//TODO: 14 => crypto::hash::Hasher::sha384(),
				15 => crypto::hash::Hasher::sha512(),
				_ => return Err(ValidationError::UnsupportedAlgorithm),
			};

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
				let record_labels = record.name().labels() as usize;
				let labels = sig.labels.into();
				// For NSec types, the name should already match the wildcard, so we don't do any
				// filtering here. This is relied upon in `verify_rr_stream` to check whether an
				// NSec record is matching via wildcard (as otherwise we'd allow a resolver to
				// change the name out from under us and change the wildcard to something else).
				if record.ty() != NSec::TYPE && record_labels != labels {
					if record_labels < labels { return Err(ValidationError::Invalid); }
					let signed_name = record.name().trailing_n_labels(sig.labels);
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
					hash_ctx.update(&signed_data);
					let hash = hash_ctx.finish();
					crypto::rsa::validate_rsa(&dnskey.pubkey, &sig.signature, hash.as_ref())
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

			// Note that technically there could be a key tag collision here, causing spurious
			// verification failure. In most zones, there's only 2-4 DNSKEY entries, meaning a
			// spurious collision shouldn't be much more often than one every billion zones. Much
			// more likely in such a case, someone is just trying to do a KeyTrap attack, so we
			// simply hard-fail and return an error immediately.
			sig_validation?;

			return Ok(());
		}
	}
	Err(ValidationError::Invalid)
}

/// Verify [`RRSig`]s over [`DnsKey`], returning a reference to the [`RRSig`] that matched, if any.
fn verify_dnskeys<'r, 'd, RI, R, DI, D>(sigs: RI, dses: DI, records: Vec<&DnsKey>)
-> Result<&'r RRSig, ValidationError>
where RI: IntoIterator<IntoIter = R>, R: Iterator<Item = &'r RRSig>,
      DI: IntoIterator<IntoIter = D>, D: Iterator<Item = &'d DS> + Clone {
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
				let mut ctx = match ds.digest_type {
					1 if trust_sha1 => crypto::hash::Hasher::sha1(),
					2 => crypto::hash::Hasher::sha256(),
					// TODO: 4 => crypto::hash::Hasher::sha384(),
					_ => continue,
				};
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

	let mut found_unsupported_alg = false;
	for sig in sigs {
		match verify_rrsig(sig, validated_dnskeys.iter().map(|k| *k), records.clone()) {
			Ok(()) => return Ok(sig),
			Err(ValidationError::UnsupportedAlgorithm) => {
				// There may be redundant signatures by different keys, where one we don't
				// supprt and another we do. Ignore ones we don't support, but if there are
				// no more, return UnsupportedAlgorithm
				found_unsupported_alg = true;
			},
			Err(ValidationError::Invalid) => {
				// If a signature is invalid, just immediately fail, avoiding KeyTrap issues.
				return Err(ValidationError::Invalid);
			},
		}
	}

	if found_unsupported_alg {
		Err(ValidationError::UnsupportedAlgorithm)
	} else {
		Err(ValidationError::Invalid)
	}
}

/// Given a set of [`RR`]s, [`verify_rr_stream`] checks what it can and returns the set of
/// non-[`RRSig`]/[`DnsKey`]/[`DS`] records which it was able to verify using this struct.
///
/// It also contains signing and expiry times, which must be validated before considering the
/// contained records verified.
#[derive(Debug, Clone)]
pub struct VerifiedRRStream<'a> {
	/// The set of verified [`RR`]s, not including [`DnsKey`], [`RRSig`], [`NSec`], and [`NSec3`]
	/// records.
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

fn nsec_ord(a: &str, b: &str) -> Ordering {
	let mut a_label_iter = a.rsplit(".");
	let mut b_label_iter = b.rsplit(".");
	loop {
		match (a_label_iter.next(), b_label_iter.next()) {
			(Some(_), None) => return Ordering::Greater,
			(None, Some(_)) => return Ordering::Less,
			(Some(a_label), Some(b_label)) => {
				let mut a_bytes = a_label.bytes();
				let mut b_bytes = b_label.bytes();
				loop {
					match (a_bytes.next(), b_bytes.next()) {
						(Some(_), None) => return Ordering::Greater,
						(None, Some(_)) => return Ordering::Less,
						(Some(mut a), Some(mut b)) => {
							if a >= 'A' as u8 && a <= 'Z' as u8 {
								a += 'a' as u8 - 'A' as u8;
							}
							if b >= 'A' as u8 && b <= 'Z' as u8 {
								b += 'a' as u8 - 'A' as u8;
							}
							if a != b { return a.cmp(&b); }
						},
						(None, None) => break,
					}
				}
			},
			(None, None) => return Ordering::Equal,
		}
	}
}
fn nsec_ord_extra<T, U>(a: &(&str, T, U), b: &(&str, T, U)) -> Ordering {
	nsec_ord(a.0, b.0)
}

#[cfg(test)]
#[test]
fn rfc4034_sort_test() {
	// Test nsec_ord based on RFC 4034 section 6.1's example
	// Note that we replace the \200 example  with \7f as I have no idea what \200 is
	let v = vec!["example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.",
		"zABC.a.EXAMPLE.", "z.example.", "\001.z.example.", "*.z.example.", "\x7f.z.example."];
	let mut sorted = v.clone();
	sorted.sort_unstable_by(|a, b| nsec_ord(*a, *b));
	assert_eq!(sorted, v);
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
	let mut rrs_needing_non_existence_proofs = Vec::new();
	let mut pending_ds_sets = Vec::with_capacity(1);
	let mut latest_inception = 0;
	let mut earliest_expiry = u64::MAX;
	let mut min_ttl = u32::MAX;
	'next_zone: while zone == "." || !pending_ds_sets.is_empty() {
		let next_ds_set;
		if let Some((next_zone, ds_set)) = pending_ds_sets.pop() {
			next_ds_set = Some(ds_set);
			zone = next_zone;
		} else {
			debug_assert_eq!(zone, ".");
			next_ds_set = None;
		}

		let dnskey_rrsigs = inp.iter()
			.filter_map(|rr| if let RR::RRSig(sig) = rr { Some(sig) } else { None })
			.filter(|rrsig| rrsig.name.as_str() == zone && rrsig.ty == DnsKey::TYPE);
		let dnskeys = inp.iter()
			.filter_map(|rr| if let RR::DnsKey(dnskey) = rr { Some(dnskey) } else { None })
			.filter(move |dnskey| dnskey.name.as_str() == zone);
		let root_hints = root_hints();
		let verified_dnskey_rrsig = if zone == "." {
			verify_dnskeys(dnskey_rrsigs, &root_hints, dnskeys.clone().collect())?
		} else {
			debug_assert!(next_ds_set.is_some());
			if next_ds_set.is_none() { break 'next_zone; }
			verify_dnskeys(dnskey_rrsigs, next_ds_set.clone().unwrap(), dnskeys.clone().collect())?
		};
		latest_inception = cmp::max(latest_inception, resolve_time(verified_dnskey_rrsig.inception));
		earliest_expiry = cmp::min(earliest_expiry, resolve_time(verified_dnskey_rrsig.expiration));
		min_ttl = cmp::min(min_ttl, verified_dnskey_rrsig.orig_ttl);
		for rrsig in inp.iter()
			.filter_map(|rr| if let RR::RRSig(sig) = rr { Some(sig) } else { None })
			.filter(move |rrsig| rrsig.key_name.as_str() == zone && rrsig.ty != DnsKey::TYPE)
		{
			if !rrsig.name.ends_with(zone) { return Err(ValidationError::Invalid); }
			let signed_records = inp.iter()
				.filter(|rr| rr.name() == &rrsig.name && rr.ty() == rrsig.ty);
			match verify_rrsig(rrsig, dnskeys.clone(), signed_records.clone().collect()) {
				Ok(()) => {},
				Err(ValidationError::UnsupportedAlgorithm) => continue,
				Err(ValidationError::Invalid) => {
					// If a signature is invalid, just immediately fail, avoiding KeyTrap issues.
					return Err(ValidationError::Invalid);
				}
			}
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
					if rrsig.labels != rrsig.name.labels() && rrsig.ty != NSec::TYPE {
						if rrsig.ty == NSec3::TYPE {
							// NSEC3 records should never appear on wildcards, so treat the
							// whole proof as invalid
							return Err(ValidationError::Invalid);
						}
						// If the RR used a wildcard, we need an NSEC/NSEC3 proof, which we
						// check for at the end. Note that the proof should be for the
						// "next closest" name, i.e. if the name here is a.b.c and it was
						// signed as *.c, we want a proof for nothing being in b.c.
						// Alternatively, if it was signed as *.b.c, we'd want a proof for
						// a.b.c.
						let proof_name = rrsig.name.trailing_n_labels(rrsig.labels + 1)
							.ok_or(ValidationError::Invalid)?;
						rrs_needing_non_existence_proofs.push((proof_name, &rrsig.key_name, rrsig.ty));
					}
					for record in signed_records {
						if !res.contains(&record) { res.push(record); }
					}
				},
			}
		}
		continue 'next_zone;
	}
	if res.is_empty() { return Err(ValidationError::Invalid) }
	if latest_inception >= earliest_expiry { return Err(ValidationError::Invalid) }

	// First sort the proofs we're looking for so that the retains below avoid shifting.
	rrs_needing_non_existence_proofs.sort_unstable_by(nsec_ord_extra);
	'proof_search_loop: while let Some((name, zone, ty)) = rrs_needing_non_existence_proofs.pop() {
		let nsec_search = res.iter()
			.filter_map(|rr| if let RR::NSec(nsec) = rr { Some(nsec) } else { None })
			.filter(|nsec| nsec.name.ends_with(zone.as_str()));
		for nsec in nsec_search {
			let name_matches = nsec.name.as_str() == name;
			let name_contained = nsec_ord(&nsec.name,  &name) != Ordering::Greater &&
				nsec_ord(&nsec.next_name, name) == Ordering::Greater;
			if (name_matches && !nsec.types.contains_type(ty)) || name_contained {
				rrs_needing_non_existence_proofs
					.retain(|(n, _, t)| *n != name || (name_matches && nsec.types.contains_type(*t)));
				continue 'proof_search_loop;
			}
		}
		let nsec3_search = res.iter()
			.filter_map(|rr| if let RR::NSec3(nsec3) = rr { Some(nsec3) } else { None })
			.filter(|nsec3| nsec3.name.ends_with(zone.as_str()));

		// Because we will only ever have two entries, a Vec is simpler than a map here.
		let mut nsec3params_to_name_hash = Vec::new();
		for nsec3 in nsec3_search.clone() {
			if nsec3.hash_iterations > 2500 {
				// RFC 5115 places different limits on the iterations based on the signature key
				// length, but we just use 2500 for all key types
				continue;
			}
			if nsec3.hash_algo != 1 { continue; }
			if nsec3params_to_name_hash.iter()
				.any(|(iterations, salt, _)| *iterations == nsec3.hash_iterations && *salt == &nsec3.salt)
			{ continue; }

			let mut hasher = crypto::hash::Hasher::sha1();
			write_name(&mut hasher, &name);
			hasher.update(&nsec3.salt);
			for _ in 0..nsec3.hash_iterations {
				let res = hasher.finish();
				hasher = crypto::hash::Hasher::sha1();
				hasher.update(res.as_ref());
				hasher.update(&nsec3.salt);
			}
			nsec3params_to_name_hash.push((nsec3.hash_iterations, &nsec3.salt, hasher.finish()));

			if nsec3params_to_name_hash.len() >= 2 {
				// We only allow for up to two sets of hash_iterations/salt per zone. Beyond that
				// we assume this is a malicious DoSing proof and give up.
				break;
			}
		}
		for nsec3 in nsec3_search {
			if nsec3.flags != 0 {
				// This is an opt-out NSEC3 (or has unknown flags set). Thus, we shouldn't rely on
				// it as proof that some record doesn't exist.
				continue;
			}
			if nsec3.hash_algo != 1 { continue; }
			let name_hash = if let Some((_, _, hash)) =
				nsec3params_to_name_hash.iter()
				.find(|(iterations, salt, _)| *iterations == nsec3.hash_iterations && *salt == &nsec3.salt)
			{
				hash
			} else { continue };

			let (start_hash_base32, _) = nsec3.name.split_once(".")
				.unwrap_or_else(|| { debug_assert!(false); ("", "")});
			let start_hash = if let Ok(start_hash) = base32::decode(start_hash_base32) {
				start_hash
			} else { continue };
			if start_hash.len() != 20 || nsec3.next_name_hash.len() != 20 { continue; }

			let hash_matches = &start_hash[..] == name_hash.as_ref();
			let hash_contained =
				&start_hash[..] <= name_hash.as_ref() && &nsec3.next_name_hash[..] > name_hash.as_ref();
			if (hash_matches && !nsec3.types.contains_type(ty)) || hash_contained {
				rrs_needing_non_existence_proofs
					.retain(|(n, _, t)| *n != name || (hash_matches && nsec3.types.contains_type(*t)));
				continue 'proof_search_loop;
			}
		}
		return Err(ValidationError::Invalid);
	}

	res.retain(|rr| rr.ty() != NSec::TYPE && rr.ty() != NSec3::TYPE);

	Ok(VerifiedRRStream {
		verified_rrs: res, valid_from: latest_inception, expires: earliest_expiry,
		max_cache_ttl: min_ttl,
	})
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
			expiration: 1710201600, inception: 1708387200, key_tag: 20326, key_name: ".".try_into().unwrap(),
			signature: base64::decode("GIgwndRLXgt7GX/JNEqSvpYw5ij6EgeQivdC/hmNNuOd2MCQRSxZx2DdLZUoK0tmn2XmOd0vYP06DgkIMUpIXcBstw/Um55WQhvBkBTPIhuB3UvKYJstmq+8hFHWVJwKHTg9xu38JA43VgCV2AbzurbzNOLSgq+rDPelRXzpLr5aYE3y+EuvL+I5gusm4MMajnp5S+ioWOL+yWOnQE6XKoDmlrfcTrYfRSxRtJewPmGeCbNdwEUBOoLUVdkCjQG4uFykcKL40cY8EOhVmM3kXAyuPuNe2Xz1QrIcVad/U4FDns+hd8+W+sWnr8QAtIUFT5pBjXooGS02m6eMdSeU6g==").unwrap(),
		};
		let root_hints = root_hints();
		verify_dnskeys([&dnskey_rrsig], &root_hints, dnskeys.iter().collect()).unwrap();
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
			expiration: 1710133200, inception: 1709006400, key_tag: 30903, key_name: ".".try_into().unwrap(),
			signature: base64::decode("WEf7UPqoulxab83nVy/518TpZcC3og0paZ7Lag5iOqGdmGvZnB0yQ42s25iqB/mL6ZU+sSUwYoclcW36Tv/yHgS813T2wOgQ4Jh01aCsjkjvpgpbtnDTxg8bL30LV1obhQhOBFu5SqD4FOMeaV9Fqcff7Z72vC1UdVy0us2Kbhti3uQYrKQlGYcDMlgQAyOE0WEaLT74YfKFTpZvIK0UfUfdUAAiM0Z6PUi7BoyToIN+eKKPvny/+4BP9iVvAOmPMgr+kq/qIWOdsvUaq/S+k7VEPTJEi+i2gODgbMC+3EZZpZie9kv1EEAwGwBtGjE7bLlA1QUbuVeTgczIzrYriQ==").unwrap(),
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
			expiration: 1710342155, inception: 1709045855, key_tag: 19718, key_name: "com.".try_into().unwrap(),
			signature: base64::decode("lF2B9nXZn0CgytrHH6xB0NTva4G/aWvg/ypnSxJ8+ZXlvR0C4974yB+nd2ZWzWMICs/oPYMKoQHqxVjnGyu8nA==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &com_ds, dnskeys.iter().collect()).unwrap();
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
			expiration: 1710133200, inception: 1709006400, key_tag: 30903, key_name: ".".try_into().unwrap(),
			signature: base64::decode("4fLiekxJy1tHW3sMzmPA/i4Mn6TYoCHDKbcvk3t3N6IXMkACSgU+6P5NxSMxo5Xa7YL5UuE1ICDKxel5o5WzyvjaRQA//hZomjwnCzqyG2XoS6Va8cULSOA5jOU153NSCvos39iHeJnuPINzbMAfsKcg6Ib/IDmNnpouQF53hQzVy+5MGLlGPUZjSO6b4GIslyKpLG0tBLKXM5rZXREPJClEY+LWKOtAS1iARqdsWmSnKxZCpgnEjmkqJBtjCus+s6AtMteBHIFyebwA7oUDNtJ3Im1dO5b6sUoGP8gUgnqdFELSLEeEhKYKpO+jSruI8g/gjNIb5C9vDwAtcSoAew==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &root_dnskeys, ninja_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAb6FWe0O0qxUkA+LghF71OPWt0WNqBaCi34HCV6Agjz70RN/j7yGi3xCExM8MkzyrbXd5yYFP4X7TCGEzI5ofLNq7GVIj9laZO0WYS8DNdCMN7qkVVaYeR2UeeGsdvIJqRWzlynABAKnCzX+y5np77FBsle4cAIGxJE/0F5kn61F").unwrap(),
		}, DnsKey {
			name: "ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAZlkeshgX2Q9i/X4zZMc2ciKO2a3+mOiOCuYHYbwt/43XXdcHdjtOUrWFFJkGBBWsHQZ/Bg0CeUGqvUGywd3ndY5IAX+e7PnuIUlhKDcNmntcQbxhrH+cpmOoB3Xo/96JoVjurPxTuJE23I1oA+0aESc581f4pKEbTp4WI7m5xNn").unwrap(),
		}, DnsKey {
			name: "ninja.".try_into().unwrap(), flags: 257, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAcceTJ3Ekkmiez70L8uNVrTDrHZxXHrQHEHQ1DJZDRXDxizuSy0prDXy1yybMqcKAkPL0IruvJ9vHg5j2eHN/hM8RVqCQ1wHgLdQASyUL37VtmLuyNmuiFpYmT+njXVh/tzRHZ4cFxrLAtACWDe6YaPApnVkJ0FEcMnKCQaymBaLX02WQOYuG3XdBr5mQQTtMs/kR/oh83QBcSxyCg3KS7G8IPP6MQPK0za94gsW9zlI5rgN2gpSjbU2qViGjDhw7N3PsC37PLTSLirUmkufeMkP9sfhDjAbP7Nv6FmpTDAIRmBmV0HBT/YNBTUBP89DmEDsrYL8knjkrOaLqV5wgkk=").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "ninja.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 8, labels: 1, orig_ttl: 3600,
			expiration: 1710689605, inception: 1708871605, key_tag: 46082, key_name: "ninja.".try_into().unwrap(),
			signature: base64::decode("kYxV1z+9Ikxqbr13N+8HFWWnAUcvHkr/dmkdf21mliUhH4cxeYCXC6a95X+YzjYQEQi3fU+S346QBDJkbFYCca5q/TzUdE7ej1B/0uTzhgNrQznm0O6sg6DI3HuqDfZp2oaBQm2C/H4vjkcUW9zxgKP8ON0KKLrZUuYelGazeGSOscjDDlmuNMD7tHhFrmK9BiiX+8sp8Cl+IE5ArP+CPXsII+P+R2QTmTqw5ovJch2FLRMRqCliEzTR/IswBI3FfegZR8h9xJ0gfyD2rDqf6lwJhD1K0aS5wxia+bgzpRIKwiGfP87GDYzkygHr83QbmZS2YG1nxlnQ2rgkqTGgXA==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &ninja_ds, dnskeys.iter().collect()).unwrap();
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
			expiration: 1709359258, inception: 1708750258, key_tag: 4534, key_name: "com.".try_into().unwrap(),
			signature: base64::decode("VqYztN78+g170QPeFOqWFkU1ZrKIsndUYj3Y+8x1ZR1v/YGJXLQe5qkcLWjrl/vMyCgknC3Q/dhcS2ag0a7W1w==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &com_dnskeys, mattcorallo_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "mattcorallo.com.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("8BP51Etiu4V6cHvGCYqwNqCip4pvHChjEgkgG4zpdDvO9YRcTGuV/p71hAUut2/qEdxqXfUOT/082BJ/Z089DA==").unwrap(),
		}, DnsKey {
			name: "mattcorallo.com.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("AhUlQ8qk7413R0m4zKfTDHb/FQRlKag+ncGXxNxT+qTzSZTb9E5IGjo9VCEp6+IMqqpkd4GrXpN9AzDvlcU9Ig==").unwrap(),
		}, DnsKey {
			name: "mattcorallo.com.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("s165ZpubX31FC2CVeIVVvnPpTnJUoOM8CGt3wk4AtxPftYadgI8uFM43F4QaD67v8B8Vshl63frxN50dc44VHQ==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "mattcorallo.com.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 13, labels: 2, orig_ttl: 604800,
			expiration:1710262250, inception: 1709047250, key_tag: 25630, key_name: "mattcorallo.com.".try_into().unwrap(),
			signature: base64::decode("dMLDvNU96m+tfgpDIQPxMBJy7T0xyZDj3Wws4b4E6+g3nt5iULdWJ8Eqrj+86KLerOVt7KH4h/YcHP18hHdMGA==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &mattcorallo_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![mattcorallo_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskeys[2].clone().into(),
			dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn mattcorallo_txt_record() -> (Txt, RRSig) {
		let txt_resp = Txt {
			name: "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap(),
			data: "bitcoin:?b12=lno1qsgqmqvgm96frzdg8m0gc6nzeqffvzsqzrxqy32afmr3jn9ggkwg3egfwch2hy0l6jut6vfd8vpsc3h89l6u3dm4q2d6nuamav3w27xvdmv3lpgklhg7l5teypqz9l53hj7zvuaenh34xqsz2sa967yzqkylfu9xtcd5ymcmfp32h083e805y7jfd236w9afhavqqvl8uyma7x77yun4ehe9pnhu2gekjguexmxpqjcr2j822xr7q34p078gzslf9wpwz5y57alxu99s0z2ql0kfqvwhzycqq45ehh58xnfpuek80hw6spvwrvttjrrq9pphh0dpydh06qqspp5uq4gpyt6n9mwexde44qv7lstzzq60nr40ff38u27un6y53aypmx0p4qruk2tf9mjwqlhxak4znvna5y".to_owned().into_bytes(),
		};
		let txt_rrsig = RRSig {
			name: "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 3600, expiration: 1710182540,
			inception: 1708967540, key_tag: 47959, key_name: "mattcorallo.com.".try_into().unwrap(),
			signature: base64::decode("vwI89CkCzWI2Iwgl3UeiSo4GKSaKCh7/E/7nE8Hbb1WQvdpwdKSB6jE4nwM1BN4wdPhi7kxd7hyS/uGiKZjxsg==").unwrap(),
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
			expiration: 1710689605, inception: 1708871605, key_tag: 34164, key_name: "ninja.".try_into().unwrap(),
			signature: base64::decode("g/Xyv6cwrGlpEyhXDV1vdKpoy9ZH7HF6MK/41q0GyCrd9wL8BrzKQgwvLqOBhvfUWACJd66CJpEMZnSwH8ZDEcWYYsd8nY2giGX7In/zGz+PA35HlFqy2BgvQcWCaN5Ht/+BUTgZXHbJBEko1iWLZ1yhciD/wA+XTqS7ScQUu88=").unwrap(),
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
			expiration: 1709947337, inception: 1708732337, key_tag: 63175, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("Y3To5FZoZuBDUMtIBZXqzRtufyRqOlDqbHVcoZQitXxerCgNQ1CsVdmoFVMmZqRV5n4itINX2x+9G/31j410og==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &bitcoin_ninja_ds, dnskeys.iter().collect()).unwrap();
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
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1709950937,
			inception: 1708735937, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("S5swe6BMTqwLBU6FH2D50j5A9i5hzli79Vlf5xB515s6YhmcqodbPZnFlN49RdBE43PKi9MJcXpHTiBxvTYBeQ==").unwrap(),
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
			ty: CName::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1709950937,
			inception: 1708735937, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("S8AYftjBADKutt4XKVzqfY7EpvbanpwOGhMDk0lEDFpvNRjl0fZ1k/FEW6AXSUyX2wOaX8hvwXUuZjpr5INuMw==").unwrap(),
		};
		(cname_resp, cname_rrsig)
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
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1709950937,
			inception: 1708735937, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("kUKbtoNYM6qnu95QJoyUwtzZoMTcRVfNfIIqSwROLdMYqqq70REjCu99ecjOW/Zm2XRsJ9KgGBB/SuiBdunLew==").unwrap(),
		};
		(txts, rrsig)
	}

	/// Note that the NSEC3 proofs here are for asdf., any other prefix may fail NSEC checks.
	fn bitcoin_ninja_wildcard_record(pfx: &str) -> (Txt, RRSig, NSec3, RRSig) {
		let name: Name = (pfx.to_owned() + ".wildcard_test.dnssec_proof_tests.bitcoin.ninja.").try_into().unwrap();
		let txt_resp = Txt {
			name: name.clone(),
			data: "wildcard_test".to_owned().into_bytes(),
		};
		let txt_rrsig = RRSig {
			name: name.clone(),
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1709950937,
			inception: 1708735937, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("Y+grWXzbZfrcoHRZC9kfRzWp002jZzBDmpSQx6qbUgN0x3aH9kZIOVy0CtQH2vwmLUxoJ+RlezgunNI6LciBzQ==").unwrap(),
		};
		let nsec3 = NSec3 {
			name: "s5sn15c8lcpo7v7f1p0ms6vlbdejt0kd.bitcoin.ninja.".try_into().unwrap(),
			hash_algo: 1, flags: 0, hash_iterations: 0, salt: Vec::from_hex("059855BD1077A2EB").unwrap(),
			next_name_hash: crate::base32::decode("T8QO5GO6M76HBR5Q6T3G6BDR79KBMDSA").unwrap(),
			types: NSecTypeMask::from_types(&[AAAA::TYPE, RRSig::TYPE]),
		};
		let nsec3_rrsig = RRSig {
			name: "s5sn15c8lcpo7v7f1p0ms6vlbdejt0kd.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec3::TYPE, alg: 13, labels: 3, orig_ttl: 60, expiration: 1710267741,
			inception: 1709052741, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("Aiz6My3goWQuIIw/XNUo+kICsp9e4C5XUUs/0Ap+WIEFJsaN/MPGegiR/c5GUGdtHt1GdeP9CU3H1OGkN9MpWQ==").unwrap(),
		};
		(txt_resp, txt_rrsig, nsec3, nsec3_rrsig)
	}

	fn bitcoin_ninja_cname_wildcard_record() -> (CName, RRSig, Txt, RRSig, [(NSec3, RRSig); 3]) {
		let cname_resp = CName {
			name: "asdf.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			canonical_name: "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
		};
		let cname_rrsig = RRSig {
			name: "asdf.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: CName::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1709950937,
			inception: 1708735937, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("qR/zy8JyihI4qCAMwn7jGU6FARW/Hl8/u+cajef9raKs5aOxnZpCrp19Tot9qPG6px9PzqaghAIP1EmxfgxtRQ==").unwrap(),
		};
		let nsec3_a = NSec3 {
			name: "2tn37cu4ulmlqqke9a3dc9g8bt8b4f6s.bitcoin.ninja.".try_into().unwrap(),
			hash_algo: 1, flags: 0, hash_iterations: 0,
			salt: Vec::from_hex("059855BD1077A2EB").unwrap(),
			next_name_hash: crate::base32::decode("4OKFHSHS41D00EDL0HNPMT7R6IKMJ48H").unwrap(),
			types: NSecTypeMask::from_types(&[DName::TYPE, RRSig::TYPE]),
		};
		let nsec3_a_rrsig = RRSig {
			name: "2tn37cu4ulmlqqke9a3dc9g8bt8b4f6s.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec3::TYPE, alg: 13, labels: 3, orig_ttl: 60, expiration: 1710266541,
			inception: 1709051541, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("tSsPsYIf1o5+piUZX9YwcWKSZgVQOB37TRdb+VL0PmcPaLpzFGJCwU0snn8tMN/BuILG+KZY+UPmAEZZFz4Fvg==").unwrap(),
		};
		let nsec3_b = NSec3 {
			name: "cjqf7lfu6ev77k9m2o6iih56kbfnshin.bitcoin.ninja.".try_into().unwrap(),
			hash_algo: 1, flags: 0, hash_iterations: 0,
			salt: Vec::from_hex("059855BD1077A2EB").unwrap(),
			next_name_hash: crate::base32::decode("DD3MT23L63OIHQPIMA5O2NULSVIGIJ3N").unwrap(),
			types: NSecTypeMask::from_types(&[A::TYPE, AAAA::TYPE, RRSig::TYPE]),
		};
		let nsec3_b_rrsig = RRSig {
			name: "cjqf7lfu6ev77k9m2o6iih56kbfnshin.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec3::TYPE, alg: 13, labels: 3, orig_ttl: 60, expiration: 1710238940,
			inception: 1709023940, key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("CtYriOUI6RzoIG3SigHbBYiTkrEvmSEvP+aOLo1wylqkbBT2iG7pK8VNucKETqMZCROLnmRBw8DHK/8rosKYsA==").unwrap(),
		};
		let (txt_resp, txt_rrsig, nsec3_c, nsec3_c_rrsig) = bitcoin_ninja_wildcard_record("asdf");
		(cname_resp, cname_rrsig, txt_resp, txt_rrsig,
			[(nsec3_a, nsec3_a_rrsig), (nsec3_b, nsec3_b_rrsig), (nsec3_c, nsec3_c_rrsig)])
	}

	fn bitcoin_ninja_nsec_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let bitcoin_ninja_dnskeys = bitcoin_ninja_dnskey().0;
		let mut bitcoin_ninja_ds = vec![DS {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			key_tag: 8036, alg: 13, digest_type: 2,
			digest: Vec::from_hex("8EC0DAE4501233979196EBED206212BCCC49E40E086EC2E56558EC1F6FB62715").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: DS::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1710190967, inception: 1708975967,
			key_tag: 37639, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("qUexI1yufru0lzkND4uY1r8bsXrXnMVNjPxTLbLauRo/+YW041w9wFu4sl2/cqq3psWvGcBVTltwIdjDJQUcZQ==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &bitcoin_ninja_dnskeys, bitcoin_ninja_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("MUnIhm31ySIr9WXIBVQc38wlSHHvYaKIOFR8WYl4O9MJBlywWeUdx16oGinCe2FjjMkUkKn9kV5zzWhGmrdIbQ==").unwrap(),
		}, DnsKey {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("GGZP8k44sro2iTzWKFoHOnbvrAhNiQv+Ng2hr0WNyb24aA5rLYLFac3N7B82xRU2odd60utYJkmU0yA//zyOzw==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: DnsKey::TYPE, alg: 13, labels: 4, orig_ttl: 604800, expiration: 1710190613, inception: 1708975613,
			key_tag: 8036, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("nX+hkH14Kvjp26Z8x/pjYh5CQW3p9lZQQ+FVJcKHyfjAilEubpw6ihlPpb3Ddh9BbyxhCEFhXDMG2g4od9Y2ow==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &bitcoin_ninja_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![bitcoin_ninja_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn bitcoin_ninja_nsec_record() -> (Txt, RRSig) {
		let txt_resp = Txt {
			name: "a.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "txt_a".to_owned().into_bytes(),
		};
		let txt_rrsig = RRSig {
			name: "a.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 30, expiration: 1710201091, inception: 1708986091,
			key_tag: 42215, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("rhDcZvSk4ngyDmMif3oBmoDMO1YoimRrvOp/ErlSaujN+OCMKocgWkssedQCx7hyLxwsFLvaaiNXCr/7ZaSe4Q==").unwrap(),
		};
		(txt_resp, txt_rrsig)
	}

	fn bitcoin_ninja_nsec_wildcard_record(pfx: &str) -> (Txt, RRSig, NSec, RRSig) {
		let name: Name = (pfx.to_owned() + ".wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.").try_into().unwrap();
		let txt_resp = Txt {
			name: name.clone(),
			data: "wildcard_test".to_owned().into_bytes(),
		};
		let txt_rrsig = RRSig {
			name: name.clone(),
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 30, expiration: 1710190613, inception: 1708975613,
			key_tag: 42215, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("E3+tEe5TxI8OSNP+LVHsOagjQ/9heD6a4ICYBgS8mkfRuqgFeXhz22n4f2LzssdXe1xzwayt7nROdHdqdfHDYg==").unwrap(),
		};
		let nsec = NSec {
			name: "*.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			next_name: "override.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			types: NSecTypeMask::from_types(&[Txt::TYPE, RRSig::TYPE, NSec::TYPE]),
		};
		let nsec_rrsig = RRSig {
			name: "*.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec::TYPE, alg: 13, labels: 5, orig_ttl: 60, expiration: 1710191561, inception: 1708976561,
			key_tag: 42215, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("ZjQMw1dt1a61d4ls3pMkCnBiWRaMyAwn6UapRaYNtdA8cTbbqbhzJZCvc6ZBhZ90CzxCYR0h/eavowlF1j53Gg==").unwrap(),
		};
		(txt_resp, txt_rrsig, nsec, nsec_rrsig)
	}

	fn bitcoin_ninja_nsec_post_override_wildcard_record(pfx: &str) -> (Txt, RRSig, NSec, RRSig) {
		let name: Name = (pfx.to_owned() + ".wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.").try_into().unwrap();
		let txt_resp = Txt {
			name: name.clone(),
			data: "wildcard_test".to_owned().into_bytes(),
		};
		let txt_rrsig = RRSig {
			name: name.clone(),
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 30, expiration: 1710190613, inception: 1708975613,
			key_tag: 42215, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("E3+tEe5TxI8OSNP+LVHsOagjQ/9heD6a4ICYBgS8mkfRuqgFeXhz22n4f2LzssdXe1xzwayt7nROdHdqdfHDYg==").unwrap(),
		};
		let nsec = NSec {
			name: "override.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			next_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			types: NSecTypeMask::from_types(&[Txt::TYPE, RRSig::TYPE, NSec::TYPE]),
		};
		let nsec_rrsig = RRSig {
			name: "override.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec::TYPE, alg: 13, labels: 6, orig_ttl: 60, expiration: 1710201063, inception: 1708986063,
			key_tag: 42215, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("pBNXnNPR0fiGEtkm/0PlnDW830JWv8KgnyhnOit6wLHtiWoLhMiS48utji3FbTfelCnePjbLh/t7SF941O2QTA==").unwrap(),
		};
		(txt_resp, txt_rrsig, nsec, nsec_rrsig)
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
		assert_eq!(verified_rrs.valid_from, 1709047250); // The mattcorallo.com. DNSKEY RRSig was created last
		assert_eq!(verified_rrs.expires, 1709359258); // The mattcorallo.com. DS RRSig expires first
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
		// Wildcard proof works for any name, even multiple names
		let dnskeys = bitcoin_ninja_dnskey().0;
		let (txt, txt_rrsig, _, _) = bitcoin_ninja_wildcard_record("name");
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();

		let (txt, txt_rrsig, _, _) = bitcoin_ninja_wildcard_record("anoter_name");
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();

		let (txt, txt_rrsig, _, _) = bitcoin_ninja_wildcard_record("multiple.names");
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_wildcard_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (cname, cname_rrsig, txt, txt_rrsig, nsec3s) = bitcoin_ninja_cname_wildcard_record();
		for rr in [RR::CName(cname), RR::RRSig(cname_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		for (rra, rrb) in nsec3s { write_rr(&rra, 1, &mut rr_stream); write_rr(&rrb, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let mut verified_rrs = verify_rr_stream(&rrs).unwrap();
		verified_rrs.verified_rrs.sort();
		assert_eq!(verified_rrs.verified_rrs.len(), 2);
		if let RR::Txt(txt) = &verified_rrs.verified_rrs[0] {
			assert_eq!(txt.name.as_str(), "asdf.wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data, b"wildcard_test");
		} else { panic!(); }
		if let RR::CName(cname) = &verified_rrs.verified_rrs[1] {
			assert_eq!(cname.name.as_str(), "asdf.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(cname.canonical_name.as_str(), "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
		} else { panic!(); }

		let filtered_rrs =
			verified_rrs.resolve_name(&"asdf.wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap());
		assert_eq!(filtered_rrs.len(), 1);
		if let RR::Txt(txt) = &filtered_rrs[0] {
			assert_eq!(txt.name.as_str(), "asdf.wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data, b"wildcard_test");
		} else { panic!(); }
	}

	#[test]
	fn check_simple_nsec_zone_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_nsec_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txt, txt_rrsig) = bitcoin_ninja_nsec_record();
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		let filtered_rrs =
			verified_rrs.resolve_name(&"a.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap());
		assert_eq!(filtered_rrs.len(), 1);
		if let RR::Txt(txt) = &filtered_rrs[0] {
			assert_eq!(txt.name.as_str(), "a.nsec_tests.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data, b"txt_a");
		} else { panic!(); }
	}

	#[test]
	fn check_nsec_wildcard_proof() {
		let check_proof = |pfx: &str, post_override: bool| -> Result<(), ()> {
			let mut rr_stream = Vec::new();
			for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_nsec_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			let (txt, txt_rrsig, nsec, nsec_rrsig) = if post_override {
				bitcoin_ninja_nsec_post_override_wildcard_record(pfx)
			} else {
				bitcoin_ninja_nsec_wildcard_record(pfx)
			};
			for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
			for rr in [RR::NSec(nsec), RR::RRSig(nsec_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

			let mut rrs = parse_rr_stream(&rr_stream).unwrap();
			rrs.shuffle(&mut rand::rngs::OsRng);
			// If the post_override flag is wrong (or the pfx is override), this will fail. No
			// other calls in this lambda should fail.
			let verified_rrs = verify_rr_stream(&rrs).map_err(|_| ())?;
			let name: Name =
				(pfx.to_owned() + ".wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.").try_into().unwrap();
			let filtered_rrs = verified_rrs.resolve_name(&name);
			assert_eq!(filtered_rrs.len(), 1);
			if let RR::Txt(txt) = &filtered_rrs[0] {
				assert_eq!(txt.name, name);
				assert_eq!(txt.data, b"wildcard_test");
			} else { panic!(); }
			Ok(())
		};
		// Records up to override will only work with the pre-override NSEC, and afterwards with
		// the post-override NSEC. The literal override will always fail.
		check_proof("a", false).unwrap();
		check_proof("a", true).unwrap_err();
		check_proof("a.b", false).unwrap();
		check_proof("a.b", true).unwrap_err();
		check_proof("o", false).unwrap();
		check_proof("o", true).unwrap_err();
		check_proof("a.o", false).unwrap();
		check_proof("a.o", true).unwrap_err();
		check_proof("override", false).unwrap_err();
		check_proof("override", true).unwrap_err();
		// Subdomains of override are also overridden by the override TXT entry and cannot use the
		// wildcard record.
		check_proof("b.override", false).unwrap_err();
		check_proof("b.override", true).unwrap_err();
		check_proof("z", false).unwrap_err();
		check_proof("z", true).unwrap_err();
		check_proof("a.z", false).unwrap_err();
		check_proof("a.z", true).unwrap_err();
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

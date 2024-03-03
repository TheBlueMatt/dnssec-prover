//! Simple variable-time big integer implementation

use alloc::vec::Vec;

const WORD_COUNT_4096: usize = 4096 / 64;

// RFC 5702 indicates RSA keys can be up to 4096 bits
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct U4096([u64; WORD_COUNT_4096]);

macro_rules! debug_unwrap { ($v: expr) => { {
	let v = $v;
	debug_assert!(v.is_ok());
	match v {
		Ok(r) => r,
		Err(e) => return Err(e),
	}
} } }

// Various const versions of existing slice utilities
/// Const version of `&a[start..end]`
const fn const_subslice<'a, T>(a: &'a [T], start: usize, end: usize) -> &'a [T] {
	assert!(start <= a.len());
	assert!(end <= a.len());
	assert!(end >= start);
	let mut startptr = a.as_ptr();
	startptr = unsafe { startptr.add(start) };
	let len = end - start;
	// The docs for from_raw_parts do not mention any requirements that the pointer be valid if the
	// length is zero, aside from requiring proper alignment (which is met here). Thus,
	// one-past-the-end should be an acceptable pointer for a 0-length slice.
	unsafe { alloc::slice::from_raw_parts(startptr, len) }
}

/// Const version of `dest[dest_start..dest_end].copy_from_slice(source)`
///
/// Once `const_mut_refs` is stable we can convert this to a function
macro_rules! copy_from_slice {
	($dest: ident, $dest_start: expr, $dest_end: expr, $source: ident) => { {
		let dest_start = $dest_start;
		let dest_end = $dest_end;
		assert!(dest_start <= $dest.len());
		assert!(dest_end <= $dest.len());
		assert!(dest_end >= dest_start);
		assert!(dest_end - dest_start == $source.len());
		let mut i = 0;
		while i < $source.len() {
			$dest[i + dest_start] = $source[i];
			i += 1;
		}
	} }
}

/// Const version of a > b
const fn slice_greater_than(a: &[u64], b: &[u64]) -> bool {
	debug_assert!(a.len() == b.len());
	let len = if a.len() <= b.len() { a.len() } else { b.len() };
	let mut i = 0;
	while i < len {
		if a[i] > b[i] { return true; }
		else if a[i] < b[i] { return false; }
		i += 1;
	}
	false // Equal
}

/// Const version of a == b
const fn slice_equal(a: &[u64], b: &[u64]) -> bool {
	debug_assert!(a.len() == b.len());
	let len = if a.len() <= b.len() { a.len() } else { b.len() };
	let mut i = 0;
	while i < len {
		if a[i] != b[i] { return false; }
		i += 1;
	}
	true
}

/// Adds one in-place, returning an overflow flag, in which case one out-of-bounds high bit is
/// implicitly included in the result.
///
/// Once `const_mut_refs` is stable we can convert this to a function
macro_rules! add_one { ($a: ident) => { {
	let len = $a.len();
	let mut i = 0;
	let mut res = true;
	while i < len {
		let (v, carry) = $a[len - 1 - i].overflowing_add(1);
		$a[len - 1 - i] = v;
		if !carry { res = false; break; }
		i += 1;
	}
	res
} } }

/// Negates the given u64 slice.
///
/// Once `const_mut_refs` is stable we can convert this to a function
macro_rules! negate { ($v: ident) => { {
	let mut i = 0;
	while i < $v.len() {
		$v[i] ^= 0xffff_ffff_ffff_ffff;
		i += 1;
	}
	let overflow = add_one!($v);
	debug_assert!(!overflow);
} } }

/// Doubles in-place, returning an overflow flag, in which case one out-of-bounds high bit is
/// implicitly included in the result.
///
/// Once `const_mut_refs` is stable we can convert this to a function
macro_rules! double { ($a: ident) => { {
	{ let _: &[u64] = &$a; } // Force type resolution
	let len = $a.len();
	let mut carry = false;
	let mut i = 0;
	while i < len {
		let mut next_carry = ($a[len - 1 - i] & (1 << 63)) != 0;
		let (v, next_carry_2) = ($a[len - 1 - i] << 1).overflowing_add(carry as u64);
		$a[len - 1 - i] = v;
		debug_assert!(!next_carry || !next_carry_2);
		next_carry |= next_carry_2;
		carry = next_carry;
		i += 1;
	}
	carry
} } }

macro_rules! define_add { ($name: ident, $len: expr) => {
	/// Adds two $len-64-bit integers together, returning a new $len-64-bit integer and an overflow
	/// bit, with the same semantics as the std [`u64::overflowing_add`] method.
	const fn $name(a: &[u64], b: &[u64]) -> ([u64; $len], bool) {
		debug_assert!(a.len() == $len);
		debug_assert!(b.len() == $len);
		let mut r = [0; $len];
		let mut carry = false;
		let mut i = 0;
		while i < $len {
			let pos = $len - 1 - i;
			let (v, mut new_carry) = a[pos].overflowing_add(b[pos]);
			let (v2, new_new_carry) = v.overflowing_add(carry as u64);
			new_carry |= new_new_carry;
			r[pos] = v2;
			carry = new_carry;
			i += 1;
		}
		(r, carry)
	}
} }

define_add!(add_2, 2);
define_add!(add_4, 4);
define_add!(add_8, 8);
define_add!(add_16, 16);
define_add!(add_32, 32);
define_add!(add_64, 64);
define_add!(add_128, 128);

macro_rules! define_sub { ($name: ident, $len: expr) => {
	/// Subtracts the `b` $len-64-bit integer from the `a` $len-64-bit integer, returning a new
	/// $len-64-bit integer and an overflow bit, with the same semantics as the std
	/// [`u64::overflowing_sub`] method.
	const fn $name(a: &[u64], b: &[u64]) -> ([u64; $len], bool) {
		debug_assert!(a.len() == $len);
		debug_assert!(b.len() == $len);
		let mut r = [0; $len];
		let mut carry = false;
		let mut i = 0;
		while i < $len {
			let pos = $len - 1 - i;
			let (v, mut new_carry) = a[pos].overflowing_sub(b[pos]);
			let (v2, new_new_carry) = v.overflowing_sub(carry as u64);
			new_carry |= new_new_carry;
			r[pos] = v2;
			carry = new_carry;
			i += 1;
		}
		(r, carry)
	}
} }

define_sub!(sub_2, 2);
define_sub!(sub_4, 4);
define_sub!(sub_8, 8);
define_sub!(sub_16, 16);
define_sub!(sub_32, 32);
define_sub!(sub_64, 64);
#[cfg(debug_assertions)]
define_sub!(sub_128, 128);

/// Multiplies two 128-bit integers together, returning a new 256-bit integer.
///
/// This is the base case for our multiplication, taking advantage of Rust's native 128-bit int
/// types to do multiplication (potentially) natively.
const fn mul_2(a: &[u64], b: &[u64]) -> [u64; 4] {
	debug_assert!(a.len() == 2);
	debug_assert!(b.len() == 2);

	// Gradeschool multiplication is way faster here.
	let (a0, a1) = (a[0] as u128, a[1] as u128);
	let (b0, b1) = (b[0] as u128, b[1] as u128);
	let z2 = a0 * b0;
	let z1i = a0 * b1;
	let z1j = b0 * a1;
	let (z1, i_carry) = z1i.overflowing_add(z1j);
	let z0 = a1 * b1;

	let z2a = ((z2 >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let z1a = ((z1 >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let z0a = ((z0 >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let z2b = (z2 & 0xffff_ffff_ffff_ffff) as u64;
	let z1b = (z1 & 0xffff_ffff_ffff_ffff) as u64;
	let z0b = (z0 & 0xffff_ffff_ffff_ffff) as u64;

	let l = z0b;
	let (k, j_carry) = z0a.overflowing_add(z1b);
	let (mut j, mut second_i_carry) = z1a.overflowing_add(z2b);

	let new_i_carry;
	(j, new_i_carry) = j.overflowing_add(j_carry as u64);
	debug_assert!(!second_i_carry || !new_i_carry);
	second_i_carry |= new_i_carry;

	let mut i = z2a;
	let mut spurious_overflow;
	(i, spurious_overflow) = i.overflowing_add(i_carry as u64);
	debug_assert!(!spurious_overflow);
	(i, spurious_overflow) = i.overflowing_add(second_i_carry as u64);
	debug_assert!(!spurious_overflow);

	[i, j, k, l]
}

macro_rules! define_mul { ($name: ident, $len: expr, $submul: ident, $add: ident, $subadd: ident, $sub: ident, $subsub: ident) => {
	/// Multiplies two $len-64-bit integers together, returning a new $len*2-64-bit integer.
	const fn $name(a: &[u64], b: &[u64]) -> [u64; $len * 2] {
		// We could probably get a bit faster doing gradeschool multiplication for some smaller
		// sizes, but its easier to just have one variable-length multiplication, so we do
		// Karatsuba always here.
		debug_assert!(a.len() == $len);
		debug_assert!(b.len() == $len);

		let a0 = const_subslice(a, 0, $len / 2);
		let a1 = const_subslice(a, $len / 2, $len);
		let b0 = const_subslice(b, 0, $len / 2);
		let b1 = const_subslice(b, $len / 2, $len);

		let z2 = $submul(a0, b0);
		let z0 = $submul(a1, b1);

		let (z1a_max, z1a_min, z1a_sign) =
			if slice_greater_than(&a1, &a0) { (a1, a0, true) } else { (a0, a1, false) };
		let (z1b_max, z1b_min, z1b_sign) =
			if slice_greater_than(&b1, &b0) { (b1, b0, true) } else { (b0, b1, false) };

		let z1a = $subsub(z1a_max, z1a_min);
		debug_assert!(!z1a.1);
		let z1b = $subsub(z1b_max, z1b_min);
		debug_assert!(!z1b.1);
		let z1m_sign = z1a_sign == z1b_sign;

		let z1m = $submul(&z1a.0, &z1b.0);
		let z1n = $add(&z0, &z2);
		let mut z1_carry = z1n.1;
		let z1 = if z1m_sign {
			let r = $sub(&z1n.0, &z1m);
			if r.1 { z1_carry ^= true; }
			r.0
		} else {
			let r = $add(&z1n.0, &z1m);
			if r.1 { z1_carry = true; }
			r.0
		};

		let l = const_subslice(&z0, $len / 2, $len);
		let (k, j_carry) = $subadd(const_subslice(&z0, 0, $len / 2), const_subslice(&z1, $len / 2, $len));
		let (mut j, mut i_carry) = $subadd(const_subslice(&z1, 0, $len / 2), const_subslice(&z2, $len / 2, $len));
		if j_carry {
			let new_i_carry = add_one!(j);
			debug_assert!(!i_carry || !new_i_carry);
			i_carry |= new_i_carry;
		}
		let mut i = [0; $len / 2];
		let i_source = const_subslice(&z2, 0, $len / 2);
		copy_from_slice!(i, 0, $len / 2, i_source);
		if i_carry {
			let spurious_carry = add_one!(i);
			debug_assert!(!spurious_carry);
		}
		if z1_carry {
			let spurious_carry = add_one!(i);
			debug_assert!(!spurious_carry);
		}

		let mut res = [0; $len * 2];
		copy_from_slice!(res, $len * 2 * 0 / 4, $len * 2 * 1 / 4, i);
		copy_from_slice!(res, $len * 2 * 1 / 4, $len * 2 * 2 / 4, j);
		copy_from_slice!(res, $len * 2 * 2 / 4, $len * 2 * 3 / 4, k);
		copy_from_slice!(res, $len * 2 * 3 / 4, $len * 2 * 4 / 4, l);
		res
	}
} }

define_mul!(mul_4, 4, mul_2, add_4, add_2, sub_4, sub_2);
define_mul!(mul_8, 8, mul_4, add_8, add_4, sub_8, sub_4);
define_mul!(mul_16, 16, mul_8, add_16, add_8, sub_16, sub_8);
define_mul!(mul_32, 32, mul_16, add_32, add_16, sub_32, sub_16);
define_mul!(mul_64, 64, mul_32, add_64, add_32, sub_64, sub_32);


/// Squares a 128-bit integer, returning a new 256-bit integer.
///
/// This is the base case for our squaring, taking advantage of Rust's native 128-bit int
/// types to do multiplication (potentially) natively.
const fn sqr_2(a: &[u64]) -> [u64; 4] {
	debug_assert!(a.len() == 2);

	let (a0, a1) = (a[0] as u128, a[1] as u128);
	let z2 = a0 * a0;
	let mut z1 = a0 * a1;
	let i_carry = z1 & (1u128 << 127) != 0;
	z1 <<= 1;
	let z0 = a1 * a1;

	let z2a = ((z2 >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let z1a = ((z1 >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let z0a = ((z0 >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let z2b = (z2 & 0xffff_ffff_ffff_ffff) as u64;
	let z1b = (z1 & 0xffff_ffff_ffff_ffff) as u64;
	let z0b = (z0 & 0xffff_ffff_ffff_ffff) as u64;

	let l = z0b;
	let (k, j_carry) = z0a.overflowing_add(z1b);
	let (mut j, mut second_i_carry) = z1a.overflowing_add(z2b);

	let new_i_carry;
	(j, new_i_carry) = j.overflowing_add(j_carry as u64);
	debug_assert!(!second_i_carry || !new_i_carry);
	second_i_carry |= new_i_carry;

	let mut i = z2a;
	let mut spurious_overflow;
	(i, spurious_overflow) = i.overflowing_add(i_carry as u64);
	debug_assert!(!spurious_overflow);
	(i, spurious_overflow) = i.overflowing_add(second_i_carry as u64);
	debug_assert!(!spurious_overflow);

	[i, j, k, l]
}

macro_rules! define_sqr { ($name: ident, $len: expr, $submul: ident, $subsqr: ident, $subadd: ident) => {
	/// Squares a $len-64-bit integers, returning a new $len*2-64-bit integer.
	const fn $name(a: &[u64]) -> [u64; $len * 2] {
		debug_assert!(a.len() == $len);

		let hi = const_subslice(a, 0, $len / 2);
		let lo = const_subslice(a, $len / 2, $len);

		let v0 = $subsqr(lo);
		let mut v1 = $submul(hi, lo);
		let i_carry  = double!(v1);
		let v2 = $subsqr(hi);

		let l = const_subslice(&v0, $len / 2, $len);
		let (k, j_carry) = $subadd(const_subslice(&v0, 0, $len / 2), const_subslice(&v1, $len / 2, $len));
		let (mut j, mut i_carry_2) = $subadd(const_subslice(&v1, 0, $len / 2), const_subslice(&v2, $len / 2, $len));

		let mut i = [0; $len / 2];
		let i_source = const_subslice(&v2, 0, $len / 2);
		copy_from_slice!(i, 0, $len / 2, i_source);

		if j_carry {
			let new_i_carry = add_one!(j);
			debug_assert!(!i_carry_2 || !new_i_carry);
			i_carry_2 |= new_i_carry;
		}
		if i_carry {
			let spurious_carry = add_one!(i);
			debug_assert!(!spurious_carry);
		}
		if i_carry_2 {
			let spurious_carry = add_one!(i);
			debug_assert!(!spurious_carry);
		}

		let mut res = [0; $len * 2];
		copy_from_slice!(res, $len * 2 * 0 / 4, $len * 2 * 1 / 4, i);
		copy_from_slice!(res, $len * 2 * 1 / 4, $len * 2 * 2 / 4, j);
		copy_from_slice!(res, $len * 2 * 2 / 4, $len * 2 * 3 / 4, k);
		copy_from_slice!(res, $len * 2 * 3 / 4, $len * 2 * 4 / 4, l);
		res
	}
} }

define_sqr!(sqr_4, 4, mul_2, sqr_2, add_2);
define_sqr!(sqr_8, 8, mul_4, sqr_4, add_4);
define_sqr!(sqr_16, 16, mul_8, sqr_8, add_8);
define_sqr!(sqr_32, 32, mul_16, sqr_16, add_16);
define_sqr!(sqr_64, 64, mul_32, sqr_32, add_32);

macro_rules! dummy_pre_push { ($name: ident, $len: expr) => {} }
macro_rules! vec_pre_push { ($name: ident, $len: expr) => { $name.push([0; $len]); } }

macro_rules! define_div_rem { ($name: ident, $len: expr, $sub: ident, $heap_init: expr, $pre_push: ident $(, $const_opt: tt)?) => {
	/// Divides two $len-64-bit integers, `a` by `b`, returning the quotient and remainder
	///
	/// Fails iff `b` is zero.
	$($const_opt)? fn $name(a: &[u64; $len], b: &[u64; $len]) -> Result<([u64; $len], [u64; $len]), ()> {
		if slice_equal(b, &[0; $len]) { return Err(()); }

		let mut b_pow = *b;
		let mut pow2s = $heap_init;
		let mut pow2s_count = 0;
		while slice_greater_than(a, &b_pow) {
			$pre_push!(pow2s, $len);
			pow2s[pow2s_count] = b_pow;
			pow2s_count += 1;
			let double_overflow = double!(b_pow);
			if double_overflow { break; }
		}
		let mut quot = [0; $len];
		let mut rem = *a;
		let mut pow2 = pow2s_count as isize - 1;
		while pow2 >= 0 {
			let b_pow = pow2s[pow2 as usize];
			let overflow = double!(quot);
			debug_assert!(!overflow);
			if slice_greater_than(&rem, &b_pow) {
				let (r, carry) = $sub(&rem, &b_pow);
				debug_assert!(!carry);
				rem = r;
				quot[$len - 1] |= 1;
			}
			pow2 -= 1;
		}
		if slice_equal(&rem, b) {
			let overflow = add_one!(quot);
			debug_assert!(!overflow);
			Ok((quot, [0; $len]))
		} else {
			Ok((quot, rem))
		}
	}
} }

#[cfg(fuzzing)]
define_div_rem!(div_rem_2, 2, sub_2, [[0; 2]; 2 * 64], dummy_pre_push, const);
#[cfg(fuzzing)]
define_div_rem!(div_rem_4, 4, sub_4, [[0; 4]; 4 * 64], dummy_pre_push, const); // Uses 8 KiB of stack
#[cfg(fuzzing)]
define_div_rem!(div_rem_8, 8, sub_8, [[0; 8]; 8 * 64], dummy_pre_push, const); // Uses 32 KiB of stack!
define_div_rem!(div_rem_64, 64, sub_64, Vec::new(), vec_pre_push); // Uses up to 2 MiB of heap
#[cfg(debug_assertions)]
define_div_rem!(div_rem_128, 128, sub_128, Vec::new(), vec_pre_push); // Uses up to 8 MiB of heap

impl U4096 {
	/// Constructs a new [`U4096`] from a variable number of big-endian bytes.
	pub(super) fn from_be_bytes(bytes: &[u8]) -> Result<U4096, ()> {
		if bytes.len() > 4096/8 { return Err(()); }
		let u64s = (bytes.len() + 7) / 8;
		let mut res = [0; WORD_COUNT_4096];
		for i in 0..u64s {
			let mut b = [0; 8];
			let pos = (u64s - i) * 8;
			let start = bytes.len().saturating_sub(pos);
			let end = bytes.len() + 8 - pos;
			b[8 + start - end..].copy_from_slice(&bytes[start..end]);
			res[i + WORD_COUNT_4096 - u64s] = u64::from_be_bytes(b);
		}
		Ok(U4096(res))
	}

	/// Naively multiplies `self` * `b` mod `m`, returning a new [`U4096`].
	///
	/// Fails iff m is 0 or self or b are greater than m.
	#[cfg(debug_assertions)]
	fn mulmod_naive(&self, b: &U4096, m: &U4096) -> Result<U4096, ()> {
		if m.0 == [0; WORD_COUNT_4096] { return Err(()); }
		if self > m || b > m { return Err(()); }

		let mul = mul_64(&self.0, &b.0);

		let mut m_zeros = [0; 128];
		m_zeros[WORD_COUNT_4096..].copy_from_slice(&m.0);
		let (_, rem) = div_rem_128(&mul, &m_zeros)?;
		let mut res = [0; WORD_COUNT_4096];
		debug_assert_eq!(&rem[..WORD_COUNT_4096], &[0; WORD_COUNT_4096]);
		res.copy_from_slice(&rem[WORD_COUNT_4096..]);
		Ok(U4096(res))
	}

	/// Calculates `self` ^ `exp` mod `m`, returning a new [`U4096`].
	///
	/// Fails iff m is 0, even, or self or b are greater than m.
	pub(super) fn expmod_odd_mod(&self, mut exp: u32, m: &U4096) -> Result<U4096, ()> {
		#![allow(non_camel_case_types)]

		if m.0 == [0; WORD_COUNT_4096] { return Err(()); }
		if m.0[WORD_COUNT_4096 - 1] & 1 == 0 { return Err(()); }
		if self > m { return Err(()); }

		let mut t = [0; WORD_COUNT_4096];
		if &m.0[..WORD_COUNT_4096 - 1] == &[0; WORD_COUNT_4096 - 1] && m.0[WORD_COUNT_4096 - 1] == 1 {
			return Ok(U4096(t));
		}
		t[WORD_COUNT_4096 - 1] = 1;
		if exp == 0 { return Ok(U4096(t)); }

		// Because m is not even, using 2^4096 as the Montgomery R value is always safe - it is
		// guaranteed to be co-prime with any non-even integer.

		type mul_ty = fn(&[u64], &[u64]) -> [u64; WORD_COUNT_4096 * 2];
		type sqr_ty = fn(&[u64]) -> [u64; WORD_COUNT_4096 * 2];
		type add_double_ty = fn(&[u64], &[u64]) -> ([u64; WORD_COUNT_4096 * 2], bool);
		type sub_ty = fn(&[u64], &[u64]) -> ([u64; WORD_COUNT_4096], bool);
		let (word_count, log_bits, mul, sqr, add_double, sub) =
			if m.0[..WORD_COUNT_4096 / 2] == [0; WORD_COUNT_4096 / 2] {
				if m.0[..WORD_COUNT_4096 * 3 / 4] == [0; WORD_COUNT_4096 * 3 / 4] {
					fn mul_16_subarr(a: &[u64], b: &[u64]) -> [u64; WORD_COUNT_4096 * 2] {
						debug_assert_eq!(a.len(), WORD_COUNT_4096);
						debug_assert_eq!(b.len(), WORD_COUNT_4096);
						debug_assert_eq!(&a[..WORD_COUNT_4096 * 3 / 4], &[0; WORD_COUNT_4096 * 3 / 4]);
						debug_assert_eq!(&b[..WORD_COUNT_4096 * 3 / 4], &[0; WORD_COUNT_4096 * 3 / 4]);
						let mut res = [0; WORD_COUNT_4096 * 2];
						res[WORD_COUNT_4096 + WORD_COUNT_4096 / 2..].copy_from_slice(
							&mul_16(&a[WORD_COUNT_4096 * 3 / 4..], &b[WORD_COUNT_4096 * 3 / 4..]));
						res
					}
					fn sqr_16_subarr(a: &[u64]) -> [u64; WORD_COUNT_4096 * 2] {
						debug_assert_eq!(a.len(), WORD_COUNT_4096);
						debug_assert_eq!(&a[..WORD_COUNT_4096 * 3 / 4], &[0; WORD_COUNT_4096 * 3 / 4]);
						let mut res = [0; WORD_COUNT_4096 * 2];
						res[WORD_COUNT_4096 + WORD_COUNT_4096 / 2..].copy_from_slice(
							&sqr_16(&a[WORD_COUNT_4096 * 3 / 4..]));
						res
					}
					fn add_32_subarr(a: &[u64], b: &[u64]) -> ([u64; WORD_COUNT_4096 * 2], bool) {
						debug_assert_eq!(a.len(), WORD_COUNT_4096 * 2);
						debug_assert_eq!(b.len(), WORD_COUNT_4096 * 2);
						debug_assert_eq!(&a[..WORD_COUNT_4096 * 3 / 2], &[0; WORD_COUNT_4096 * 3 / 2]);
						debug_assert_eq!(&b[..WORD_COUNT_4096 * 3 / 2], &[0; WORD_COUNT_4096 * 3 / 2]);
						let (add, overflow) = add_32(&a[WORD_COUNT_4096 * 3 / 2..], &b[WORD_COUNT_4096 * 3 / 2..]);
						let mut res = [0; WORD_COUNT_4096 * 2];
						res[WORD_COUNT_4096 * 3 / 2..].copy_from_slice(&add);
						(res, overflow)
					}
					fn sub_16_subarr(a: &[u64], b: &[u64]) -> ([u64; WORD_COUNT_4096], bool) {
						debug_assert_eq!(a.len(), WORD_COUNT_4096);
						debug_assert_eq!(b.len(), WORD_COUNT_4096);
						debug_assert_eq!(&a[..WORD_COUNT_4096 * 3 / 4], &[0; WORD_COUNT_4096 * 3 / 4]);
						debug_assert_eq!(&b[..WORD_COUNT_4096 * 3 / 4], &[0; WORD_COUNT_4096 * 3 / 4]);
						let (sub, underflow) = sub_16(&a[WORD_COUNT_4096 * 3 / 4..], &b[WORD_COUNT_4096 * 3 / 4..]);
						let mut res = [0; WORD_COUNT_4096];
						res[WORD_COUNT_4096 * 3 / 4..].copy_from_slice(&sub);
						(res, underflow)
					}
					(16, 10, mul_16_subarr as mul_ty, sqr_16_subarr as sqr_ty, add_32_subarr as add_double_ty, sub_16_subarr as sub_ty)
				} else {
					fn mul_32_subarr(a: &[u64], b: &[u64]) -> [u64; WORD_COUNT_4096 * 2] {
						debug_assert_eq!(a.len(), WORD_COUNT_4096);
						debug_assert_eq!(b.len(), WORD_COUNT_4096);
						debug_assert_eq!(&a[..WORD_COUNT_4096 / 2], &[0; WORD_COUNT_4096 / 2]);
						debug_assert_eq!(&b[..WORD_COUNT_4096 / 2], &[0; WORD_COUNT_4096 / 2]);
						let mut res = [0; WORD_COUNT_4096 * 2];
						res[WORD_COUNT_4096..].copy_from_slice(
							&mul_32(&a[WORD_COUNT_4096 / 2..], &b[WORD_COUNT_4096 / 2..]));
						res
					}
					fn sqr_32_subarr(a: &[u64]) -> [u64; WORD_COUNT_4096 * 2] {
						debug_assert_eq!(a.len(), WORD_COUNT_4096);
						debug_assert_eq!(&a[..WORD_COUNT_4096 / 2], &[0; WORD_COUNT_4096 / 2]);
						let mut res = [0; WORD_COUNT_4096 * 2];
						res[WORD_COUNT_4096..].copy_from_slice(
							&sqr_32(&a[WORD_COUNT_4096 / 2..]));
						res
					}
					fn add_64_subarr(a: &[u64], b: &[u64]) -> ([u64; WORD_COUNT_4096 * 2], bool) {
						debug_assert_eq!(a.len(), WORD_COUNT_4096 * 2);
						debug_assert_eq!(b.len(), WORD_COUNT_4096 * 2);
						debug_assert_eq!(&a[..WORD_COUNT_4096], &[0; WORD_COUNT_4096]);
						debug_assert_eq!(&b[..WORD_COUNT_4096], &[0; WORD_COUNT_4096]);
						let (add, overflow) = add_64(&a[WORD_COUNT_4096..], &b[WORD_COUNT_4096..]);
						let mut res = [0; WORD_COUNT_4096 * 2];
						res[WORD_COUNT_4096..].copy_from_slice(&add);
						(res, overflow)
					}
					fn sub_32_subarr(a: &[u64], b: &[u64]) -> ([u64; WORD_COUNT_4096], bool) {
						debug_assert_eq!(a.len(), WORD_COUNT_4096);
						debug_assert_eq!(b.len(), WORD_COUNT_4096);
						debug_assert_eq!(&a[..WORD_COUNT_4096 / 2], &[0; WORD_COUNT_4096 / 2]);
						debug_assert_eq!(&b[..WORD_COUNT_4096 / 2], &[0; WORD_COUNT_4096 / 2]);
						let (sub, underflow) = sub_32(&a[WORD_COUNT_4096 / 2..], &b[WORD_COUNT_4096 / 2..]);
						let mut res = [0; WORD_COUNT_4096];
						res[WORD_COUNT_4096 / 2..].copy_from_slice(&sub);
						(res, underflow)
					}
					(32, 11, mul_32_subarr as mul_ty, sqr_32_subarr as sqr_ty, add_64_subarr as add_double_ty, sub_32_subarr as sub_ty)
				}
			} else {
				(64, 12, mul_64 as mul_ty, sqr_64 as sqr_ty, add_128 as add_double_ty, sub_64 as sub_ty)
			};

		let mut r = [0; WORD_COUNT_4096 * 2];
		r[WORD_COUNT_4096 * 2 - word_count - 1] = 1;

		let mut m_inv_pos = [0; WORD_COUNT_4096];
		m_inv_pos[WORD_COUNT_4096 - 1] = 1;
		let mut two = [0; WORD_COUNT_4096];
		two[WORD_COUNT_4096 - 1] = 2;
		for _ in 0..log_bits {
			let mut m_m_inv = mul(&m_inv_pos, &m.0);
			m_m_inv[..WORD_COUNT_4096 * 2 - word_count].fill(0);
			let m_inv = mul(&sub(&two, &m_m_inv[WORD_COUNT_4096..]).0, &m_inv_pos);
			m_inv_pos[WORD_COUNT_4096 - word_count..].copy_from_slice(&m_inv[WORD_COUNT_4096 * 2 - word_count..]);
		}
		m_inv_pos[..WORD_COUNT_4096 - word_count].fill(0);

		// We want the negative modular inverse of m mod R, so subtract m_inv from R.
		let mut m_inv = m_inv_pos;
		negate!(m_inv);
		m_inv[..WORD_COUNT_4096 - word_count].fill(0);
		debug_assert_eq!(&mul(&m_inv, &m.0)[WORD_COUNT_4096 * 2 - word_count..],
			// R - 1 == -1 % R
			&[0xffff_ffff_ffff_ffff; WORD_COUNT_4096][WORD_COUNT_4096 - word_count..]);

		debug_assert_eq!(&m_inv[..WORD_COUNT_4096 - word_count], &[0; WORD_COUNT_4096][..WORD_COUNT_4096 - word_count]);

		let mont_reduction = |mu: [u64; WORD_COUNT_4096 * 2]| -> [u64; WORD_COUNT_4096] {
			debug_assert_eq!(&mu[..WORD_COUNT_4096 * 2 - word_count * 2],
				&[0; WORD_COUNT_4096 * 2][..WORD_COUNT_4096 * 2 - word_count * 2]);
			let mut mu_mod_r = [0; WORD_COUNT_4096];
			mu_mod_r[WORD_COUNT_4096 - word_count..].copy_from_slice(&mu[WORD_COUNT_4096 * 2 - word_count..]);
			let mut v = mul(&mu_mod_r, &m_inv);
			v[..WORD_COUNT_4096 * 2 - word_count].fill(0); // mod R
			let t0 = mul(&v[WORD_COUNT_4096..], &m.0);
			let (t1, t1_extra_bit) = add_double(&t0, &mu);
			let mut t1_on_r = [0; WORD_COUNT_4096];
			debug_assert_eq!(&t1[WORD_COUNT_4096 * 2 - word_count..], &[0; WORD_COUNT_4096][WORD_COUNT_4096 - word_count..],
				"t1 should be divisible by r");
			t1_on_r[WORD_COUNT_4096 - word_count..].copy_from_slice(&t1[WORD_COUNT_4096 * 2 - word_count * 2..WORD_COUNT_4096 * 2 - word_count]);
			if t1_extra_bit || t1_on_r >= m.0 {
				let underflow;
				(t1_on_r, underflow) = sub(&t1_on_r, &m.0);
				debug_assert_eq!(t1_extra_bit, underflow);
			}
			t1_on_r
		};

		// Calculate R^2 mod m as ((2^DOUBLES * R) mod m)^(log_bits - LOG2_DOUBLES) mod R
		let mut r_minus_one = [0xffff_ffff_ffff_ffffu64; WORD_COUNT_4096];
		r_minus_one[..WORD_COUNT_4096 - word_count].fill(0);
		// While we do a full div here, in general R should be less than 2x m (assuming the RSA
		// modulus used its full bit range and is 1024, 2048, or 4096 bits), so it should be cheap.
		// In cases with a nonstandard RSA modulus we may end up being pretty slow here, but we'll
		// survive.
		// If we ever find a problem with this we should reduce R to be tigher on m, as we're
		// wasting extra bits of calculation if R is too far from m.
		let (_, mut r_mod_m) = debug_unwrap!(div_rem_64(&r_minus_one, &m.0));
		let r_mod_m_overflow = add_one!(r_mod_m);
		if r_mod_m_overflow || r_mod_m >= m.0 {
			(r_mod_m, _) = sub_64(&r_mod_m, &m.0);
		}

		let mut r2_mod_m: [u64; 64] = r_mod_m;
		const DOUBLES: usize = 32;
		const LOG2_DOUBLES: usize = 5;

		for _ in 0..DOUBLES {
			let overflow = double!(r2_mod_m);
			if overflow || r2_mod_m > m.0 {
				(r2_mod_m, _) = sub_64(&r2_mod_m, &m.0);
			}
		}
		for _ in 0..log_bits - LOG2_DOUBLES {
			r2_mod_m = mont_reduction(sqr(&r2_mod_m));
		}
		// Clear excess high bits
		for (m_limb, r2_limb) in m.0.iter().zip(r2_mod_m.iter_mut()) {
			let clear_bits = m_limb.leading_zeros();
			if clear_bits == 0 { break; }
			*r2_limb &= !(0xffff_ffff_ffff_ffffu64 << (64 - clear_bits));
			if *m_limb != 0 { break; }
		}
		debug_assert!(r2_mod_m < m.0);

		// Calculate t * R and a * R as mont multiplications by R^2 mod m
		let mut tr = mont_reduction(mul(&r2_mod_m, &t));
		let mut ar = mont_reduction(mul(&r2_mod_m, &self.0));

		#[cfg(debug_assertions)] {
			debug_assert_eq!(r2_mod_m, U4096(r_mod_m).mulmod_naive(&U4096(r_mod_m), &m).unwrap().0);
			debug_assert_eq!(&tr, &U4096(t).mulmod_naive(&U4096(r_mod_m), &m).unwrap().0);
			debug_assert_eq!(&ar, &self.mulmod_naive(&U4096(r_mod_m), &m).unwrap().0);
		}

		while exp != 1 {
			if exp % 2 == 1 {
				tr = mont_reduction(mul(&tr, &ar));
				exp -= 1;
			}
			ar = mont_reduction(sqr(&ar));
			exp /= 2;
		}
		ar = mont_reduction(mul(&ar, &tr));
		let mut resr = [0; WORD_COUNT_4096 * 2];
		resr[WORD_COUNT_4096..].copy_from_slice(&ar);
		Ok(U4096(mont_reduction(resr)))
	}
}

#[cfg(fuzzing)]
extern crate ibig;
#[cfg(fuzzing)]
/// Read some bytes and use them to test bigint math by comparing results against the `ibig` crate.
pub fn fuzz_math(input: &[u8]) {
	if input.len() < 32 || input.len() % 16 != 0 { return; }
	let split = core::cmp::min(input.len() / 2, 512);
	let (a, b) = input.split_at(core::cmp::min(input.len() / 2, 512));
	let b = &b[..split];

	let ai = ibig::UBig::from_be_bytes(&a);
	let bi = ibig::UBig::from_be_bytes(&b);

	let mut a_u64s = Vec::with_capacity(split / 8);
	for chunk in a.chunks(8) {
		a_u64s.push(u64::from_be_bytes(chunk.try_into().unwrap()));
	}
	let mut b_u64s = Vec::with_capacity(split / 8);
	for chunk in b.chunks(8) {
		b_u64s.push(u64::from_be_bytes(chunk.try_into().unwrap()));
	}

	macro_rules! test { ($mul: ident, $sqr: ident, $add: ident, $sub: ident, $div_rem: ident) => {
		let res = $mul(&a_u64s, &b_u64s);
		let mut res_bytes = Vec::with_capacity(input.len() / 2);
		for i in res {
			res_bytes.extend_from_slice(&i.to_be_bytes());
		}
		assert_eq!(ibig::UBig::from_be_bytes(&res_bytes), ai.clone() * bi.clone());

		debug_assert_eq!($mul(&a_u64s, &a_u64s), $sqr(&a_u64s));
		debug_assert_eq!($mul(&b_u64s, &b_u64s), $sqr(&b_u64s));

		let (res, carry) = $add(&a_u64s, &b_u64s);
		let mut res_bytes = Vec::with_capacity(input.len() / 2 + 1);
		if carry { res_bytes.push(1); } else { res_bytes.push(0); }
		for i in res {
			res_bytes.extend_from_slice(&i.to_be_bytes());
		}
		assert_eq!(ibig::UBig::from_be_bytes(&res_bytes), ai.clone() + bi.clone());

		let mut add_u64s = a_u64s.clone();
		let carry = add_one!(add_u64s);
		let mut res_bytes = Vec::with_capacity(input.len() / 2 + 1);
		if carry { res_bytes.push(1); } else { res_bytes.push(0); }
		for i in &add_u64s {
			res_bytes.extend_from_slice(&i.to_be_bytes());
		}
		assert_eq!(ibig::UBig::from_be_bytes(&res_bytes), ai.clone() + 1);

		let mut double_u64s = b_u64s.clone();
		let carry = double!(double_u64s);
		let mut res_bytes = Vec::with_capacity(input.len() / 2 + 1);
		if carry { res_bytes.push(1); } else { res_bytes.push(0); }
		for i in &double_u64s {
			res_bytes.extend_from_slice(&i.to_be_bytes());
		}
		assert_eq!(ibig::UBig::from_be_bytes(&res_bytes), bi.clone() * 2);

		let (quot, rem) = if let Ok(res) =
			$div_rem(&a_u64s[..].try_into().unwrap(), &b_u64s[..].try_into().unwrap()) {
				res
			} else { return };
		let mut quot_bytes = Vec::with_capacity(input.len() / 2);
		for i in quot {
			quot_bytes.extend_from_slice(&i.to_be_bytes());
		}
		let mut rem_bytes = Vec::with_capacity(input.len() / 2);
		for i in rem {
			rem_bytes.extend_from_slice(&i.to_be_bytes());
		}
		let (quoti, remi) = ibig::ops::DivRem::div_rem(ai.clone(), &bi);
		assert_eq!(ibig::UBig::from_be_bytes(&quot_bytes), quoti);
		assert_eq!(ibig::UBig::from_be_bytes(&rem_bytes), remi);
	} }

	if a_u64s.len() == 2 {
		test!(mul_2, sqr_2, add_2, sub_2, div_rem_2);
	} else if a_u64s.len() == 4 {
		test!(mul_4, sqr_4, add_4, sub_4, div_rem_4);
	} else if a_u64s.len() == 8 {
		test!(mul_8, sqr_8, add_8, sub_8, div_rem_8);
	} else if input.len() == 512*2 + 4 {
		let mut e_bytes = [0; 4];
		e_bytes.copy_from_slice(&input[512 * 2..512 * 2 + 4]);
		let e = u32::from_le_bytes(e_bytes);
		let a = U4096::from_be_bytes(&a).unwrap();
		let b = U4096::from_be_bytes(&b).unwrap();

		let res = if let Ok(r) = a.expmod_odd_mod(e, &b) { r } else { return };
		let mut res_bytes = Vec::with_capacity(512);
		for i in res.0 {
			res_bytes.extend_from_slice(&i.to_be_bytes());
		}

		let ring = ibig::modular::ModuloRing::new(&bi);
		let ar = ring.from(ai.clone());
		assert_eq!(ar.pow(&e.into()).residue(), ibig::UBig::from_be_bytes(&res_bytes));
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn mul_min_simple_tests() {
		let a = [1, 2];
		let b = [3, 4];
		let res = mul_2(&a, &b);
		assert_eq!(res, [0, 3, 10, 8]);

		let a = [0x1bad_cafe_dead_beef, 2424];
		let b = [0x2bad_beef_dead_cafe, 4242];
		let res = mul_2(&a, &b);
		assert_eq!(res, [340296855556511776, 15015369169016130186, 4248480538569992542, 10282608]);

		let a = [0xf6d9_f8eb_8b60_7a6d, 0x4b93_833e_2194_fc2e];
		let b = [0xfdab_0000_6952_8ab4, 0xd302_0000_8282_0000];
		let res = mul_2(&a, &b);
		assert_eq!(res, [17625486516939878681, 18390748118453258282, 2695286104209847530, 1510594524414214144]);

		let a = [0x8b8b_8b8b_8b8b_8b8b, 0x8b8b_8b8b_8b8b_8b8b];
		let b = [0x8b8b_8b8b_8b8b_8b8b, 0x8b8b_8b8b_8b8b_8b8b];
		let res = mul_2(&a, &b);
		assert_eq!(res, [5481115605507762349, 8230042173354675923, 16737530186064798, 15714555036048702841]);

		let a = [0x0000_0000_0000_0020, 0x002d_362c_005b_7753];
		let b = [0x0900_0000_0030_0003, 0xb708_00fe_0000_00cd];
		let res = mul_2(&a, &b);
		assert_eq!(res, [1, 2306290405521702946, 17647397529888728169, 10271802099389861239]);

		let a = [0x0000_0000_7fff_ffff, 0xffff_ffff_0000_0000];
		let b = [0x0000_0800_0000_0000, 0x0000_1000_0000_00e1];
		let res = mul_2(&a, &b);
		assert_eq!(res, [1024, 0, 483183816703, 18446743107341910016]);

		let a = [0xf6d9_f8eb_ebeb_eb6d, 0x4b93_83a0_bb35_0680];
		let b = [0xfd02_b9b9_b9b9_b9b9, 0xb9b9_b9b9_b9b9_b9b9];
		let res = mul_2(&a, &b);
		assert_eq!(res, [17579814114991930107, 15033987447865175985, 488855932380801351, 5453318140933190272]);

		let a = [u64::MAX; 2];
		let b = [u64::MAX; 2];
		let res = mul_2(&a, &b);
		assert_eq!(res, [18446744073709551615, 18446744073709551614, 0, 1]);
	}

	#[test]
	fn add_simple_tests() {
		let a = [u64::MAX; 2];
		let b = [u64::MAX; 2];
		assert_eq!(add_2(&a, &b), ([18446744073709551615, 18446744073709551614], true));

		let a = [0x1bad_cafe_dead_beef, 2424];
		let b = [0x2bad_beef_dead_cafe, 4242];
		assert_eq!(add_2(&a, &b), ([5141855058045667821, 6666], false));
	}

	#[test]
	fn mul_4_simple_tests() {
		let a = [1; 4];
		let b = [2; 4];
		assert_eq!(mul_4(&a, &b),
			[0, 2, 4, 6, 8, 6, 4, 2]);

		let a = [0x1bad_cafe_dead_beef, 2424, 0x1bad_cafe_dead_beef, 2424];
		let b = [0x2bad_beef_dead_cafe, 4242, 0x2bad_beef_dead_cafe, 4242];
		assert_eq!(mul_4(&a, &b),
			[340296855556511776, 15015369169016130186, 4929074249683016095, 11583994264332991364,
			 8837257932696496860, 15015369169036695402, 4248480538569992542, 10282608]);

		let a = [u64::MAX; 4];
		let b = [u64::MAX; 4];
		assert_eq!(mul_4(&a, &b),
			[18446744073709551615, 18446744073709551615, 18446744073709551615,
			 18446744073709551614, 0, 0, 0, 1]);
	}

	#[test]
	fn double_simple_tests() {
		let mut a = [0xfff5_b32d_01ff_0000, 0x00e7_e7e7_e7e7_e7e7];
		assert!(double!(a));
		assert_eq!(a, [18440945635998695424, 130551405668716494]);

		let mut a = [u64::MAX, u64::MAX];
		assert!(double!(a));
		assert_eq!(a, [18446744073709551615, 18446744073709551614]);
	}
}

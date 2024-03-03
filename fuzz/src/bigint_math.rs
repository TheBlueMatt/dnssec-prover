// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![cfg_attr(feature = "libfuzzer_fuzz", no_main)]

#[cfg(not(fuzzing))]
compile_error!("Fuzz targets need cfg=fuzzing");

extern crate dnssec_prover;
use dnssec_prover::crypto::bigint::fuzz_math;

#[cfg(feature = "afl")]
#[macro_use] extern crate afl;
#[cfg(feature = "afl")]
fn main() {
	fuzz!(|data| {
		fuzz_math(data);
	});
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
	loop {
		fuzz!(|data| {
			fuzz_math(data);
		});
	}
}

#[cfg(feature = "libfuzzer_fuzz")]
#[macro_use] extern crate libfuzzer_sys;
#[cfg(feature = "libfuzzer_fuzz")]
fuzz_target!(|data: &[u8]| {
	fuzz_math(data);
});

#[cfg(feature = "stdin_fuzz")]
fn main() {
	use std::io::Read;

	let mut data = Vec::with_capacity(8192);
	std::io::stdin().read_to_end(&mut data).unwrap();
	fuzz_math(&data);
}

#[test]
fn run_test_cases() {
	use std::fs;
	use std::io::Read;

	if let Ok(tests) = fs::read_dir("test_cases/bigint_math") {
		for test in tests {
			let mut data: Vec<u8> = Vec::new();
			let path = test.unwrap().path();
			fs::File::open(&path).unwrap().read_to_end(&mut data).unwrap();

			fuzz_math(&data);
		}
	}
}

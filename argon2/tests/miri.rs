//! Tiny test cases to run in Miri.
//!
//! To test the parallel implementation, run:
//!
//! ```text
//! MIRIFLAGS="-Zmiri-ignore-leaks" cargo +nightly miri nextest run -F parallel -- miri
//! ```
//!
//! To test the serial implementation, run:
//!
//! ```text
//! cargo +nightly miri nextest run -- miri
//! ```

use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use hex_literal::hex;

const PWD: &[u8] = b"passowrd";
const SALT: &[u8] = b"somesalt";

// TODO: use a custom rayon pool to avoid having to work around the leak; that said:
// https://github.com/rayon-rs/rayon/issues/1072

#[allow(clippy::too_many_arguments)]
fn hashtest(algorithm: Algorithm, t: u32, m: u32, p: u32, expected_raw_hash: &[u8]) {
    let params = ParamsBuilder::new()
        .t_cost(t)
        .m_cost(1 << m)
        .p_cost(p)
        .build()
        .unwrap();

    let ctx = Argon2::new(algorithm, Version::default(), params);

    let mut out = [0u8; 32];
    ctx.hash_password_into(PWD, SALT, &mut out).unwrap();
    eprintln!("{:02x?}", out);
    eprintln!("{:02x?}", expected_raw_hash);

    assert_eq!(out, expected_raw_hash);
}

#[test]
fn miri_argon2d_1_8_2() {
    let expected_hash = hex!("423f888e2392f1d5d79051dcdb01ad29084b616db11841442588c9368e371678");
    hashtest(Algorithm::Argon2d, 1, 8, 2, &expected_hash);
}

#[test]
fn miri_argon2i_1_8_2() {
    let expected_hash = hex!("e5bb7119ad1ecd61c4cbfcb6ca3e501599c8a18bcf65258345ca01433128876d");
    hashtest(Algorithm::Argon2i, 1, 8, 2, &expected_hash);
}

#[test]
fn miri_argon2id_1_8_2() {
    let expected_hash = hex!("eb55c59528cdff0722d395dff30f87c2d1f2259d17f5b7c0bcd86d549d93d5cd");
    hashtest(Algorithm::Argon2id, 1, 8, 2, &expected_hash);
}

#[cfg(feature = "parallel")]
#[test]
fn miri_smoke() {
    use rayon::iter::{IntoParallelIterator, ParallelIterator};
    let sum: u64 = (1..16).map(|x| dbg!(x) * 2).sum();
    assert_eq!(sum, 240);
}

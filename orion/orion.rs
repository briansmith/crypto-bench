#![feature(test)]

extern crate test;
#[macro_use]
extern crate crypto_bench;
extern crate orion;

mod aead {
    use test;

    macro_rules! orion_aead_bench {
        ( $benchmark_name:ident, $input_len:expr, $ad:expr, $sealer:path, $nonce_size: expr) => {
            #[bench]
            fn $benchmark_name(b: &mut test::Bencher) {
                use $sealer::{seal, SecretKey, Nonce};
                b.bytes = $input_len as u64;
                let key = SecretKey::generate();

                let nonce = match $nonce_size {
                    12 => Nonce::from_slice(&crypto_bench::aead::NONCE).unwrap(), // ChaCha20Poly1305.
                    24 => Nonce::from_slice(&[0u8; 24]).unwrap(), // XChaCha20Poly1305.
                    _ => panic!("Illegal nonce size passed") 
                };
                // XXX: orion does not support in-place encryption,
                // but copies the result into an out parameter which must be
                // at least $input_len + 16 in size.
                let mut out = [0u8; $input_len + 16];
                b.iter(|| {
                    seal(&key, &nonce, &[0u8; $input_len], Some($ad), &mut out).unwrap();
                });
            }
        }
    }

    // A TLS 1.2/3 finished message.
    orion_aead_bench!(chacha20poly1305_tls12_finished,
                      crypto_bench::aead::TLS12_FINISHED_LEN,
                      &crypto_bench::aead::TLS12_AD,
                      orion::hazardous::aead::chacha20poly1305,
                      orion::hazardous::stream::chacha20::IETF_CHACHA_NONCESIZE);
    orion_aead_bench!(chacha20poly1305_tls13_finished,
                      crypto_bench::aead::TLS13_FINISHED_LEN,
                      &crypto_bench::aead::TLS13_AD,
                      orion::hazardous::aead::chacha20poly1305,
                      orion::hazardous::stream::chacha20::IETF_CHACHA_NONCESIZE);
            
    // For comparison with BoringSSL.
    orion_aead_bench!(chacha20poly1305_tls12_16,
                      16,
                      &crypto_bench::aead::TLS12_AD,
                      orion::hazardous::aead::chacha20poly1305,
                      orion::hazardous::stream::chacha20::IETF_CHACHA_NONCESIZE);

    // ~1 packet of data in TLS.
    orion_aead_bench!(chacha20poly1305_tls12_1350, 
                      1350,
                      &crypto_bench::aead::TLS12_AD,
                      orion::hazardous::aead::chacha20poly1305,
                      orion::hazardous::stream::chacha20::IETF_CHACHA_NONCESIZE);
    orion_aead_bench!(chacha20poly1305_tls13_1350,
                      1350,
                      &crypto_bench::aead::TLS13_AD,
                      orion::hazardous::aead::chacha20poly1305,
                      orion::hazardous::stream::chacha20::IETF_CHACHA_NONCESIZE);

    // For comparison with BoringSSL.
    orion_aead_bench!(chacha20poly1305_tls12_8192, 
                      8192,
                      &crypto_bench::aead::TLS12_AD,
                      orion::hazardous::aead::chacha20poly1305,
                      orion::hazardous::stream::chacha20::IETF_CHACHA_NONCESIZE);
    orion_aead_bench!(chacha20poly1305_tls13_8192,
                      8192,
                      &crypto_bench::aead::TLS13_AD,
                      orion::hazardous::aead::chacha20poly1305,
                      orion::hazardous::stream::chacha20::IETF_CHACHA_NONCESIZE);

    // XChaCha20Poly1305

    orion_aead_bench!(xchacha20poly1305_16,
                      16,
                      &[0u8; 0],
                      orion::hazardous::aead::xchacha20poly1305,
                      orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE);

    orion_aead_bench!(xchacha20poly1305_1350, 
                      1350,
                      &[0u8; 0],
                      orion::hazardous::aead::xchacha20poly1305,
                      orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE);

    orion_aead_bench!(xchacha20poly1305_8192, 
                      8192,
                      &[0u8; 0],
                      orion::hazardous::aead::xchacha20poly1305,
                      orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE);
}

mod digest {
    macro_rules! orion_digest_benches {
        ( $name:ident, $block_len:expr, $output_len:expr, $digester:path) => {
            mod $name {
                use crypto_bench;
                use $digester::*;

                digest_benches!($block_len, input, {
                    digest(&input).unwrap()
                });
            }
        }
    }

    orion_digest_benches!(sha512, 
                          crypto_bench::SHA512_BLOCK_LEN, 
                          crypto_bench::SHA512_OUTPUT_LEN,
                          orion::hazardous::hash::sha512);
}

mod pbkdf2 {
    use orion::hazardous::kdf::pbkdf2;
    use test;

    macro_rules! orion_pbkdf2_bench {
        ( $bench_fn_name:ident, $out_len:expr, $secret:expr, $iter:expr, $salt:expr) => {
            #[bench]
            fn $bench_fn_name(b: &mut test::Bencher) {
                let mut out = [0u8; $out_len];
                b.iter(|| {
                    // XXX: Password::from_slice() will process the input
                    // as an HMAC secret key for subsequent HMAC calls 
                    // and is therefore included in the benchmarks.
                    let secret = pbkdf2::Password::from_slice($secret).unwrap();
                    pbkdf2::derive_key(&secret, $salt, $iter, &mut out).unwrap();
                });
            }
        }
    }

    orion_pbkdf2_bench!(hmac_sha512, 
                        crypto_bench::SHA512_OUTPUT_LEN, 
                        crypto_bench::pbkdf2::PASSWORD,
                        crypto_bench::pbkdf2::ITERATIONS as usize,
                        crypto_bench::pbkdf2::SALT);
}

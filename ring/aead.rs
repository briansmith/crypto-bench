// TODO: The BoringSSL benchmarks align the input/output buffers to 16-bytes
// boundaries. Should we?

use crypto_bench;
use ring::{aead, rand};
use test;

fn generate_sealing_key(algorithm: &'static aead::Algorithm)
                        -> Result<aead::SealingKey, ()> {
    let mut key_bytes = vec![0u8; algorithm.key_len()];
    try!(rand::fill_secure_random(&mut key_bytes));
    aead::SealingKey::new(algorithm, &key_bytes)
}

fn seal_in_place_bench(algorithm: &'static aead::Algorithm,
                       chunk_len: usize, ad: &[u8],
                       b: &mut test::Bencher) {
    let out_suffix_capacity = algorithm.max_overhead_len();
    let mut in_out = vec![0u8; chunk_len + out_suffix_capacity];

    // XXX: This is a little misleading when `ad` isn't empty.
    b.bytes = chunk_len as u64;

    let key = generate_sealing_key(algorithm).unwrap();
    b.iter(|| {
        aead::seal_in_place(&key, &crypto_bench::aead::NONCE,
                            &mut in_out, out_suffix_capacity,
                            ad).unwrap();
    });
}

macro_rules! ring_seal_in_place_bench {
    ( $benchmark_name:ident, $algorithm:expr, $chunk_len:expr, $ad:expr ) => {
        #[bench]
        fn $benchmark_name(b: &mut test::Bencher) {
            use ring::aead;
            use super::super::seal_in_place_bench;
            seal_in_place_bench($algorithm, $chunk_len, $ad, b);
        }
    }
}

macro_rules! ring_seal_in_place_benches {
    ( $name:ident, $algorithm:expr ) => {
        mod $name {
            use crypto_bench;
            use test;

            // A TLS 1.2 finished message.
            ring_seal_in_place_bench!(tls12_finished, $algorithm,
                                      crypto_bench::aead::TLS12_FINISHED_LEN,
                                      &crypto_bench::aead::TLS12_AD);
            ring_seal_in_place_bench!(tls13_finished, $algorithm,
                                      crypto_bench::aead::TLS13_FINISHED_LEN,
                                      &crypto_bench::aead::TLS13_AD);

            // For comparison with BoringSSL.
            ring_seal_in_place_bench!(tls12_16, $algorithm, 16,
                                      &crypto_bench::aead::TLS12_AD);

            // ~1 packet of data in TLS.
            ring_seal_in_place_bench!(tls12_1350, $algorithm, 1350,
                                      &crypto_bench::aead::TLS12_AD);
            ring_seal_in_place_bench!(tls13_1350, $algorithm, 1350,
                                      &crypto_bench::aead::TLS13_AD);

            // For comparison with BoringSSL.
            ring_seal_in_place_bench!(tls12_8192, $algorithm, 8192,
                                      &crypto_bench::aead::TLS12_AD);
            ring_seal_in_place_bench!(tls13_8192, $algorithm, 8192,
                                      &crypto_bench::aead::TLS13_AD);
        }
    }
}

mod seal_in_place {
    ring_seal_in_place_benches!(aes_128_gcm, &aead::AES_128_GCM);
    ring_seal_in_place_benches!(aes_256_gcm, &aead::AES_256_GCM);
    ring_seal_in_place_benches!(chacha20_poly1305,
                                &aead::CHACHA20_POLY1305);
    ring_seal_in_place_benches!(chacha20_poly1305_old,
                                &aead::CHACHA20_POLY1305_OLD);
}

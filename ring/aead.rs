// TODO: The BoringSSL benchmarks align the input/output buffers to 16-bytes
// boundaries. Should we?

use ring::{aead::{self, BoundKey}, error, rand};

struct NonceSequence(u64);
impl NonceSequence {
    fn new() -> Self { Self(0) }
}

impl aead::NonceSequence for NonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        let mut result = [0u8; aead::NONCE_LEN];
        result[4..].copy_from_slice(&u64::to_be_bytes(self.0));
        self.0 = self.0.checked_add(1).ok_or(error::Unspecified)?;
        Ok(aead::Nonce::assume_unique_for_key(result))
    }
}

fn generate_sealing_key(algorithm: &'static aead::Algorithm, rng: &dyn rand::SecureRandom)
                        -> Result<aead::SealingKey<NonceSequence>, error::Unspecified> {
    let mut key_bytes = vec![0u8; algorithm.key_len()];
    rng.fill(&mut key_bytes)?;
    let key = aead::UnboundKey::new(algorithm, &key_bytes)?;
    Ok(aead::SealingKey::new(key, NonceSequence::new()))
}

fn seal_in_place_bench(algorithm: &'static aead::Algorithm,
                       rng: &dyn rand::SecureRandom,
                       chunk_len: usize, aad: &[u8],
                       b: &mut test::Bencher) {
    let out_suffix_capacity = algorithm.tag_len();
    let mut in_out = vec![0u8; chunk_len + out_suffix_capacity];

    // XXX: This is a little misleading when `ad` isn't empty.
    b.bytes = chunk_len as u64;

    let mut key = generate_sealing_key(algorithm, rng).unwrap();
    b.iter(|| {
        let aad = aead::Aad::from(aad);
        key.seal_in_place(aad, &mut in_out,out_suffix_capacity).unwrap();


    });
}

macro_rules! ring_seal_in_place_bench {
    ( $benchmark_name:ident, $algorithm:expr, $chunk_len:expr, $ad:expr ) => {
        #[bench]
        fn $benchmark_name(b: &mut test::Bencher) {
            use ring::aead;
            use ring::rand::SystemRandom;
            use super::super::seal_in_place_bench;
            let rng = SystemRandom::new();
            seal_in_place_bench($algorithm, &rng, $chunk_len, $ad, b);
        }
    }
}

macro_rules! ring_seal_in_place_benches {
    ( $name:ident, $algorithm:expr ) => {
        mod $name {
            use crypto_bench;

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
}

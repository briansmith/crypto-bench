// TODO: The BoringSSL benchmarks align the input/output buffers to 16-bytes
// boundaries. Should we?

// All the AEADs we're testing use 96-bit nonces.
const NONCE: [u8; 96 / 8] = [0u8; 96 / 8];


// A TLS 1.2 finished message is always 12 bytes long.
const TLS12_FINISHED_LEN: usize = 12;

// A TLS 1.3 finished message is "[t]he size of the HMAC output for the Hash
// used for the handshake," which is usually SHA-256.
const TLS13_FINISHED_LEN: usize = 32;

// In TLS 1.2, 13 bytes of additional data are used for AEAD cipher suites.
const TLS12_AD: [u8; 13] = [
    23,         // Type: application_data
    3, 3,       // Version = TLS 1.2.
    0x12, 0x34, // Length = 0x1234.
    0, 0, 0, 0, 0, 0, 0, 1, // Record #1
];

// In TLS 1.3, no additional data is used for AEAD cipher suites.
const TLS13_AD: [u8; 0] = [ ];

mod ring {
    use ring::{aead, rand};
    use super::NONCE;
    use test;

    fn generate_sealing_key(algorithm: &'static aead::Algorithm)
                            -> Result<aead::SealingKey, ()> {
        let mut key_bytes = vec![0u8; algorithm.key_len];
        try!(rand::fill_secure_random(&mut key_bytes));
        aead::SealingKey::new(algorithm, &key_bytes)
    }

    fn seal_in_place_bench(algorithm: &'static aead::Algorithm,
                           chunk_len: usize, ad: &[u8],
                           b: &mut test::Bencher) {
        let out_suffix_capacity = algorithm.max_overhead_len;
        let mut in_out = vec![0u8; chunk_len + out_suffix_capacity];

        // XXX: This is a little misleading when `ad` isn't empty.
        b.bytes = chunk_len as u64;

        let key = generate_sealing_key(algorithm).unwrap();
        b.iter(|| {
            aead::seal_in_place(&key, &NONCE, &mut in_out,
                                out_suffix_capacity, ad).unwrap();
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
        ( $algorithm:expr ) => {
            use super::super::super::{
                TLS12_AD, TLS12_FINISHED_LEN,
                TLS13_AD, TLS13_FINISHED_LEN
            };
            use test;

            // A TLS 1.2 finished message.
            ring_seal_in_place_bench!(tls12_finished, $algorithm,
                                      TLS12_FINISHED_LEN, &TLS12_AD);
            ring_seal_in_place_bench!(tls13_finished, $algorithm,
                                      TLS13_FINISHED_LEN, &TLS12_AD);

            // For comparison with BoringSSL.
            ring_seal_in_place_bench!(tls12_16, $algorithm, 16, &TLS12_AD);

            // ~1 packet of data in TLS.
            ring_seal_in_place_bench!(tls12_1350, $algorithm, 1350, &TLS12_AD);
            ring_seal_in_place_bench!(tls13_1350, $algorithm, 1350, &TLS13_AD);

            // For comparison with BoringSSL.
            ring_seal_in_place_bench!(tls12_8192, $algorithm, 8192, &TLS12_AD);
            ring_seal_in_place_bench!(tls13_8192, $algorithm, 8192, &TLS13_AD);
        }
    }

    mod seal_in_place {
        mod aes_128_gcm { ring_seal_in_place_benches!(&aead::AES_128_GCM); }
        mod aes_256_gcm { ring_seal_in_place_benches!(&aead::AES_256_GCM); }
        mod chacha20_poly1305 { ring_seal_in_place_benches!(&aead::CHACHA20_POLY1305); }
        mod chacha20_poly1305_old { ring_seal_in_place_benches!(&aead::CHACHA20_POLY1305_OLD); }
    }
}

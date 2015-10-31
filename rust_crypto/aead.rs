fn generate_key(key_len: usize) -> Vec<u8> {
    use rand::{OsRng, Rng};

    let mut key_bytes = vec![0u8; key_len];
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut key_bytes);
    key_bytes
}

mod seal_in_place {
    use crypto_bench;
    use test;

    fn aes_gcm(key_len: usize, tag_len: usize, chunk_len: usize, ad: &[u8],
               b: &mut test::Bencher) {
        use crypto::{aes, aes_gcm};
        use crypto::aead::AeadEncryptor;

        let key = super::generate_key(key_len);
        let key_size = match key.len() {
            16 => aes::KeySize::KeySize128,
            32 => aes::KeySize::KeySize256,
            _ => unimplemented!(),
        };

        let mut in_out = vec![0u8; chunk_len + tag_len];

        // rust-crypto doesn't have an encrypt-in-place operation, so we have
        // to synthesize one by having it write its output to `out` &`tag` and
        // then copying `out` and `tag` to `in_out`.
        let mut out = vec![0u8; chunk_len];
        let mut tag = vec![0u8; tag_len];

        // XXX: This is a little misleading when `ad` isn't empty.
        b.bytes = chunk_len as u64;

        b.iter(|| {
            let mut encryptor =
                aes_gcm::AesGcm::new(key_size, &key, &crypto_bench::aead::NONCE,
                                     ad);
            encryptor.encrypt(&in_out[0..chunk_len], &mut out, &mut tag);
            // XXX: I doubt this is the fastest way of copying from `Vec`
            // to `Vec`.
            for i in 0..chunk_len {
                in_out[i] = out[i];
            }
            for i in 0..tag_len {
                in_out[chunk_len + i] = tag[i];
            }
        });
    }

    macro_rules! aes_gcm_bench {
        ( $benchmark_name:ident, $key_len: expr, $chunk_len:expr,
          $ad:expr ) => {
            #[bench]
            fn $benchmark_name(b: &mut test::Bencher) {
                super::aes_gcm($key_len, 128 / 8, $chunk_len, $ad, b);
            }
        }
    }

    macro_rules! aes_gcm_benches {
        ( $name:ident, $key_len:expr ) => {
            mod $name {
                use crypto_bench;
                use test;

                aes_gcm_bench!(tls12_finished, $key_len,
                               crypto_bench::aead::TLS12_FINISHED_LEN,
                               &crypto_bench::aead::TLS12_AD);
                aes_gcm_bench!(tls13_finished, $key_len,
                               crypto_bench::aead::TLS13_FINISHED_LEN,
                               &crypto_bench::aead::TLS12_AD);

                // For comparison with BoringSSL.
                aes_gcm_bench!(tls12_16, $key_len, 16,
                            &crypto_bench::aead::TLS12_AD);

                // ~1 packet of data in TLS.
                aes_gcm_bench!(tls12_1350, $key_len, 1350,
                               &crypto_bench::aead::TLS12_AD);
                aes_gcm_bench!(tls13_1350, $key_len, 1350,
                               &crypto_bench::aead::TLS13_AD);

                aes_gcm_bench!(tls12_8192, $key_len, 8192,
                               &crypto_bench::aead::TLS12_AD);
                aes_gcm_bench!(tls13_8192, $key_len, 8192,
                               &crypto_bench::aead::TLS13_AD);
            }
        }
    }

    aes_gcm_benches!(aes_128_gcm, 128 / 8);
    aes_gcm_benches!(aes_256_gcm, 256 / 8);

    // TODO: mod chacha20_poly1305 { ring_seal_in_place_benches!(&aead::CHACHA20_POLY1305); }
    // TODO: mod chacha20_poly1305_old { ring_seal_in_place_benches!(&aead::CHACHA20_POLY1305_OLD); }
}

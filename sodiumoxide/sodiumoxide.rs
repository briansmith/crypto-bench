#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

extern crate sodiumoxide;

mod agreement {
    mod x25519 {
        use sodiumoxide::init;
        use sodiumoxide::randombytes::randombytes_into;
        use sodiumoxide::crypto::scalarmult;
        use test::Bencher;

        #[bench]
        fn generate_key_pair(b: &mut Bencher) {
            init();

            b.iter(|| {
                let mut k = [0; scalarmult::SCALARBYTES];
                randombytes_into(&mut k[..]);
                let s = scalarmult::Scalar(k);

                scalarmult::scalarmult_base(&s)
            });
        }

        #[bench]
        fn generate_private_key(b: &mut Bencher) {
            init();

            b.iter(|| {
                let mut k = [0; scalarmult::SCALARBYTES];
                randombytes_into(&mut k[..]);
                scalarmult::Scalar(k)
            });
        }

        #[bench]
        fn generate_key_pair_and_agree_ephemeral(b: &mut Bencher) {
            init();

            let mut k = [0; scalarmult::SCALARBYTES];
            randombytes_into(&mut k[..]);
            let s = scalarmult::Scalar(k);

            b.iter(|| {
                let mut k1 = [0; scalarmult::SCALARBYTES];
                randombytes_into(&mut k1[..]);
                let s1 = scalarmult::Scalar(k1);
                let e1 = scalarmult::scalarmult_base(&s1);

                scalarmult::scalarmult(&s, &e1)
            });
        }
    }
}

mod digest {
    macro_rules! sodiumoxide_digest_benches {
        ( $name:ident, $block_len:expr, $output_len:expr, $digester:path) => {
            mod $name {
                use crypto_bench;
                use $digester;

                digest_benches!($block_len, input, {
                    hash(&input)
                });
            }
        }
    }

    sodiumoxide_digest_benches!(
        sha256, crypto_bench::SHA256_BLOCK_LEN, crypto_bench::SHA256_OUTPUT_LEN,
        sodiumoxide::crypto::hash::sha256::hash);
    sodiumoxide_digest_benches!(
        sha512, crypto_bench::SHA512_BLOCK_LEN, crypto_bench::SHA512_OUTPUT_LEN,
        sodiumoxide::crypto::hash::sha512::hash);
}

mod aead {
    use test;

    macro_rules! sodiumoxide_aead_bench {
        ( $benchmark_name:ident, $input_len:expr, $sealer:path ) => {
            #[bench]
            fn $benchmark_name(b: &mut test::Bencher) {
                use $sealer;
                use sodiumoxide::crypto::secretbox;
                b.bytes = $input_len;
                let key = secretbox::gen_key();
                let nonce = secretbox::gen_nonce();
                // XXX: secretbox doesn't support in-place encryption, so we
                // explicitly memcpy to have the same semantics as other
                // benchmarks. secretbox will add at most MACBYTES to the
                // result length, so that lets us know how to build a buffer
                // big enough for both input and output.
                let mut in_out = [0u8; $input_len + secretbox::MACBYTES];
                b.iter(|| {
                    let out = seal(&in_out[0..$input_len], &nonce, &key);
                    for i in 0..out.len() {
                        in_out[i] = out[i];
                    }
                });
            }
        }
    }

    sodiumoxide_aead_bench!(
        xsalsa20poly1305_16, 16,
        sodiumoxide::crypto::secretbox::xsalsa20poly1305::seal);
    sodiumoxide_aead_bench!(
        xsalsa20poly1305_1350, 1350,
        sodiumoxide::crypto::secretbox::xsalsa20poly1305::seal);
    sodiumoxide_aead_bench!(
        xsalsa20poly1305_8192, 8192,
        sodiumoxide::crypto::secretbox::xsalsa20poly1305::seal);
}

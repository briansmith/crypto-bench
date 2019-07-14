#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

mod aead;

mod agreement {
    macro_rules! ring_agreement_benches {
        ( $name:ident, $alg:expr) => {
            mod $name {
                use ring::{agreement, rand};

                // Generate a new private key and compute the public key.
                // Although these are separate steps in *ring*, in other APIs
                // they are a single step.
                #[bench]
                fn generate_key_pair(b: &mut test::Bencher) {
                    let rng = rand::SystemRandom::new();
                    b.iter(|| {
                        let private_key =
                            agreement::EphemeralPrivateKey::generate($alg, &rng).unwrap();
                        let _ = test::black_box(private_key.compute_public_key().unwrap());
                    });
                }

                #[bench]
                fn generate_private_key(b: &mut test::Bencher) {
                    let rng = rand::SystemRandom::new();
                    b.iter(|| {
                        let _ = agreement::EphemeralPrivateKey::generate($alg, &rng).unwrap();
                    });
                }

                // XXX: Because ring::agreement::agree_ephemeral moves its
                // private key argument, we cannot measure
                // `agreement::agree_ephemeral` on its own using the Rust
                // `Bencher` interface. To get an idea of its performance,
                // subtract the timing of `generate_private_key` from the
                // timing of this function.
                #[bench]
                fn generate_key_pair_and_agree_ephemeral(b: &mut test::Bencher) {
                    let rng = rand::SystemRandom::new();

                    // These operations are done by the peer.
                    let b_private = agreement::EphemeralPrivateKey::generate($alg, &rng).unwrap();
                    let b_public = b_private.compute_public_key().unwrap();
                    let b_public = agreement::UnparsedPublicKey::new($alg, b_public.as_ref());

                    b.iter(|| {
                        // These operations are all done in the
                        // `generate_key_pair` step.
                        let a_private =
                            agreement::EphemeralPrivateKey::generate($alg, &rng).unwrap();
                        let _a_public = a_private.compute_public_key().unwrap();
                        agreement::agree_ephemeral(a_private, &b_public, (), |_| Ok(())).unwrap();
                    });
                }
            }
        };
    }

    ring_agreement_benches!(p256, &agreement::ECDH_P256);
    ring_agreement_benches!(p384, &agreement::ECDH_P384);
    ring_agreement_benches!(x25519, &agreement::X25519);
}

mod digest {
    macro_rules! ring_digest_benches {
        ( $name:ident, $algorithm:expr) => {
            mod $name {
                use ring::digest;
                digest_benches!($algorithm.block_len, input, {
                    let _ = digest::digest($algorithm, &input);
                });
            }
        };
    }

    ring_digest_benches!(sha1, &digest::SHA1_FOR_LEGACY_USE_ONLY);
    ring_digest_benches!(sha256, &digest::SHA256);
    ring_digest_benches!(sha384, &digest::SHA384);
    ring_digest_benches!(sha512, &digest::SHA512);
}

mod pbkdf2 {
    use crypto_bench;
    use ring::pbkdf2;

    pbkdf2_bench!(
        hmac_sha256,
        crypto_bench::SHA256_OUTPUT_LEN,
        out,
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            crypto_bench::pbkdf2::ITERATIONS,
            &crypto_bench::pbkdf2::SALT,
            crypto_bench::pbkdf2::PASSWORD,
            &mut out
        )
    );

    pbkdf2_bench!(
        hmac_sha384,
        crypto_bench::SHA384_OUTPUT_LEN,
        out,
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA384,
            crypto_bench::pbkdf2::ITERATIONS,
            crypto_bench::pbkdf2::SALT,
            crypto_bench::pbkdf2::PASSWORD,
            &mut out
        )
    );

    pbkdf2_bench!(
        hmac_sha512,
        crypto_bench::SHA512_OUTPUT_LEN,
        out,
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512,
            crypto_bench::pbkdf2::ITERATIONS,
            crypto_bench::pbkdf2::SALT,
            crypto_bench::pbkdf2::PASSWORD,
            &mut out
        )
    );
}

mod signature {
    mod ed25519 {
        use ring::{rand, signature};

        #[bench]
        fn generate_key_pair(b: &mut test::Bencher) {
            let rng = rand::SystemRandom::new();
            b.iter(|| {
                signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            });
        }

        // We're interested in the timing of the Ed25519 operation, not the
        // timing of the hashing, so sign an empty message to minimize the time
        // spent hashing.
        #[bench]
        fn sign_empty(b: &mut test::Bencher) {
            let rng = rand::SystemRandom::new();
            let key_pair = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let key_pair = signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).unwrap();
            b.iter(|| {
                let signature = key_pair.sign(b"");
                let _ = signature.as_ref();
            });
        }
    }
}

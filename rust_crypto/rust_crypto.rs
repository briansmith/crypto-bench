#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

extern crate crypto;

#[cfg(test)]
mod digest {
    macro_rules! rust_crypto_digest_benches {
        ( $name:ident, $block_len:expr, $output_len:expr, $digest:expr) => {
            mod $name {
                use crypto;
                use crypto::digest::Digest;
                use crypto_bench;

                digest_benches!($block_len, input, {
                    let mut result = [0u8; $output_len];
                    let mut ctx = $digest;
                    ctx.input(&input);
                    ctx.result(&mut result);
                });
            }
        }
    }

    rust_crypto_digest_benches!(sha1, crypto_bench::SHA1_BLOCK_LEN,
                                crypto_bench::SHA1_OUTPUT_LEN,
                                crypto::sha1::Sha1::new());
    rust_crypto_digest_benches!(sha256, crypto_bench::SHA256_BLOCK_LEN,
                                crypto_bench::SHA256_OUTPUT_LEN,
                                crypto::sha2::Sha256::new());
    rust_crypto_digest_benches!(sha384, crypto_bench::SHA384_BLOCK_LEN,
                                crypto_bench::SHA384_OUTPUT_LEN,
                                crypto::sha2::Sha384::new());
    rust_crypto_digest_benches!(sha512, crypto_bench::SHA512_BLOCK_LEN,
                                crypto_bench::SHA512_OUTPUT_LEN,
                                crypto::sha2::Sha512::new());
}

#[cfg(test)]
mod pbkdf2 {
    use crypto::{hmac, pbkdf2, sha1, sha2};
    use crypto_bench;
    use test;

    pbkdf2_bench!(hmac_sha1, 20, out, {
        let mut mac = hmac::Hmac::new(sha1::Sha1::new(),
                                      &crypto_bench::pbkdf2::PASSWORD);
        pbkdf2::pbkdf2(&mut mac, &crypto_bench::pbkdf2::SALT,
                       crypto_bench::pbkdf2::ITERATIONS, &mut out);
    });

    pbkdf2_bench!(hmac_sha256, 32, out, {
        let mut mac = hmac::Hmac::new(sha2::Sha256::new(),
                                      &crypto_bench::pbkdf2::PASSWORD);
        pbkdf2::pbkdf2(&mut mac, &crypto_bench::pbkdf2::SALT,
                       crypto_bench::pbkdf2::ITERATIONS, &mut out);
    });

    pbkdf2_bench!(hmac_sha512, 64, out, {
        let mut mac = hmac::Hmac::new(sha2::Sha512::new(),
                                      &crypto_bench::pbkdf2::PASSWORD);
        pbkdf2::pbkdf2(&mut mac, &crypto_bench::pbkdf2::SALT,
                       crypto_bench::pbkdf2::ITERATIONS, &mut out);
    });
}

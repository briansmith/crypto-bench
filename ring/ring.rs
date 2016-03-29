#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

extern crate ring;

#[cfg(test)]
mod aead;

#[cfg(test)]
mod digest {
    macro_rules! ring_digest_benches {
        ( $name:ident, $algorithm:expr) => {
            mod $name {
                use ring::digest;
                digest_benches!($algorithm.block_len, input, {
                    let _ = digest::digest($algorithm, &input);
                });
            }
        }
    }

    ring_digest_benches!(sha1, &digest::SHA1);
    ring_digest_benches!(sha256, &digest::SHA256);
    ring_digest_benches!(sha384, &digest::SHA384);
    ring_digest_benches!(sha512, &digest::SHA512);
}

#[cfg(test)]
mod pbkdf2 {
    use crypto_bench;
    use ring::pbkdf2;
    use test;

    pbkdf2_bench!(hmac_sha256, crypto_bench::SHA256_OUTPUT_LEN, out,
                pbkdf2::derive(&pbkdf2::HMAC_SHA256,
                                crypto_bench::pbkdf2::ITERATIONS as usize,
                                &crypto_bench::pbkdf2::SALT,
                                crypto_bench::pbkdf2::PASSWORD, &mut out));

    pbkdf2_bench!(hmac_sha512, crypto_bench::SHA512_OUTPUT_LEN, out,
                pbkdf2::derive(&pbkdf2::HMAC_SHA512,
                                crypto_bench::pbkdf2::ITERATIONS as usize,
                                crypto_bench::pbkdf2::SALT,
                                crypto_bench::pbkdf2::PASSWORD, &mut out));
}

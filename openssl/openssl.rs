#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

extern crate openssl;

macro_rules! openssl_digest_benches {
    ( $name:ident, $block_len:expr, $alg:expr) => {
        mod $name {
            use crypto_bench;
            use openssl::crypto::hash;

            digest_benches!($block_len, input, {
                let _ = hash::hash($alg, input);
            });
        }
    }
}

mod digest {
    openssl_digest_benches!(sha1, crypto_bench::SHA1_BLOCK_LEN,
                            hash::Type::SHA1);
    openssl_digest_benches!(sha256, crypto_bench::SHA256_BLOCK_LEN,
                            hash::Type::SHA256);
    openssl_digest_benches!(sha384, crypto_bench::SHA384_BLOCK_LEN,
                            hash::Type::SHA384);
    openssl_digest_benches!(sha512, crypto_bench::SHA512_BLOCK_LEN,
                            hash::Type::SHA512);
}

mod pbkdf2 {
    use crypto_bench;
    use openssl;
    use test;

    pbkdf2_bench!(hmac_sha1, 20, out, {
        let vec = openssl::crypto::pkcs5::pbkdf2_hmac_sha1(
                    &crypto_bench::pbkdf2::PASSWORD_STR, &crypto_bench::pbkdf2::SALT,
                    crypto_bench::pbkdf2::ITERATIONS as usize, out.len());
        for i in 0..out.len() {
            out[i] = vec[i];
        }
    });
}

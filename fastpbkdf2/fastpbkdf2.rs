#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

extern crate fastpbkdf2;

mod pbkdf2 {
    use crypto_bench;
    use fastpbkdf2;
    use test;

    pbkdf2_bench!(hmac_sha1, crypto_bench::SHA1_OUTPUT_LEN, out,
                  fastpbkdf2::pbkdf2_hmac_sha1(crypto_bench::pbkdf2::PASSWORD,
                                               crypto_bench::pbkdf2::SALT,
                                               crypto_bench::pbkdf2::ITERATIONS.into(),
                                               &mut out));

    pbkdf2_bench!(hmac_sha256, crypto_bench::SHA256_OUTPUT_LEN, out,
                  fastpbkdf2::pbkdf2_hmac_sha256(crypto_bench::pbkdf2::PASSWORD,
                                                 crypto_bench::pbkdf2::SALT,
                                                 crypto_bench::pbkdf2::ITERATIONS.into(),
                                                 &mut out));

    pbkdf2_bench!(hmac_sha512, crypto_bench::SHA512_OUTPUT_LEN, out,
                  fastpbkdf2::pbkdf2_hmac_sha512(crypto_bench::pbkdf2::PASSWORD,
                                                 crypto_bench::pbkdf2::SALT,
                                                 crypto_bench::pbkdf2::ITERATIONS.into(),
                                                 &mut out));
}

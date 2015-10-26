// These values are copied from
// https://github.com/ctz/rust-fastpbkdf2/tree/master/pbkdf2-bench,
// except `ITERATIONS` was lowered from `1 << 20` because the
// benchmarks were excruciatingly slow with 2^20 iterations, and that
// iteration count isn't realistic for most applications anyway.
pub const ITERATIONS: u32 = 100_000;
pub const PASSWORD: &'static [u8] = b"password";
pub const PASSWORD_STR: &'static str = "password";
pub const SALT: &'static [u8] = b"salt";

macro_rules! pbkdf2_bench {
    ( $bench_fn_name:ident, $out_len:expr, $out:ident, $calculation:expr) => {
        #[bench]
        fn $bench_fn_name(b: &mut test::Bencher) {
            let mut $out = [0u8; $out_len];
            b.iter(|| $calculation);
        }
    }
}

mod ring {
    use ring::pbkdf2;
    use super::*;
    use test;

    pbkdf2_bench!(hmac_sha1, 20, out,
                  pbkdf2::derive(&pbkdf2::HMAC_SHA1, ITERATIONS as usize, SALT,
                                 PASSWORD, &mut out));

    pbkdf2_bench!(hmac_sha256, 32, out,
                  pbkdf2::derive(&pbkdf2::HMAC_SHA256, ITERATIONS as usize, SALT,
                                 PASSWORD, &mut out));

    pbkdf2_bench!(hmac_sha512, 64, out,
                  pbkdf2::derive(&pbkdf2::HMAC_SHA512, ITERATIONS as usize, SALT,
                                 PASSWORD, &mut out));
}

mod rust_crypto {
    use crypto::{hmac, pbkdf2, sha1, sha2};
    use super::*;
    use test;

    pbkdf2_bench!(hmac_sha1, 20, out, {
            let mut mac = hmac::Hmac::new(sha1::Sha1::new(), PASSWORD);
            pbkdf2::pbkdf2(&mut mac, SALT, ITERATIONS, &mut out);
    });

    pbkdf2_bench!(hmac_sha256, 32, out, {
            let mut mac = hmac::Hmac::new(sha2::Sha256::new(), PASSWORD);
            pbkdf2::pbkdf2(&mut mac, SALT, ITERATIONS, &mut out);
    });

    pbkdf2_bench!(hmac_sha512, 64, out, {
            let mut mac = hmac::Hmac::new(sha2::Sha512::new(), PASSWORD);
            pbkdf2::pbkdf2(&mut mac, SALT, ITERATIONS, &mut out);
    });
}

mod rust_fastpbkdf2 {
    use fastpbkdf2;
    use super::*;
    use test;

    pbkdf2_bench!(hmac_sha1, 20, out,
                  fastpbkdf2::pbkdf2_hmac_sha1(PASSWORD, SALT, ITERATIONS,
                                               &mut out));

    pbkdf2_bench!(hmac_sha256, 32, out,
                  fastpbkdf2::pbkdf2_hmac_sha256(PASSWORD, SALT, ITERATIONS,
                                                 &mut out));

    pbkdf2_bench!(hmac_sha512, 64, out,
                  fastpbkdf2::pbkdf2_hmac_sha512(PASSWORD, SALT, ITERATIONS,
                                                 &mut out));
}

mod rust_openssl {
    use openssl;
    use super::*;
    use test;

    pbkdf2_bench!(hmac_sha1, 20, out, {
        let vec = openssl::crypto::pkcs5::pbkdf2_hmac_sha1(&PASSWORD_STR, SALT,
                                                        ITERATIONS as usize,
                                                        out.len());
        for i in 0..out.len() {
            out[i] = vec[i];
        }
    });
}

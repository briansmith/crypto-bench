#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;
extern crate commoncrypto_sys;

mod digest {
    macro_rules! commoncrypto_digest_benches {
        ( $name: ident, $block_len: expr, $alg: ident ) => {
            mod $name {
                use crypto_bench;
                use commoncrypto_sys;

                digest_benches!($block_len, input, {
                    let mut md = [0u8; $block_len];
                    unsafe {
                        commoncrypto_sys::CCDigest(commoncrypto_sys::CCDigestAlgorithm::$alg,
                                                   input.as_ptr(),
                                                   input.len(),
                                                   md.as_mut_ptr());
                    }
                });
            }
        }
    }

    commoncrypto_digest_benches!(sha1, crypto_bench::SHA1_BLOCK_LEN, kCCDigestSHA1);
    commoncrypto_digest_benches!(sha256, crypto_bench::SHA256_BLOCK_LEN, kCCDigestSHA256);
    commoncrypto_digest_benches!(sha384, crypto_bench::SHA384_BLOCK_LEN, kCCDigestSHA384);
    commoncrypto_digest_benches!(sha512, crypto_bench::SHA512_BLOCK_LEN, kCCDigestSHA512);
}

mod pbkdf2 {
    use commoncrypto_sys;
    use crypto_bench;
    use test;

    macro_rules! commoncrypto_pbkdf2_bench {
        ( $name: ident, $alg: expr, $out_len: expr ) => {

            pbkdf2_bench!($name, $out_len, out, {
                unsafe {
                    let _ =  commoncrypto_sys::CCKeyDerivationPBKDF(
                        commoncrypto_sys::CCPBKDFAlgorithm::kCCPBKDF2,
                        crypto_bench::pbkdf2::PASSWORD_STR.as_ptr(),
                        crypto_bench::pbkdf2::PASSWORD_STR.len(),
                        crypto_bench::pbkdf2::SALT.as_ptr(),
                        crypto_bench::pbkdf2::SALT.len(),
                        $alg,
                        crypto_bench::pbkdf2::ITERATIONS,
                        out.as_mut_ptr(),
                        $out_len
                    );
                }
            });
        }
    }

    commoncrypto_pbkdf2_bench!(hmac_sha1,
                               commoncrypto_sys::CCPseudoRandomAlgorithm::kCCPRFHmacAlgSHA1,
                               crypto_bench::SHA1_OUTPUT_LEN);

    commoncrypto_pbkdf2_bench!(hmac_sha256,
                               commoncrypto_sys::CCPseudoRandomAlgorithm::kCCPRFHmacAlgSHA256,
                               crypto_bench::SHA256_OUTPUT_LEN);

    commoncrypto_pbkdf2_bench!(hmac_sha512,
                               commoncrypto_sys::CCPseudoRandomAlgorithm::kCCPRFHmacAlgSHA512,
                               crypto_bench::SHA512_OUTPUT_LEN);
}

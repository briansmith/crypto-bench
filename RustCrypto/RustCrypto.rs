#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

extern crate sha2;

mod digest {
    macro_rules! rust_crypto_digest_benches {
        ( $name:ident, $block_len:expr, $output_len:expr, $digest:expr) => {
            mod $name {
                use sha2::Digest;
                use crypto_bench;

                digest_benches!($block_len, input, {
                    let mut ctx = $digest;
                    ctx.input(&input);
                    let _ = ctx.result();
                });
            }
        }
    }
    rust_crypto_digest_benches!(sha256, crypto_bench::SHA256_BLOCK_LEN,
                                crypto_bench::SHA256_OUTPUT_LEN,
                                sha2::Sha256::default());
    rust_crypto_digest_benches!(sha384, crypto_bench::SHA384_BLOCK_LEN,
                                crypto_bench::SHA384_OUTPUT_LEN,
                                sha2::Sha384::default());
    rust_crypto_digest_benches!(sha512, crypto_bench::SHA512_BLOCK_LEN,
                                crypto_bench::SHA512_OUTPUT_LEN,
                                sha2::Sha512::default());
}


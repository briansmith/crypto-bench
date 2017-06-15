#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

extern crate sha1;


mod digest {
    macro_rules! rust_crypto_digest_benches {
        ( $name:ident, $block_len:expr, $output_len:expr, $digest:expr) => {
            mod $name {
                use sha1;
                use crypto_bench;

                digest_benches!($block_len, input, {
                    // let mut result = [0u8; $output_len];
                    let mut ctx = $digest;
                    ctx.update(&input);
                    ctx.digest();
                });
            }
        }
    }

    rust_crypto_digest_benches!(sha1, crypto_bench::SHA1_BLOCK_LEN,
                                crypto_bench::SHA1_OUTPUT_LEN,
                                sha1::Sha1::new());
}
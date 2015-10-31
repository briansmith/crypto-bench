#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

extern crate octavo;

#[cfg(test)]
mod digest {
    macro_rules! octavo_digest_benches {
        ( $name:ident, $block_len:expr, $output_len:expr, $digest:expr) => {
            mod $name {
                use crypto_bench;
                use octavo::digest;
                use octavo::digest::Digest;

                digest_benches!($block_len, input, {
                    let mut out = [0u8; $output_len];
                    let mut ctx = $digest;
                    ctx.update(&input);
                    ctx.result(&mut out[..]);
                });
            }
        }
    }

    octavo_digest_benches!(sha1, crypto_bench::SHA1_BLOCK_LEN,
                           crypto_bench::SHA1_OUTPUT_LEN,
                           digest::sha1::Sha1::default());
    octavo_digest_benches!(sha256, crypto_bench::SHA256_BLOCK_LEN,
                           crypto_bench::SHA256_OUTPUT_LEN,
                           digest::sha2::Sha256::default());
    octavo_digest_benches!(sha384, crypto_bench::SHA384_BLOCK_LEN,
                           crypto_bench::SHA384_OUTPUT_LEN,
                           digest::sha2::Sha384::default());
    octavo_digest_benches!(sha512, crypto_bench::SHA512_BLOCK_LEN,
                           crypto_bench::SHA512_OUTPUT_LEN,
                           digest::sha2::Sha512::default());
}

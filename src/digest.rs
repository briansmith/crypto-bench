
macro_rules! digest_bench {
    ( $bench_fn_name:ident, $input_len:expr, $input:ident,
      $calculation:expr) => {
        #[bench]
        fn $bench_fn_name(b: &mut test::Bencher) {
            let $input = vec![0u8; $input_len];
            let $input = &$input[..];
            b.iter(|| $calculation)
        }
    }
}

macro_rules! digest_benches {
    ($algorithm_name:ident, $block_len:expr, $input:ident, $calculation:expr) =>
    {
        mod $algorithm_name {
            use ring;
            use test;

            digest_bench!(block_len, $block_len, $input, $calculation); // PBKDF2
            digest_bench!(_16, 16, $input, $calculation); // BoringSSL
            digest_bench!(_256, 256, $input, $calculation); // BoringSSL
            digest_bench!(_1000, 1000, $input, $calculation); // X.509 TBSCertificate
            digest_bench!(_2000, 2000, $input, $calculation); // X.509 TBSCertificate
            digest_bench!(_8192, 8192, $input, $calculation); // BoringSSL
        }
    }
}

mod octavo {
    digest_benches!(sha1, ring::digest::SHA1.block_len, input, {
        use octavo::digest;
        use octavo::digest::Digest;
        let mut out = [0u8; 20];
        let mut ctx = digest::sha1::Sha1::default();
        ctx.update(&input);
        ctx.result(&mut out[..]);
    });

    digest_benches!(sha256, ring::digest::SHA256.block_len, input, {
        use octavo::digest;
        use octavo::digest::Digest;
        let mut out = [0u8; 32];
        let mut ctx = digest::sha2::Sha256::default();
        ctx.update(&input);
        ctx.result(&mut out[..]);
    });

    digest_benches!(sha384, ring::digest::SHA384.block_len, input, {
        use octavo::digest;
        use octavo::digest::Digest;
        let mut out = [0u8; 48];
        let mut ctx = digest::sha2::Sha384::default();
        ctx.update(&input);
        ctx.result(&mut out[..]);
    });

    digest_benches!(sha512, ring::digest::SHA512.block_len, input, {
        use octavo::digest;
        use octavo::digest::Digest;
        let mut out = [0u8; 64];
        let mut ctx = digest::sha2::Sha512::default();
        ctx.update(&input);
        ctx.result(&mut out[..]);
    });
}

mod ring {
    digest_benches!(sha1, ring::digest::SHA1.block_len, input,
                    ring::digest::digest(&ring::digest::SHA1, &input));
    digest_benches!(sha256, ring::digest::SHA256.block_len, input,
                    ring::digest::digest(&ring::digest::SHA256, &input));
    digest_benches!(sha384, ring::digest::SHA384.block_len, input,
                    ring::digest::digest(&ring::digest::SHA384, &input));
    digest_benches!(sha512, ring::digest::SHA512.block_len, input,
                    ring::digest::digest(&ring::digest::SHA512, &input));
}

mod rust_crypto {
    digest_benches!(sha1, ring::digest::SHA1.block_len, input, {
        use crypto;
        use crypto::digest::Digest;
        let mut result = [0u8; 20];
        let mut ctx = crypto::sha1::Sha1::new();
        ctx.input(&input);
        ctx.result(&mut result);
    });

    digest_benches!(sha256, ring::digest::SHA256.block_len, input, {
        use crypto;
        use crypto::digest::Digest;
        let mut result = [0u8; 32];
        let mut ctx = crypto::sha2::Sha256::new();
        ctx.input(&input);
        ctx.result(&mut result);
    });

    digest_benches!(sha384, ring::digest::SHA384.block_len, input, {
        use crypto;
        use crypto::digest::Digest;
        let mut result = [0u8; 48];
        let mut ctx = crypto::sha2::Sha384::new();
        ctx.input(&input);
        ctx.result(&mut result);
    });

    digest_benches!(sha512, ring::digest::SHA512.block_len, input, {
        use crypto;
        use crypto::digest::Digest;
        let mut result = [0u8; 64];
        let mut ctx = crypto::sha2::Sha512::new();
        ctx.input(&input);
        ctx.result(&mut result[..]);
    });
}

mod rust_openssl {
    digest_benches!(sha1, ring::digest::SHA1.block_len, input, {
        use openssl::crypto::hash;
        let _ = hash::hash(hash::Type::SHA1, input);
    });
    digest_benches!(sha256, ring::digest::SHA256.block_len, input, {
        use openssl::crypto::hash;
        let _ = hash::hash(hash::Type::SHA256, input);
    });
    digest_benches!(sha384, ring::digest::SHA384.block_len, input, {
        use openssl::crypto::hash;
        let _ = hash::hash(hash::Type::SHA384, input);
    });
    digest_benches!(sha512, ring::digest::SHA512.block_len, input, {
        use openssl::crypto::hash;
        let _ = hash::hash(hash::Type::SHA512, input);
    });
}

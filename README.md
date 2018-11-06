# crypto-bench

Benchmarks for Rust crypto libraries



## Which benchmarks have been written?

|                                              |       *ring*       |     rust-crypto    | rust-nettle (Nettle) | rust-openssl (OpenSSL) | sodiumoxide (libsodium) | Windows CNG | Mac/iOS Common Crypto |
|----------------------------------------------|:------------------:|:------------------:|----------------------|:----------------------:|:-----------------------:|:-----------:|:---------------------:|
| SHA&#x2011;1 & SHA&#x2011;2                  | :white_check_mark: | :white_check_mark: |                      | :white_check_mark:     | SHA-{256,512} only      |             |                       |
| HMAC (SHA&#x2011;1 & SHA&#x2011;2)           |                    |                    |                      |                        |                         |             |                       |
| PBKDF2 (SHA&#x2011;1 & SHA&#x2011;2)         | SHA-2 only         | :white_check_mark: |                      | SHA-1 only             |                         |             |                       |
| AES&#x2011;128&#x2011;GCM & AES&#x2011;256&#x2011;GCM | :white_check_mark: | :white_check_mark: |                      |                        |                         |             |                       |
| ChaCha20&#x2011;Poly1305                     | :white_check_mark: | :white_check_mark: |                      |                        |                         |             |                       |
| Salsa20&#x2011;Poly1305                      |                    |                    |                      |                        | :white_check_mark:      |             |                       |
| ECDH (Suite B) key exchange                  | :white_check_mark: |                    |                      |                        |                         |             |                       |
| X25519 (Curve25519) key exchange             | :white_check_mark: | :white_check_mark: |                      |                        |                         |             |                       |
| Random Byte Generation                       |                    |                    |                      |                        |                         |             |                       |
| ECDSA (Suite B) signature verification       | In Progress (@briansmith) |             |                      |                        |                         |             |                       |
| Ed25519 signature verification               | In Progress (@briansmith) | In Progress (@briansmith) |        |                        |                         |             |                       |
| RSA signature verification                   | In Progress (@briansmith) |             |                      |                        |                         |             |                       |
| ECDSA signing (Suite B with SHA&#x2011;1 & SHA&#x2011;2) |        |                    |                      |                        |                         |             |                       |
| Ed25519 (Curve25519) signing                 | :white_check_mark: | :white_check_mark: |                      |                        |                         |             |                       |
| RSA signing (SHA&#x2011;1 & SHA&#x2011;2)    |                    |                    |                      |                        |                         |             |                       |

* fastpbkdf2 is also benchmarked, for PBKDF2 only.
* "Suite B" refers the the P-256 and P-384 elliptic curves.
* "SHA-2" refers to SHA-256, SHA-384, and SHA-512.


## How to contribute

### Add new benchmarks

Follow the style of the existing examples. When implementing the same benchmark
across multiple implementations, make sure that you're comparing the same
thing (as much as is practical). Also, follow the submodule structure and
naming scheme used in the existing benchmarks. It is often useful to create
macros to minimize the amount of boilerplate required.

### Add tools for visualizing the results

For example, it would be great to be able to get a graph or a table, or JSON
that can be imported into some charting library, that allows one to compare the
performance of one implementation to another. Similarly, it would be awesome to
have a tool that allows one to see how the performance of a particular crypto
library changes between versions.

These tools do *not* need to be written in Rust. They can be in Python or
shell scripts or whatever. I highly recommend just scraping the output of
`cargo bench` instead of trying to make changes to rustc, Cargo, and the Rust
standard library. Perfect is the enemy of the good.



## How to run all the benchmarks for all implementations

These benchmarks currently only can be built/run using Nightly Rust because
they use Rust's built-in benchmarking feature, and that feature is marked
"unstable" (i.e. "Nightly-only").

```
git clone https://github.com/briansmith/crypto-bench && cd crypto-bench && cargo update && cargo +nightly bench
```

You must use Rust Nightly because `cargo bench` is used for these benchmarks,
and only Right Nightly supports `cargo bench`.

You don't need to run `cargo build`, and in fact `cargo build` does not do
anything useful for this crate.

`./cargo +nightly test` runs one iteration of every benchmark for every
implementation. This is useful for quickly making sure that a change to the
benchmarks does not break them. Do this before submitting a pull request.

`cargo update` in the workspace root will update all the libraries to the
latest version.


## How to run all the benchmarks for a specific crypto library

* `cargo +nightly bench -p crypto_bench_fastpbkdf2` runs all the tests for [rust-fastpbkdf2](https://github.com/ctz/rust-fastpbkdf2).
* `cargo +nightly bench -p crypto_bench_openssl` runs all the tests for [rust-openssl](https://github.com/sfackler/rust-openssl).
* `cargo +nightly bench -p crypto_bench_ring` runs all the tests for [*ring*](https://github.com/briansmith/ring).
* `cargo +nightly bench -p crypto_bench_rust_crypto` runs all the tests for [rust-crypto](https://github.com/DaGenix/rust-crypto).
* `cargo +nightly bench -p crypto_bench_sodiumoxide` runs all the tests for [sodiumoxide](https://github.com/dnaq/sodiumoxide).



## How to run other subsets of the benchmarks

`cargo bench` takes arbitrary substrings of the test names as parameters, so
you can get as specific as you want. For example,
`cargo +nightly bench sha512::_2000` will run just the SHA-512 benchmark that
takes a 2000 byte input, for every implementation.



## Why does each implementation's benchmark live in a separate crate?

* Not all implementations build and work on all platforms. And, some
  implementations requre manual configuration (e.g. building/installing some
  third-party C library) to work.

* Some implementations may not be able to (correctly) coexist in the same
  program because they define extern C symbols with the same names, but which
  are not interoperable. (This used to be the case for *ring* and rust-openssl,
  however *ring* implemented a workaround that allows *ring* to be used
  alongside other OpenSSL forks.)



## License

[CC0](https://creativecommons.org/publicdomain/zero/1.0/).

# crypto-bench: Benchmarks for Rust crypto libraries.

## How to run all the benchmarks for all implementations.

```
git clone https://github.com/briansmith/crypto-bench && \
cd cargo-bench && \
./cargo_all bench
```

You must use Rust Nightly because `cargo bench` is used for these benchmarks,
and only Right Nightly supports `cargo bench`.

You don't need to run `cargo build`, and in fact `cargo build` does not do
anything useful for this crate.

`./cargo_all.sh test` runs one iteration of every benchmark for every
implementation. This is useful for quickly making sure that a change to the
benchmarks does not break them. Do this before submitting a pull request.

## How to run all the benchmarks for a specific crypto library

* `(cd fastpbkdf2 && cargo bench)` runs all the tests for [rust-fastpbkdf2](https://github.com/ctz/rust-fastpbkdf2).
* `(cd octavo && cargo bench)` runs all the tests for [Octavo](https://github.com/libOctavo/octavo).
* `(cd openssl && cargo bench)` runs all the tests for [rust-openssl](https://github.com/sfackler/rust-openssl).
* `(cd ring && cargo bench)` runs all the tests for [*ring*](https://github.com/briansmith/ring).
* `(cd rust_crypto && cargo bench)` runs all the tests for [rust-crypto](https://github.com/DaGenix/rust-crypto).

## How to run other subsets of the benchmarks

`./cargo bench` takes arbitrary substrings of the test names as parameters, so
you can get as specific as you want. For example,
`./cargo_all bench sha512::_2000` will run just the SHA-512
benchmark that takes a 2000 byte input, for every implementation.

## Why does each implementation's benchmark live in a separate crate?

* Not all implementations build and work on all platforms. And, some
  implementations requre manual configuration (e.g. building/installing some
  third-party C library) to work. The `cargo_all` scripts keep going on
  failure, so they'll build/test/benchmark whatever implementations actually
  work, and skip over the ones that don't. This would be difficult to acheive
  if all the benchmarks were in one crate.

* Some implementations (*ring* and any of the crates that use OpenSSL) cannot
  (correctly) coexist in the same program because they define extern C symbols
  with the same names, but which have different ABIs.

## How to contribute

* Add new benchmarks. It is recommended that you
  [file an issue in the issue tracker](https://github.com/briansmith/crypto-bench/issues/new)
  beforehand, to nail down the design of the benchmark and ensure it will be
  accepted.

* Add tools for visualizing the results.

## License

[CC0](https://creativecommons.org/publicdomain/zero/1.0/).

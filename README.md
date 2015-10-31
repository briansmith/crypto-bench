# crypto-bench: Benchmarks for Rust crypto libraries.

## How to run all the benchmarks for all implementations.

```
git clone https://github.com/briansmith/crypto-bench
cargo bench
```

You must use Rust Nightly because `cargo bench` is used for these benchmarks,
and only Right Nightly supports `cargo bench`. Note that currently the
benchmarks do not build for pc-windows-msvc targets because
[rust-fastpbkdf2 fails to build for pc-windows-msvc](https://github.com/ctz/rust-fastpbkdf2/issues/1)
and [rust-crypto fails to build for pc-windows-msvc](https://github.com/DaGenix/rust-crypto/issues/324).
pc-windows-gnu targets are not supported because the pc-windows-gnu targets are
a dead end.

You don't need to run `cargo build`, and in fact `cargo build` does not do
anything useful for this crate.

`cargo test` runs one iteration of every benchmark. This is useful for quickly
making sure that a change to the benchmarks does not break them.

Note that some crypto libraries only support a subset of the tests.

## How to run all the benchmarks for a specific crypto library

Use `cargo bench ::<implementation>::`:

* `cargo bench ::ring::` runs all the tests for [*ring*](https://github.com/briansmith/ring).
* `cargo bench ::octavo::` runs all the tests for [Octavo](https://github.com/libOctavo/octavo).
* `cargo bench ::rust_crypto::` runs all the tests for [rust-crypto](https://github.com/DaGenix/rust-crypto).
* `cargo bench ::fastpbkdf2::` runs all the tests for [rust-fastpbkdf2](https://github.com/ctz/rust-fastpbkdf2).
* `cargo bench ::openssl::` runs all the tests for [rust-openssl](https://github.com/sfackler/rust-openssl).

## How to run other subsets of the benchmarks

`cargo bench` takes arbitrary substrings of the test names as parameters, so
you can get as specific as you want. For example,
`digest::ring::sha512::_2000` will run just the SHA-512
benchmark that takes a 2000 byte input, just for *ring*.

## How to contribute

* Add new benchmarks. It is recommended that you
  [file an issue in the issue tracker](https://github.com/briansmith/crypto-bench/issues/new)
  beforehand, to nail down the design of the benchmark and ensure it will be
  accepted.

* Add tools for visualizing the results.

## License

[CC0](https://creativecommons.org/publicdomain/zero/1.0/).

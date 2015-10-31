PUSHD fastpbkdf2
cargo %*
POPD

PUSHD octavo
cargo %*
POPD

PUSHD openssl
cargo %*
POPD

PUSHD ring
cargo %*
POPD

PUSHD rust_crypto
cargo %*
POPD

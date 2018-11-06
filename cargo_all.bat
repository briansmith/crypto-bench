PUSHD fastpbkdf2
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

PUSHD sodiumoxide
cargo %*
POPD

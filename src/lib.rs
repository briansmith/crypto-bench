// This crate only contains benchmarks, but we have to define a program with
// `main` to avoid things complaining.

#![feature(test)]

extern crate crypto;
extern crate fastpbkdf2;
extern crate octavo;
extern crate openssl;
extern crate ring;
extern crate test;

#[cfg(test)] mod aead;
#[cfg(test)] mod digest;
#[cfg(test)] mod pbkdf2;

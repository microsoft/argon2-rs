//! Verifies one BLAKE2b 128-byte block-to-chaining-state transition.

#![feature(proc_macro_hygiene)]

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
#[path = "../src/blake2b_compress.rs"]
mod blake2b_compress;
#[path = "../src/blake2b_tables.rs"]
mod blake2b_tables;
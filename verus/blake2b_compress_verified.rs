//! Verifies one BLAKE2b 128-byte block-to-chaining-state transition.

#![feature(proc_macro_hygiene)]
#![feature(cfg_eval)]

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
#[path = "../src/wipe.rs"]
mod wipe;
#[path = "../src/blake2b_compress.rs"]
mod blake2b_compress;
#[path = "../src/blake2b_tables.rs"]
mod blake2b_tables;
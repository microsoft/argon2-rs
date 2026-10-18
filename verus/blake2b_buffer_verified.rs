//! Verifies one streaming BLAKE2b buffer append transition.

#![feature(proc_macro_hygiene)]
#![feature(cfg_eval)]
#![verifier::exec_allows_no_decreases_clause]

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
#[path = "../src/wipe.rs"]
mod wipe;
#[path = "../src/blake2b_compress.rs"]
mod blake2b_compress;
#[path = "../src/blake2b_tables.rs"]
mod blake2b_tables;
#[path = "../src/blake2b_buffer.rs"]
mod blake2b_buffer;
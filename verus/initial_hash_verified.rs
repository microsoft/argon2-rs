//! Same-source H0 serialization/composition proof, not a returned-tag theorem.

#![feature(proc_macro_hygiene)]
#![feature(cfg_eval)]

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
#[path = "../proofs/blake2b_update.rs"]
mod blake2b_update_model;
#[path = "../proofs/blake2b_long.rs"]
mod blake2b_long_model;
#[path = "../proofs/initial_hash.rs"]
mod initial_hash_model;
#[path = "../src/blake2b_tables.rs"]
mod blake2b_tables;
#[path = "../src/blake2b_compress.rs"]
mod blake2b_compress;
#[path = "../src/blake2b_buffer.rs"]
mod blake2b_buffer;
#[path = "../src/blake2b_update.rs"]
mod blake2b_update;
#[path = "../src/wipe.rs"]
mod wipe;
#[path = "../src/blake2b.rs"]
mod blake2b;
#[path = "../src/initial_hash.rs"]
mod initial_hash;
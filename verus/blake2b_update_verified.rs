//! Same-source offset-update proof against a finite model-step trace.

#![feature(proc_macro_hygiene)]

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
#[path = "../proofs/blake2b_update.rs"]
mod blake2b_update_model;
#[path = "../src/blake2b_compress.rs"]
mod blake2b_compress;
#[path = "../src/blake2b_tables.rs"]
mod blake2b_tables;
#[path = "../src/blake2b_buffer.rs"]
mod blake2b_buffer;
#[path = "../src/blake2b_update.rs"]
mod blake2b_update;
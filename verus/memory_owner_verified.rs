//! Real owning-arena initialization method; allocation is not specified here.

#![feature(proc_macro_hygiene)]
#![feature(cfg_eval)]

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
#[path = "../proofs/geometry.rs"]
mod proofs;
#[path = "../proofs/blake2b_update.rs"]
mod blake2b_update_model;
#[path = "../proofs/blake2b_long.rs"]
mod blake2b_long_model;
#[path = "../proofs/memory_initialization.rs"]
mod memory_initialization_model;
#[path = "../src/core_primitives.rs"]
mod core_primitives;
#[path = "../src/parameters.rs"]
mod parameters;
pub use parameters::{Algorithm, Error, Params, Version};
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
#[path = "../src/block_primitives.rs"]
mod block_primitives;
#[path = "../src/block_g.rs"]
mod block_g;
#[path = "../src/block_g_column.rs"]
mod block_g_column;
#[path = "../src/block_g_columns.rs"]
mod block_g_columns;
#[path = "../src/block_g_fill.rs"]
mod block_g_fill;
#[path = "../src/block.rs"]
mod block;
#[path = "../src/memory_initialization.rs"]
mod memory_initialization;
#[path = "../src/memory.rs"]
mod memory;
//! Verifies the scalar 128-word G composition used by block::fill_block.

#![feature(proc_macro_hygiene)]
#![feature(cfg_eval)]
#![verifier::exec_allows_no_decreases_clause]

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
#[path = "../src/wipe.rs"]
mod wipe;
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
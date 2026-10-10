//! Verifies the real data-independent address-block generation transition.

#![feature(proc_macro_hygiene)]

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
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
#[path = "../src/core_address.rs"]
mod core_address;
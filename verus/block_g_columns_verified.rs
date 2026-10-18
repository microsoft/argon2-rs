//! Verifies the production loop that applies P to all eight block columns.

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
#[path = "../src/block_g_column.rs"]
mod block_g_column;
#[path = "../src/block_g_columns.rs"]
mod block_g_columns;
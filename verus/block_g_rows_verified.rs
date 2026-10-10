//! Verifies the row-wise loop helper used by the production scalar G body.

#![feature(proc_macro_hygiene)]
#![verifier::exec_allows_no_decreases_clause]

use vstd::prelude::*;

#[path = "../src/block_g.rs"]
mod block_g;
#[path = "../src/block_primitives.rs"]
mod block_primitives;
#[path = "../specs/mod.rs"]
mod specs;

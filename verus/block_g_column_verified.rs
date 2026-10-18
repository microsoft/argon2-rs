//! Verifies gathering, permuting, and scattering one Argon2 block column.

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
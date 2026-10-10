//! Verifies the production BLAKE2b IV and SIGMA table constructors.

#![feature(proc_macro_hygiene)]

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
#[path = "../src/blake2b_tables.rs"]
mod blake2b_tables;
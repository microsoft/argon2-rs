#![feature(proc_macro_hygiene)]
#![feature(cfg_eval)]

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
#[path = "../proofs/geometry.rs"]
mod proofs;
#[path = "../src/core_primitives.rs"]
mod core_primitives;
#[path = "../src/parameters.rs"]
mod parameters;
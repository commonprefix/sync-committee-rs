//! Primitive types for sync committee verifier
//! This crate contains code adapted from https://github.com/ralexstokes/ethereum-consensus
#[warn(unused_imports)]
#[warn(unused_variables)]
extern crate alloc;

pub mod consensus_types;
pub mod constants;
pub mod domains;
pub mod error;
pub mod serde;
mod ssz;
pub mod types;
pub mod util;

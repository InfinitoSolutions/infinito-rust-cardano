//! Epoch start and normal blocks
//!
//! All epoch inner block specific types are available in the normal module
//! and the new epoch block types are in genesis

pub mod types;
pub mod genesis; /* genesis block related value */
pub mod normal; /* normal block related value */
pub mod block;
pub mod verify;
pub mod update;

pub use block::types::*;
pub use block::block::*;
pub use block::verify::*;

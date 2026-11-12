#![forbid(unsafe_code)]

pub mod inspect;
pub mod output;

pub use inspect::{InspectionLimits, inspect_path, inspect_path_with_limits};

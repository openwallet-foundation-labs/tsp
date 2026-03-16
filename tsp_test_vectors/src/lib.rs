//! Support crate for TSP test-vector assets, authoring workflows, and
//! validator-facing consumption utilities.

pub mod authoring;
pub mod case_runner;
pub mod layout;
pub mod validator;

/// Crate-local marker for the workspace-level test-vector package.
pub const CRATE_NAME: &str = "tsp_test_vectors";

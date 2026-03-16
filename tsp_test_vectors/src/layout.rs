//! Shared path defaults for the test-vector workspace member.

/// Current default root for canonical case packages.
pub const DEFAULT_PACKAGE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");

/// Current default shared vector catalog path after staged migration into the
/// dedicated test-vector crate.
pub const DEFAULT_VECTOR_CATALOG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/spec/test-vector-instances.md"
);

/// Current default case-level outputs catalog path.
pub const DEFAULT_CASE_OUTPUTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/spec/test-vector-case-outputs.md"
);

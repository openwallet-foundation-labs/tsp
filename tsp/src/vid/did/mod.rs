pub(crate) const SCHEME: &str = "did";

pub(crate) mod peer;

pub(crate) mod tdw;
#[cfg(feature = "resolve")]
pub(crate) mod web;

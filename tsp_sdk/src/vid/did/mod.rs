pub(crate) const SCHEME: &str = "did";

pub(crate) mod peer;

#[cfg(feature = "resolve")]
pub(crate) mod web;

#[cfg(feature = "resolve")]
pub use web::get_resolve_url;

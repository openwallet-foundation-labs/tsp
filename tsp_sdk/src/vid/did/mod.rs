pub(crate) const SCHEME: &str = "did";

pub(crate) mod peer;

#[cfg(feature = "resolve")]
pub mod web;

pub use web::get_resolve_url;

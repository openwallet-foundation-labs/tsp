pub(crate) const SCHEME: &str = "did";

pub(crate) mod peer;

#[cfg(feature = "resolve")]
pub mod web;

#[cfg(feature = "resolve")]
pub mod webvh;

/// The controller's side of the hosting service: registry, apply, publish, notify.
#[cfg(feature = "resolve")]
pub mod hosting;

#[cfg(feature = "resolve")]
pub mod scid;

#[cfg(feature = "resolve")]
pub use web::get_resolve_url;

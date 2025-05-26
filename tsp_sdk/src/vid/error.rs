#[cfg(not(target_arch = "wasm32"))]
use didwebvh_resolver::ResolutionError;
#[cfg(feature = "create-webvh")]
use pyo3::PyErr;

#[derive(thiserror::Error, Debug)]
pub enum VidError {
    #[cfg(feature = "resolve")]
    #[error("fetching '{0}' failed: {1}")]
    Http(String, reqwest::Error),
    #[cfg(feature = "resolve")]
    #[error("deserializing '{0}' failed: {1}")]
    Json(String, reqwest::Error),
    #[cfg(feature = "resolve")]
    #[error("(de)serializing '{0}")]
    Serde(#[from] serde_json::Error),
    #[error("connection to '{0}' failed: {1}")]
    Connection(String, std::io::Error),
    #[error("invalid VID '{0}'")]
    InvalidVid(String),
    #[error("could not resolve VID '{0}'")]
    ResolveVid(&'static str),
    #[error("{0}")]
    InternalError(String),
    #[error("{0}")]
    Verification(String),
    #[cfg(feature = "create-webvh")]
    #[error("error in the underlying Python code base: {0}")]
    Python(#[from] PyErr),
    #[error("invalid URL")]
    Url(#[from] url::ParseError),
}

#[cfg(not(target_arch = "wasm32"))]
impl From<ResolutionError> for VidError {
    fn from(err: ResolutionError) -> Self {
        match err {
            ResolutionError::NotFound => Self::ResolveVid("Not found"),
            ResolutionError::InvalidDID(s) => Self::InvalidVid(s),
            ResolutionError::MethodNotSupported => Self::ResolveVid("Method not supported"),
            ResolutionError::InternalError(s) => Self::InternalError(s),
            ResolutionError::InvalidDIDDocument(s) => Self::InvalidVid(s),
            ResolutionError::VerificationFailed(s) => Self::Verification(s),
        }
    }
}

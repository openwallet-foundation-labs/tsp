#[cfg(feature = "resolve")]
use didwebvh_rs::DIDWebVHError;

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
    #[error("invalid URL")]
    Url(#[from] url::ParseError),
    #[cfg(feature = "resolve")]
    #[error("WebVH DID resolution failed: {0}")]
    WebVHError(String),
}

#[cfg(feature = "resolve")]
// Convert WebVH Errors to VidError
impl From<DIDWebVHError> for VidError {
    fn from(err: DIDWebVHError) -> Self {
        match err {
            DIDWebVHError::NotFound => Self::ResolveVid("Not found"),
            DIDWebVHError::DIDError(s) => Self::InvalidVid(s),
            DIDWebVHError::InvalidMethodIdentifier(_) => Self::ResolveVid("Method not supported"),
            DIDWebVHError::UnsupportedMethod => Self::ResolveVid("Method not supported"),
            other => Self::WebVHError(other.to_string()),
        }
    }
}

#[cfg(feature = "resolve")]
use once_cell::sync::OnceCell;

#[cfg(feature = "resolve")]
#[derive(Debug)]
pub(crate) struct ReqwestClientError {
    pub(crate) context: &'static str,
    pub(crate) source: reqwest::Error,
}

#[cfg(feature = "resolve")]
pub(crate) fn reqwest_client() -> Result<&'static reqwest::Client, ReqwestClientError> {
    static CLIENT: OnceCell<reqwest::Client> = OnceCell::new();

    CLIENT.get_or_try_init(|| {
        let client = reqwest::Client::builder();

        #[cfg(feature = "use_local_certificate")]
        let client = {
            #[cfg(feature = "async")]
            tracing::warn!("Using local root CA! (should only be used for local testing)");

            let cert = reqwest::Certificate::from_pem(include_bytes!(
                "../../examples/test/root-ca.pem"
            ))
            .map_err(|e| ReqwestClientError {
                context: "Local root CA",
                source: e,
            })?;

            client.add_root_certificate(cert)
        };

        client.build().map_err(|e| ReqwestClientError {
            context: "Client build error",
            source: e,
        })
    })
}


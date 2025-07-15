use crate::{
    Vid,
    vid::{
        VidError,
        did::web::{DidDocument, resolve_document},
    },
};
#[cfg(feature = "create-webvh")]
pub use create_webvh::{create_webvh, update};
use didwebvh_resolver::{self, DefaultHttpClient, ResolutionOptions};
use serde::{Deserialize, Serialize};

pub(crate) const SCHEME: &str = "webvh";

#[derive(Debug, Serialize, Deserialize)]
pub struct WebvhMetadata {
    version_id: Option<String>,
    updated: Option<String>,
    pub update_keys: Option<Vec<String>>,
}
/// Returns the Vid and [`WebvhMetadata`] for the given `id`.
pub async fn resolve(id: &str) -> Result<(Vid, serde_json::Value), VidError> {
    let http = DefaultHttpClient::new();
    let resolver = didwebvh_resolver::resolver::WebVHResolver::new(http);
    let resolved = resolver.resolve(id, &ResolutionOptions::default()).await?;
    let metadata = WebvhMetadata {
        version_id: resolved.did_document_metadata.version_id,
        updated: resolved.did_document_metadata.updated,
        update_keys: resolved.did_document_metadata.update_keys,
    };
    let did_doc: DidDocument = serde_json::from_value(resolved.did_document)?;

    Ok((
        resolve_document(did_doc, id)?,
        serde_json::to_value(&metadata)?,
    ))
}

#[cfg(feature = "create-webvh")]
mod create_webvh {
    use crate::{
        OwnedVid,
        vid::{
            VidError,
            did::web::{DidDocument, resolve_document},
            vid_to_did_document,
        },
    };
    use pyo3::{ffi::c_str, prelude::*};
    use serde::Deserialize;
    use serde_pyobject::to_pyobject;
    use serde_with::serde_derive::Serialize;
    use url::Url;

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct HistoryEntry {
        version_id: String,
        version_time: String,
        parameters: serde_json::Value,
        pub state: DidDocument,
        proof: Vec<serde_json::Value>,
    }

    pub async fn create_webvh(
        did_name: &str,
        transport: Url,
    ) -> Result<(OwnedVid, serde_json::Value, String, Vec<u8>), VidError> {
        let tsp_mod = load_python()?;

        let placeholder =
            Python::with_gil(|py| -> String { placeholder_id(py, &tsp_mod, did_name) });

        let transport = transport
            .as_str()
            .replace("[vid_placeholder]", &placeholder.replace("%", "%25"));

        let mut vid = OwnedVid::bind(&placeholder, transport.parse()?);
        let genesis_document = vid_to_did_document(vid.vid());

        let (genesis_doc, update_kid, update_key) = Python::with_gil(|py| -> PyResult<_> {
            let (genesis_doc, update_kid, update_key) =
                provision(tsp_mod.bind(py), genesis_document)?;
            println!("{genesis_doc}");
            let genesis_doc: HistoryEntry =
                serde_json::from_str(&genesis_doc).expect("Invalid genesis doc");

            Ok((genesis_doc, update_kid, update_key))
        })?;

        let id = genesis_doc.state.id.clone();
        // TODO propper jsonl support.
        //  Currently, we just rely on the fact that serde_json will serialize it to a single line
        let history = serde_json::to_value(&genesis_doc).expect("Cannot serialize history");
        let new_vid = resolve_document(genesis_doc.state, &id)?;

        vid.vid = new_vid;

        Ok((vid, history, update_kid, update_key))
    }

    pub async fn update(
        updated_document: serde_json::Value,
        update_key: &[u8],
    ) -> Result<HistoryEntry, VidError> {
        let tsp_mod = load_python()?;

        let fut = Python::with_gil(|py| -> PyResult<_> {
            pyo3_async_runtimes::tokio::into_future(update_future(
                tsp_mod.bind(py),
                updated_document,
                update_key,
            )?)
        })?;

        let res = fut.await?;

        Ok(Python::with_gil(|py| -> PyResult<_> {
            let updated_history: String = res.extract(py)?;
            let updated_history =
                serde_json::from_str(&updated_history).expect("Invalid history entry");
            Ok(updated_history)
        })?)
    }

    fn update_future<'py>(
        tsp_mod: &Bound<'py, PyAny>,
        updated_document: serde_json::Value,
        update_key: &[u8],
    ) -> PyResult<Bound<'py, PyAny>> {
        tsp_mod.call_method1(
            "tsp_update_did",
            (to_pyobject(tsp_mod.py(), &updated_document)?, update_key),
        )
    }

    fn provision(
        tsp_mod: &Bound<PyAny>,
        genesis_document: serde_json::Value,
    ) -> PyResult<(String, String, Vec<u8>)> {
        tsp_mod
            .call_method1(
                "tsp_provision_did",
                (to_pyobject(tsp_mod.py(), &genesis_document)?,),
            )?
            .extract()
    }

    fn placeholder_id(py: Python, tsp_mod: &PyObject, domain: &str) -> String {
        let placeholder_id: String = tsp_mod
            .call_method1(py, "placeholder_id", (domain,))
            .expect("Cannot create placeholder ID")
            .extract(py)
            .expect("Cannot extract placeholder ID");
        placeholder_id
    }

    fn load_python() -> PyResult<PyObject> {
        Python::with_gil(|py| -> PyResult<PyObject> {
            Ok(PyModule::from_code(
                py,
                c_str!(include_str!("tsp_provision_webvh.py")),
                c_str!("tsp_provision_webvh.py"),
                c_str!("tsp_provision_webvh"),
            )?
            .into())
        })
    }
}

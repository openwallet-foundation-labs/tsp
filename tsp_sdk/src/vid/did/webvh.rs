use crate::Vid;
use crate::vid::VidError;
use crate::vid::did::web::{DidDocument, resolve_document};
#[cfg(feature = "create-webvh")]
pub use create_webvh::create_webvh;
use didwebvh_resolver;
use didwebvh_resolver::{DefaultHttpClient, ResolutionOptions};
use serde::Serialize;

pub(crate) const SCHEME: &str = "webvh";

#[derive(Debug, Serialize)]
struct WebvhMetadata {
    version_id: Option<String>,
    updated: Option<String>,
}

pub async fn resolve(id: &str) -> Result<(Vid, serde_json::Value), VidError> {
    let http = DefaultHttpClient::new();
    let resolver = didwebvh_resolver::resolver::WebVHResolver::new(http);
    let resolved = resolver.resolve(id, &ResolutionOptions::default()).await?;
    let metadata = WebvhMetadata {
        version_id: resolved.did_document_metadata.version_id,
        updated: resolved.did_document_metadata.updated,
    };
    let did_doc: DidDocument = serde_json::from_value(resolved.did_document)?;

    Ok((
        resolve_document(did_doc, id)?,
        serde_json::to_value(&metadata)?,
    ))
}

#[cfg(feature = "create-webvh")]
mod create_webvh {
    use crate::OwnedVid;
    use crate::vid::did::web::{DidDocument, resolve_document};
    use crate::vid::{VidError, vid_to_did_document};
    use pyo3::ffi::c_str;
    use pyo3::prelude::*;
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
        state: DidDocument,
        proof: Vec<serde_json::Value>,
    }

    pub async fn create_webvh(
        did_server: &str,
        transport: Url,
        name: &str,
    ) -> Result<(OwnedVid, serde_json::Value), VidError> {
        let tsp_mod = load_python()?;

        let placeholder = Python::with_gil(|py| -> String {
            placeholder_id(py, &tsp_mod, &format!("{did_server}/endpoint/{name}"))
        });

        let transport = transport
            .as_str()
            .replace("[vid_placeholder]", &placeholder.replace("%", "%25"));

        let mut vid = OwnedVid::bind(&placeholder, transport.parse()?);
        let genesis_document = vid_to_did_document(vid.vid());

        let fut = Python::with_gil(|py| -> PyResult<_> {
            pyo3_async_runtimes::tokio::into_future(provision(tsp_mod.bind(py), genesis_document)?)
        })?;

        let res = fut.await?;

        let genesis_doc = Python::with_gil(|py| -> PyResult<_> {
            let genesis_doc: String = res.extract(py)?;
            // TODO handle jsonl correctly
            let genesis_doc: HistoryEntry =
                serde_json::from_str(&genesis_doc).expect("Invalid genesis doc");

            Ok(genesis_doc)
        })?;

        let id = genesis_doc.state.id.clone();
        // TODO propper jsonl support.
        //  Currently, we just rely on the fact that serde_json will serialize it to a single line
        let history = serde_json::to_value(&genesis_doc).expect("Cannot serialize history");
        let new_vid = resolve_document(genesis_doc.state, &id)?;

        vid.vid = new_vid;

        Ok((vid, history))
    }

    fn provision<'py>(
        tsp_mod: &Bound<'py, PyAny>,
        genesis_document: serde_json::Value,
    ) -> PyResult<Bound<'py, PyAny>> {
        tsp_mod.call_method1(
            "tsp_provision_did",
            (to_pyobject(tsp_mod.py(), &genesis_document)?,),
        )
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
                    c_str!(
                        r#"
from pathlib import Path

import aries_askar
from did_webvh.askar import AskarSigningKey
from did_webvh.const import (
    ASKAR_STORE_FILENAME,
    HISTORY_FILENAME,
    METHOD_NAME,
)
from did_webvh.domain_path import DomainPath
from did_webvh.history import load_local_history, write_document_state
from did_webvh.provision import provision_did

def placeholder_id(domain_path: str) -> str:
    pathinfo = DomainPath.parse_normalized(domain_path)
    return f"did:{METHOD_NAME}:{pathinfo.identifier}"
    

async def tsp_provision_did(genesis_document: dict) -> str:
    pass_key = "unsecure"

    update_key = AskarSigningKey.generate("ed25519")

    # the SCID in the transport does get percent encoded in Rust, but we need the original value to make the {SCID} replacement work.
    genesis_document['service'][0]['serviceEndpoint'] = genesis_document['service'][0]['serviceEndpoint'].replace('%7B', '{').replace('%7D', '}')

    params = dict(updateKeys=[update_key.multikey])
    state = provision_did(genesis_document, params=params, hash_name="sha2-256")
    doc_dir = Path(f"{state.scid}")
    doc_dir.mkdir(exist_ok=True)

    store = await aries_askar.Store.provision(
        f"sqlite://{doc_dir}/{ASKAR_STORE_FILENAME}", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(update_key.kid, update_key.key)
    await store.close()

    state.proofs.append(
        state.create_proof(
            update_key,
            timestamp=state.timestamp,
        )
    )
    write_document_state(doc_dir, state)

    # verify log
    await load_local_history(doc_dir.joinpath(HISTORY_FILENAME), verify_proofs=True)

    return state.history_json()
                            "#
                    ),
                    c_str!("tsp_provision_did.py"),
                    c_str!("tsp_provision_did"),
                )?
                    .into())
        })
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[pyo3_async_runtimes::tokio::main]
        #[test]
        async fn main() -> Result<(), PyErr> {
            create_webvh(
                "demo.teaspoon.world",
                "https://demo.teaspoon.world/endpoint/[vid_placeholder]"
                    .parse()
                    .unwrap(),
                "foo",
            )
            .await
            .unwrap();

            Ok(())
        }
    }
}

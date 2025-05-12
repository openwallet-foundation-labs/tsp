use crate::vid::did::web::{resolve_document, DidDocument};
use crate::vid::VidError;
use crate::Vid;
use didwebvh_resolver;
use didwebvh_resolver::{DefaultHttpClient, ResolutionOptions};

pub(crate) const SCHEME: &str = "webvh";

pub async fn resolve(id: &str) -> Result<Vid, VidError> {
    let http = DefaultHttpClient::new();
    let resolver = didwebvh_resolver::resolver::WebVHResolver::new(http);
    let resolved = resolver.resolve(id, &ResolutionOptions::default()).await?;

    let did_doc: DidDocument = serde_json::from_value(resolved.did_document)?;

    resolve_document(did_doc, id)
}

#[cfg(feature = "create-webvh")]
mod create_webvh {
    use pyo3::ffi::c_str;
    use crate::OwnedVid;
    use pyo3::prelude::*;
    use pyo3::py_run;
    use pyo3::types::PyList;

    pub async fn create_did_webvh(
        path: &str,
        domain: &str,
        transport: &str,
    ) -> (serde_json::Value, serde_json::Value, OwnedVid) {
        todo!()
    }

    pub fn load_python(py: Python<'_>) -> PyResult<Bound<PyAny>> {
            let tsp_did = PyModule::from_code(
                py,
                c_str!(
                    r#"
import argparse
import asyncio
import base64
import json
import re
from copy import deepcopy
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Optional, Union

import aries_askar
import jsoncanon

from did_webvh.askar import AskarSigningKey
from did_webvh.const import (
    ASKAR_STORE_FILENAME,
    DOCUMENT_FILENAME,
    HISTORY_FILENAME,
    METHOD_NAME,
    METHOD_VERSION,
)
from did_webvh.core.hash_utils import DEFAULT_HASH, HashInfo
from did_webvh.core.proof import VerifyingKey
from did_webvh.core.state import DocumentState
from did_webvh.domain_path import DomainPath
from did_webvh.history import load_local_history, write_document_state
from did_webvh.provision import genesis_document, provision_did
import did_webvh

async def tsp_provision_did(domain_path):
    pass_key = "password"

    pathinfo = DomainPath.parse_normalized(domain_path)
    update_key = AskarSigningKey.generate("ed25519")
    placeholder_id = f"did:{METHOD_NAME}:{pathinfo.identifier}"
    print(placeholder_id)
    genesis = genesis_document(placeholder_id)

    state = provision_did(genesis, hash_name="sha2-256")
    doc_dir = Path(f"{pathinfo.domain}_{state.scid}")
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
    # TODO verify proofs
    await load_local_history(doc_dir.joinpath(HISTORY_FILENAME), verify_proofs=False)
                        "#
                ),
                c_str!("tsp_provision_did.py"),
                c_str!("tsp_provision_did"),
            )?;

            tsp_did.call_method1("tsp_provision_did", ("test.domain",))
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[pyo3_async_runtimes::tokio::main]
        #[test]
        async fn main() -> PyResult<()> {
            // PyO3 is initialized - Ready to go

            let fut = Python::with_gil(|py| -> PyResult<_> {
                
                // convert asyncio.run into a Rust Future
                pyo3_async_runtimes::tokio::into_future(
                    load_python(py)?
                )
            })?;

            fut.await?;

            Ok(())
        }
    }
}

use std::future::Future;

use pyo3::{exceptions::PyException, prelude::*};

fn tokio() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap())
}

fn py_exception<E: std::fmt::Debug>(e: E) -> PyErr {
    PyException::new_err(format!("{e:?}"))
}

#[pyclass]
struct AsyncStore(tsp::Store);

async fn spawn<F>(fut: F) -> PyResult<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio().spawn(fut).await.map_err(py_exception)
}

#[pymethods]
impl AsyncStore {
    #[new]
    fn new() -> Self {
        Self(tsp::Store::default())
    }

    fn add_private_vid(&self, vid: OwnedVid) -> PyResult<()> {
        self.0.add_private_vid(vid.0).unwrap();
        Ok(())
    }

    async fn verify_vid(&mut self, vid: String) -> PyResult<()> {
        let verified_vid = spawn(async move { tsp::vid::verify_vid(&vid).await })
            .await?
            .map_err(py_exception)?;

        self.0.add_verified_vid(verified_vid).map_err(py_exception)
    }

    #[pyo3(signature = (sender, receiver, nonconfidential_data, message))]
    async fn send(
        &self,
        sender: String,
        receiver: String,
        nonconfidential_data: Option<Vec<u8>>,
        message: Vec<u8>,
    ) -> PyResult<Vec<u8>> {
        let (url, bytes) = self
            .0
            .seal_message(
                &sender,
                &receiver,
                nonconfidential_data.as_deref(),
                &message,
            )
            .map_err(py_exception)?;

        let fut = async move {
            tsp::transport::send_message(&url, &bytes).await?;
            Ok::<Vec<_>, tsp::transport::TransportError>(bytes)
        };

        spawn(fut).await?.map_err(py_exception)
    }
}

#[pyclass]
#[derive(Clone)]
struct OwnedVid(tsp::OwnedVid);

#[pymethods]
impl OwnedVid {
    #[staticmethod]
    async fn from_file(path: String) -> PyResult<OwnedVid> {
        let fut = async move {
            let owned_vid = tsp::OwnedVid::from_file(&path)
                .await
                .map_err(py_exception)?;
            Ok(Self(owned_vid))
        };

        tokio().spawn(fut).await.unwrap()
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn tsp_python(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AsyncStore>()?;
    m.add_class::<OwnedVid>()?;

    Ok(())
}

use std::future::Future;

use async_stream::stream;
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

    /// Send TSP broadcast message to the specified VIDs
    pub async fn send_anycast(
        &self,
        sender: String,
        receivers: Vec<String>,
        nonconfidential_message: Vec<u8>,
    ) -> PyResult<()> {
        let message = self
            .0
            .sign_anycast(&sender, &nonconfidential_message)
            .unwrap();

        let inner = self.0.clone();

        let fut = async move {
            for vid in receivers {
                let receiver = inner.get_verified_vid(vid.as_ref()).unwrap();

                tsp::transport::send_message(receiver.endpoint(), &message)
                    .await
                    .unwrap();
            }
        };

        spawn(fut).await
    }

    pub async fn receive(&self, vid: String) -> PyResult<ReceivedTspMessageStream> {
        let receiver = self.0.get_private_vid(&vid).map_err(py_exception)?;
        let messages =
            spawn(async move { tsp::transport::receive_messages(receiver.endpoint()).await })
                .await?
                .map_err(py_exception)?;

        //        Ok(ReceivedTspMessageStream(Box::pin(stream! {
        //                    yield Ok(tsp::ReceivedTspMessage::AcceptRelationship {
        //            sender: String::from("foobarbaz"),
        //        },
        //                             );
        //            })))

        use futures::StreamExt;
        let db = self.0.clone();
        Ok(ReceivedTspMessageStream(Box::pin(messages.then(
            move |message| {
                let db_inner = db.clone();
                async move {
                    match message {
                        Ok(mut m) => match db_inner.open_message(&mut m) {
                            Err(tsp::Error::UnverifiedSource(unknown_vid)) => {
                                Ok(tsp::ReceivedTspMessage::PendingMessage {
                                    unknown_vid,
                                    payload: m.to_vec(),
                                })
                            }
                            maybe_message => maybe_message,
                        },
                        Err(e) => Err(e.into()),
                    }
                }
            },
        ))))
    }

    //    pub async fn receive(&self, vid: &str) -> Result<TSPStream<ReceivedTspMessage, Error>, Error> {
    //        let receiver = self.inner.get_private_vid(vid)?;
    //        let messages = crate::transport::receive_messages(receiver.endpoint()).await?;
    //
    //        let db = self.inner.clone();
    //        Ok(Box::pin(messages.then(move |message| {
    //            let db_inner = db.clone();
    //            async move {
    //                match message {
    //                    Ok(mut m) => match db_inner.open_message(&mut m) {
    //                        Err(Error::UnverifiedSource(unknown_vid)) => {
    //                            Ok(ReceivedTspMessage::PendingMessage {
    //                                unknown_vid,
    //                                payload: m.to_vec(),
    //                            })
    //                        }
    //                        maybe_message => maybe_message,
    //                    },
    //                    Err(e) => Err(e.into()),
    //                }
    //            }
    //        })))
    //    }
}

#[pyclass]
struct ReceivedTspMessageStream(tsp::definitions::TSPStream<tsp::ReceivedTspMessage, tsp::Error>);

#[pyclass]
#[derive(Clone, Copy)]
enum ReceivedTspMessageVariant {
    GenericMessage,
    RequestRelationship,
    AcceptRelationship,
    CancelRelationship,
    ForwardRequest,
    PendingMessage,
}

impl From<&tsp::ReceivedTspMessage> for ReceivedTspMessageVariant {
    fn from(value: &tsp::ReceivedTspMessage) -> Self {
        match value {
            tsp::ReceivedTspMessage::GenericMessage { .. } => Self::GenericMessage,
            tsp::ReceivedTspMessage::RequestRelationship { .. } => Self::RequestRelationship,
            tsp::ReceivedTspMessage::AcceptRelationship { .. } => Self::AcceptRelationship,
            tsp::ReceivedTspMessage::CancelRelationship { .. } => Self::CancelRelationship,
            tsp::ReceivedTspMessage::ForwardRequest { .. } => Self::ForwardRequest,
            tsp::ReceivedTspMessage::PendingMessage { .. } => Self::PendingMessage,
        }
    }
}

#[pyclass]
#[derive(Clone, Copy)]
enum MessageType {
    Signed,
    SignedAndEncrypted,
}

#[pyclass]
struct FlatReceivedTspMessage {
    #[pyo3(get, set)]
    variant: ReceivedTspMessageVariant,
    #[pyo3(get, set)]
    sender: Option<String>,
    #[pyo3(get, set)]
    nonconfidential_data: Option<Option<Vec<u8>>>,
    #[pyo3(get, set)]
    message: Option<Vec<u8>>,
    #[pyo3(get, set)]
    message_type: Option<MessageType>,
    #[pyo3(get, set)]
    route: Option<Option<Vec<Vec<u8>>>>,
    #[pyo3(get, set)]
    thread_id: Option<[u8; 32]>,
    #[pyo3(get, set)]
    next_hop: Option<String>,
    #[pyo3(get, set)]
    payload: Option<Vec<u8>>,
    #[pyo3(get, set)]
    opaque_payload: Option<Vec<u8>>,
    #[pyo3(get, set)]
    unknown_vid: Option<String>,
}

impl From<tsp::ReceivedTspMessage> for FlatReceivedTspMessage {
    fn from(value: tsp::ReceivedTspMessage) -> Self {
        let variant = ReceivedTspMessageVariant::from(&value);

        let mut this = FlatReceivedTspMessage {
            variant,
            sender: None,
            nonconfidential_data: None,
            message: None,
            message_type: None,
            route: None,
            thread_id: None,
            next_hop: None,
            payload: None,
            opaque_payload: None,
            unknown_vid: None,
        };

        match value {
            tsp::ReceivedTspMessage::GenericMessage {
                sender,
                nonconfidential_data,
                message,
                message_type,
            } => {
                this.sender = Some(sender);
                this.nonconfidential_data = Some(nonconfidential_data);
                this.message = Some(message);
                this.message_type = match message_type {
                    tsp::definitions::MessageType::Signed => Some(MessageType::Signed),
                    tsp::definitions::MessageType::SignedAndEncrypted => {
                        Some(MessageType::SignedAndEncrypted)
                    }
                };
            }
            tsp::ReceivedTspMessage::RequestRelationship {
                sender,
                route,
                thread_id,
            } => {
                this.sender = Some(sender);
                this.route = Some(route);
                this.thread_id = Some(thread_id);
            }
            tsp::ReceivedTspMessage::AcceptRelationship { sender } => {
                this.sender = Some(sender);
            }
            tsp::ReceivedTspMessage::CancelRelationship { sender } => {
                this.sender = Some(sender);
            }
            tsp::ReceivedTspMessage::ForwardRequest {
                sender,
                next_hop,
                route,
                opaque_payload,
            } => {
                this.sender = Some(sender);
                this.next_hop = Some(next_hop);
                this.route = Some(Some(route));
                this.opaque_payload = Some(opaque_payload);
            }
            tsp::ReceivedTspMessage::PendingMessage {
                unknown_vid,
                payload,
            } => {
                this.unknown_vid = Some(unknown_vid);
                this.payload = Some(payload);
            }
        };

        this
    }
}

#[pymethods]
impl ReceivedTspMessageStream {
    async fn next(&mut self) -> PyResult<Option<FlatReceivedTspMessage>> {
        use futures::prelude::*;

        match self.0.next().await {
            None => Ok(None),
            Some(Ok(value)) => Ok(Some(value.into())),
            Some(Err(e)) => Err(py_exception(e)),
        }
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

    m.add_class::<ReceivedTspMessageVariant>()?;
    m.add_class::<FlatReceivedTspMessage>()?;

    Ok(())
}

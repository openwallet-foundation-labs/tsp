use pyo3::{exceptions::PyException, prelude::*};

#[pymodule]
fn tsp_python(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Store>()?;
    m.add_class::<OwnedVid>()?;

    m.add_class::<CryptoType>()?;
    m.add_class::<SignatureType>()?;
    m.add_class::<ReceivedTspMessageVariant>()?;
    m.add_class::<FlatReceivedTspMessage>()?;

    Ok(())
}

fn py_exception<E: std::fmt::Debug>(e: E) -> PyErr {
    PyException::new_err(format!("{e:?}"))
}

#[pyclass]
struct Store(tsp::Store);

#[pymethods]
impl Store {
    #[new]
    fn new() -> Self {
        Self(tsp::Store::default())
    }

    fn add_private_vid(&self, vid: OwnedVid) -> PyResult<()> {
        self.0.add_private_vid(vid.0).map_err(py_exception)
    }

    fn add_verified_vid(&self, vid: OwnedVid) -> PyResult<()> {
        self.0.add_verified_vid(vid.0).map_err(py_exception)
    }

    fn set_relation_for_vid(&self, vid: String, relation_vid: Option<String>) -> PyResult<()> {
        self.0
            .set_relation_for_vid(&vid, relation_vid.as_deref())
            .map_err(py_exception)
    }

    fn set_route_for_vid(&self, vid: String, route: Vec<String>) -> PyResult<()> {
        let borrowed: Vec<_> = route.iter().map(|s| s.as_str()).collect();
        self.0
            .set_route_for_vid(&vid, &borrowed)
            .map_err(py_exception)
    }

    #[pyo3(signature = (sender, receiver, nonconfidential_data, message))]
    fn seal_message(
        &self,
        sender: String,
        receiver: String,
        nonconfidential_data: Option<Vec<u8>>,
        message: Vec<u8>,
    ) -> PyResult<(String, Vec<u8>)> {
        let (url, bytes) = self
            .0
            .seal_message(
                &sender,
                &receiver,
                nonconfidential_data.as_deref(),
                &message,
            )
            .map_err(py_exception)?;

        Ok((url.to_string(), bytes))
    }

    #[pyo3(signature = (sender, receiver, route))]
    fn make_relationship_request(
        &self,
        sender: String,
        receiver: String,
        route: Option<Vec<String>>,
    ) -> PyResult<(String, Vec<u8>)> {
        let route_items: Vec<&str> = route.iter().flatten().map(|s| s.as_str()).collect();

        let (url, bytes) = self
            .0
            .make_relationship_request(
                &sender,
                &receiver,
                route.as_ref().map(|_| route_items.as_slice()),
            )
            .map_err(py_exception)?;

        Ok((url.to_string(), bytes))
    }

    #[pyo3(signature = (sender, receiver, thread_id, route))]
    fn make_relationship_accept(
        &self,
        sender: String,
        receiver: String,
        thread_id: [u8; 32],
        route: Option<Vec<String>>,
    ) -> PyResult<(String, Vec<u8>)> {
        let route_items: Vec<&str> = route.iter().flatten().map(|s| s.as_str()).collect();

        let (url, bytes) = self
            .0
            .make_relationship_accept(
                &sender,
                &receiver,
                thread_id,
                route.as_ref().map(|_| route_items.as_slice()),
            )
            .map_err(py_exception)?;

        Ok((url.to_string(), bytes))
    }

    #[pyo3(signature = (sender, receiver))]
    fn make_relationship_cancel(
        &self,
        sender: String,
        receiver: String,
    ) -> PyResult<(String, Vec<u8>)> {
        let (url, bytes) = self
            .0
            .make_relationship_cancel(&sender, &receiver)
            .map_err(py_exception)?;

        Ok((url.to_string(), bytes))
    }

    #[pyo3(signature = (sender, receiver, sender_new_vid))]
    fn make_new_identifier_notice(
        &self,
        sender: String,
        receiver: String,
        sender_new_vid: String,
    ) -> PyResult<(String, Vec<u8>)> {
        let (url, bytes) = self
            .0
            .make_new_identifier_notice(&sender, &receiver, &sender_new_vid)
            .map_err(py_exception)?;

        Ok((url.to_string(), bytes))
    }

    #[pyo3(signature = (sender, receiver, referred_vid))]
    fn make_relationship_referral(
        &self,
        sender: String,
        receiver: String,
        referred_vid: String,
    ) -> PyResult<(String, Vec<u8>)> {
        let (url, bytes) = self
            .0
            .make_relationship_referral(&sender, &receiver, &referred_vid)
            .map_err(py_exception)?;

        Ok((url.to_string(), bytes))
    }

    fn make_nested_relationship_request(
        &self,
        parent_sender: String,
        receiver: String,
    ) -> PyResult<((String, Vec<u8>), OwnedVid)> {
        let ((url, bytes), vid) = self
            .0
            .make_nested_relationship_request(&parent_sender, &receiver)
            .map_err(py_exception)?;

        Ok(((url.to_string(), bytes), OwnedVid(vid)))
    }

    fn make_nested_relationship_accept(
        &self,
        sender: String,
        receiver: String,
        thread_id: [u8; 32],
    ) -> PyResult<((String, Vec<u8>), OwnedVid)> {
        let ((url, bytes), vid) = self
            .0
            .make_nested_relationship_accept(&sender, &receiver, thread_id)
            .map_err(py_exception)?;

        Ok(((url.to_string(), bytes), OwnedVid(vid)))
    }

    fn forward_routed_message(
        &self,
        next_hop: String,
        route: Vec<Vec<u8>>,
        opaque_payload: Vec<u8>,
    ) -> PyResult<(String, Vec<u8>)> {
        let borrowed_route: Vec<_> = route.iter().map(|v| v.as_slice()).collect();
        let (url, bytes) = self
            .0
            .forward_routed_message(&next_hop, borrowed_route, &opaque_payload)
            .map_err(py_exception)?;

        Ok((url.to_string(), bytes))
    }

    fn open_message(&self, mut message: Vec<u8>) -> PyResult<FlatReceivedTspMessage> {
        self.0
            .open_message(&mut message)
            .map(|msg| msg.into_owned())
            .map(FlatReceivedTspMessage::from)
            .map_err(py_exception)
    }
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
enum ReceivedTspMessageVariant {
    GenericMessage,
    RequestRelationship,
    AcceptRelationship,
    CancelRelationship,
    ForwardRequest,
    PendingMessage,
    NewIdentifier,
    Referral,
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
            tsp::ReceivedTspMessage::NewIdentifier { .. } => Self::NewIdentifier,
            tsp::ReceivedTspMessage::Referral { .. } => Self::Referral,
        }
    }
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub enum CryptoType {
    Plaintext = 0,
    HpkeAuth = 1,
    HpkeEssr = 2,
    NaclAuth = 3,
    NaclEssr = 4,
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub enum SignatureType {
    NoSignature = 0,
    Ed25519 = 1,
}

#[pyclass]
#[derive(Debug)]
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
    crypto_type: Option<CryptoType>,
    #[pyo3(get, set)]
    signature_type: Option<SignatureType>,
    #[pyo3(get, set)]
    route: Option<Option<Vec<Vec<u8>>>>,
    #[pyo3(get, set)]
    nested_vid: Option<Option<String>>,
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
    #[pyo3(get, set)]
    new_vid: Option<String>,
    #[pyo3(get, set)]
    referred_vid: Option<String>,
}

#[pymethods]
impl FlatReceivedTspMessage {
    fn __repr__(&self) -> String {
        format!("{self:?}")
    }
}

impl From<tsp::ReceivedTspMessage> for FlatReceivedTspMessage {
    fn from(value: tsp::ReceivedTspMessage) -> Self {
        let variant = ReceivedTspMessageVariant::from(&value);

        let mut this = FlatReceivedTspMessage {
            variant,
            sender: None,
            nonconfidential_data: None,
            message: None,
            crypto_type: None,
            signature_type: None,
            route: None,
            nested_vid: None,
            thread_id: None,
            next_hop: None,
            payload: None,
            opaque_payload: None,
            unknown_vid: None,
            new_vid: None,
            referred_vid: None,
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
                this.crypto_type = match message_type.crypto_type {
                    tsp::cesr::CryptoType::Plaintext => Some(CryptoType::Plaintext),
                    tsp::cesr::CryptoType::HpkeAuth => Some(CryptoType::HpkeAuth),
                    tsp::cesr::CryptoType::HpkeEssr => Some(CryptoType::HpkeEssr),
                    tsp::cesr::CryptoType::NaclAuth => Some(CryptoType::NaclAuth),
                    tsp::cesr::CryptoType::NaclEssr => Some(CryptoType::NaclEssr),
                };
                this.signature_type = match message_type.signature_type {
                    tsp::cesr::SignatureType::NoSignature => Some(SignatureType::NoSignature),
                    tsp::cesr::SignatureType::Ed25519 => Some(SignatureType::Ed25519),
                };
            }
            tsp::ReceivedTspMessage::RequestRelationship {
                sender,
                route,
                nested_vid,
                thread_id,
            } => {
                this.sender = Some(sender);
                this.route = Some(route);
                this.nested_vid = Some(nested_vid);
                this.thread_id = Some(thread_id);
            }
            tsp::ReceivedTspMessage::AcceptRelationship { sender, nested_vid } => {
                this.sender = Some(sender);
                this.nested_vid = Some(nested_vid);
            }
            tsp::ReceivedTspMessage::CancelRelationship { sender } => {
                this.sender = Some(sender);
            }
            tsp::ReceivedTspMessage::NewIdentifier { sender, new_vid } => {
                this.sender = Some(sender);
                this.new_vid = Some(new_vid);
            }
            tsp::ReceivedTspMessage::Referral {
                sender,
                referred_vid,
            } => {
                this.sender = Some(sender);
                this.referred_vid = Some(referred_vid);
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

#[pyclass]
#[derive(Clone)]
struct OwnedVid(tsp::OwnedVid);

#[pymethods]
impl OwnedVid {
    #[staticmethod]
    fn new_did_peer(url: String) -> Self {
        OwnedVid(tsp::OwnedVid::new_did_peer(url.parse().unwrap()))
    }

    fn identifier(&self) -> String {
        use tsp::VerifiedVid;
        self.0.identifier().to_string()
    }
}

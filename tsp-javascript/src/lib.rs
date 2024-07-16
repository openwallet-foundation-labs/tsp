use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

pub struct Error(tsp::Error);

impl From<Error> for JsValue {
    fn from(e: Error) -> Self {
        JsValue::from_str(&format!("{:?}", e.0))
    }
}

#[derive(Default, Clone)]
#[wasm_bindgen]
pub struct Store(tsp::Store);

#[wasm_bindgen]
pub struct SealedMessage {
    #[wasm_bindgen(getter_with_clone)]
    pub url: String,
    #[wasm_bindgen(getter_with_clone)]
    pub sealed: Vec<u8>,
}

#[wasm_bindgen]
pub struct NestedSealedMessage {
    #[wasm_bindgen(getter_with_clone)]
    pub url: String,
    #[wasm_bindgen(getter_with_clone)]
    pub sealed: Vec<u8>,
    #[wasm_bindgen(getter_with_clone)]
    pub nested_vid: OwnedVid,
}

#[wasm_bindgen]
impl Store {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen]
    pub fn add_private_vid(&self, vid: &OwnedVid) -> Result<(), Error> {
        self.0.add_private_vid(vid.0.clone()).map_err(Error)
    }

    #[wasm_bindgen]
    pub fn add_verified_vid(&self, vid: &OwnedVid) -> Result<(), Error> {
        self.0.add_verified_vid(vid.0.clone()).map_err(Error)
    }

    #[wasm_bindgen]
    pub fn set_relation_for_vid(
        &self,
        vid: String,
        relation_vid: Option<String>,
    ) -> Result<(), Error> {
        self.0
            .set_relation_for_vid(&vid, relation_vid.as_deref())
            .map_err(Error)
    }

    #[wasm_bindgen]
    pub fn set_route_for_vid(&self, vid: String, route: Vec<String>) -> Result<(), Error> {
        let borrowed: Vec<_> = route.iter().map(|s| s.as_str()).collect();
        self.0.set_route_for_vid(&vid, &borrowed).map_err(Error)
    }

    #[wasm_bindgen]
    pub fn seal_message(
        &self,
        sender: String,
        receiver: String,
        nonconfidential_data: Option<Vec<u8>>,
        message: Vec<u8>,
    ) -> Result<SealedMessage, Error> {
        let (url, sealed) = self
            .0
            .seal_message(
                &sender,
                &receiver,
                nonconfidential_data.as_deref(),
                &message,
            )
            .map_err(Error)?;

        Ok(SealedMessage {
            url: url.to_string(),
            sealed,
        })
    }

    #[wasm_bindgen]
    pub fn open_message(&self, mut message: Vec<u8>) -> Result<FlatReceivedTspMessage, Error> {
        self.0
            .open_message(&mut message)
            .map(FlatReceivedTspMessage::from)
            .map_err(Error)
    }

    #[wasm_bindgen]
    pub fn make_relationship_request(
        &self,
        sender: String,
        receiver: String,
        route: Option<Vec<String>>,
    ) -> Result<SealedMessage, Error> {
        let route_items: Vec<&str> = route.iter().flatten().map(|s| s.as_str()).collect();

        let (url, sealed) = self
            .0
            .make_relationship_request(
                &sender,
                &receiver,
                route.as_ref().map(|_| route_items.as_slice()),
            )
            .map_err(Error)?;

        Ok(SealedMessage {
            url: url.to_string(),
            sealed,
        })
    }

    #[wasm_bindgen]
    pub fn make_relationship_accept(
        &self,
        sender: String,
        receiver: String,
        thread_id: Vec<u8>,
        route: Option<Vec<String>>,
    ) -> Result<SealedMessage, Error> {
        let route_items: Vec<&str> = route.iter().flatten().map(|s| s.as_str()).collect();

        let (url, sealed) = self
            .0
            .make_relationship_accept(
                &sender,
                &receiver,
                thread_id.try_into().unwrap(),
                route.as_ref().map(|_| route_items.as_slice()),
            )
            .map_err(Error)?;

        Ok(SealedMessage {
            url: url.to_string(),
            sealed,
        })
    }

    #[wasm_bindgen]
    pub fn make_relationship_cancel(
        &self,
        sender: String,
        receiver: String,
    ) -> Result<SealedMessage, Error> {
        let (url, sealed) = self
            .0
            .make_relationship_cancel(&sender, &receiver)
            .map_err(Error)?;

        Ok(SealedMessage {
            url: url.to_string(),
            sealed,
        })
    }

    #[wasm_bindgen]
    pub fn make_relationship_referral(
        &self,
        sender: String,
        receiver: String,
        referred_vid: String,
    ) -> Result<SealedMessage, Error> {
        let (url, sealed) = self
            .0
            .make_relationship_referral(&sender, &receiver, &referred_vid)
            .map_err(Error)?;

        Ok(SealedMessage {
            url: url.to_string(),
            sealed,
        })
    }

    #[wasm_bindgen]
    pub fn make_nested_relationship_request(
        &self,
        parent_sender: String,
        receiver: String,
    ) -> Result<NestedSealedMessage, Error> {
        let ((url, sealed), vid) = self
            .0
            .make_nested_relationship_request(&parent_sender, &receiver)
            .map_err(Error)?;

        Ok(NestedSealedMessage {
            url: url.to_string(),
            sealed,
            nested_vid: OwnedVid(vid),
        })
    }

    #[wasm_bindgen]
    pub fn make_nested_relationship_accept(
        &self,
        sender: String,
        receiver: String,
        thread_id: Vec<u8>,
    ) -> Result<NestedSealedMessage, Error> {
        let ((url, sealed), vid) = self
            .0
            .make_nested_relationship_accept(&sender, &receiver, thread_id.try_into().unwrap())
            .map_err(Error)?;

        Ok(NestedSealedMessage {
            url: url.to_string(),
            sealed,
            nested_vid: OwnedVid(vid),
        })
    }

    #[wasm_bindgen]
    pub fn forward_routed_message(
        &self,
        next_hop: String,
        route: JsValue,
        opaque_payload: Vec<u8>,
    ) -> Result<SealedMessage, Error> {
        let route = convert(route).unwrap();
        let borrowed_route: Vec<_> = route.iter().map(|v| v.as_slice()).collect();
        let (url, sealed) = self
            .0
            .forward_routed_message(&next_hop, borrowed_route, &opaque_payload)
            .map_err(Error)?;

        Ok(SealedMessage {
            url: url.to_string(),
            sealed,
        })
    }
}

fn convert(value: JsValue) -> Result<Vec<Vec<u8>>, serde_wasm_bindgen::Error> {
    match serde_wasm_bindgen::from_value(value.clone()) {
        Ok(x) => Ok(x),
        Err(_) => {
            let x: Vec<String> = serde_wasm_bindgen::from_value(value)?;
            Ok(x.into_iter().map(Vec::from).collect())
        }
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct OwnedVid(tsp::OwnedVid);

#[wasm_bindgen]
impl OwnedVid {
    #[wasm_bindgen]
    pub fn new_did_peer(url: String) -> Self {
        OwnedVid(tsp::OwnedVid::new_did_peer(url.parse().unwrap()))
    }

    #[wasm_bindgen]
    pub fn identifier(&self) -> String {
        use tsp::VerifiedVid;
        self.0.identifier().to_string()
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ReceivedTspMessageVariant {
    GenericMessage = 0,
    RequestRelationship = 1,
    AcceptRelationship = 2,
    CancelRelationship = 3,
    ForwardRequest = 4,
    NewIdentifier = 5,
    Referral = 6,
}

impl From<&tsp::ReceivedTspMessage> for ReceivedTspMessageVariant {
    fn from(value: &tsp::ReceivedTspMessage) -> Self {
        match value {
            tsp::ReceivedTspMessage::GenericMessage { .. } => Self::GenericMessage,
            tsp::ReceivedTspMessage::RequestRelationship { .. } => Self::RequestRelationship,
            tsp::ReceivedTspMessage::AcceptRelationship { .. } => Self::AcceptRelationship,
            tsp::ReceivedTspMessage::CancelRelationship { .. } => Self::CancelRelationship,
            tsp::ReceivedTspMessage::ForwardRequest { .. } => Self::ForwardRequest,
            tsp::ReceivedTspMessage::NewIdentifier { .. } => Self::NewIdentifier,
            tsp::ReceivedTspMessage::Referral { .. } => Self::Referral,
            #[cfg(not(target_arch = "wasm32"))]
            tsp::ReceivedTspMessage::PendingMessage { .. } => unreachable!(),
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MessageType {
    Signed,
    SignedAndEncrypted,
}

#[wasm_bindgen(inspectable)]
#[derive(Debug, Serialize, Deserialize)]
pub struct FlatReceivedTspMessage {
    pub variant: ReceivedTspMessageVariant,
    sender: Option<String>,
    nonconfidential_data: Option<Option<Vec<u8>>>,
    message: Option<Vec<u8>>,
    pub message_type: Option<MessageType>,
    route: Option<Option<Vec<Vec<u8>>>>,
    nested_vid: Option<Option<String>>,
    thread_id: Option<Vec<u8>>,
    next_hop: Option<String>,
    payload: Option<Vec<u8>>,
    opaque_payload: Option<Vec<u8>>,
    unknown_vid: Option<String>,
    referred_vid: Option<String>,
    new_vid: Option<String>,
}

#[wasm_bindgen]
impl FlatReceivedTspMessage {
    #[wasm_bindgen(getter)]
    pub fn sender(&self) -> Option<String> {
        self.sender.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nonconfidential_data(&self) -> JsValue {
        match &self.nonconfidential_data {
            Some(Some(data)) => serde_wasm_bindgen::to_value(data).unwrap(),
            _ => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn message(&self) -> JsValue {
        match &self.message {
            Some(data) => serde_wasm_bindgen::to_value(data).unwrap(),
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn route(&self) -> JsValue {
        match &self.route {
            Some(Some(routes)) => serde_wasm_bindgen::to_value(routes).unwrap(),
            _ => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn nested_vid(&self) -> JsValue {
        match &self.nested_vid {
            Some(Some(vid)) => JsValue::from_str(vid),
            _ => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn thread_id(&self) -> JsValue {
        match &self.thread_id {
            Some(data) => serde_wasm_bindgen::to_value(data).unwrap(),
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn next_hop(&self) -> JsValue {
        match &self.next_hop {
            Some(next_hop) => JsValue::from_str(next_hop),
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> JsValue {
        match &self.payload {
            Some(data) => serde_wasm_bindgen::to_value(data).unwrap(),
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn opaque_payload(&self) -> JsValue {
        match &self.opaque_payload {
            Some(data) => serde_wasm_bindgen::to_value(data).unwrap(),
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn unknown_vid(&self) -> JsValue {
        match &self.unknown_vid {
            Some(unknown_vid) => JsValue::from_str(unknown_vid),
            None => JsValue::NULL,
        }
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
            message_type: None,
            route: None,
            nested_vid: None,
            thread_id: None,
            next_hop: None,
            payload: None,
            opaque_payload: None,
            unknown_vid: None,
            referred_vid: None,
            new_vid: None,
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
                nested_vid,
                thread_id,
            } => {
                this.sender = Some(sender);
                this.route = Some(route);
                this.nested_vid = Some(nested_vid);
                this.thread_id = Some(thread_id.to_vec());
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
            #[cfg(not(target_arch = "wasm32"))]
            tsp::ReceivedTspMessage::PendingMessage { .. } => {
                unreachable!()
            }
        };

        this
    }
}

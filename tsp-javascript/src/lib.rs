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
    pub bytes: Vec<u8>,
}

#[wasm_bindgen]
impl Store {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen]
    pub fn add_private_vid(&self, vid: OwnedVid) -> Result<(), Error> {
        self.0.add_private_vid(vid.0).map_err(Error)
    }

    #[wasm_bindgen]
    pub fn seal_message(
        &self,
        sender: String,
        receiver: String,
        nonconfidential_data: Option<Vec<u8>>,
        message: Vec<u8>,
    ) -> Result<SealedMessage, Error> {
        let (url, bytes) = self
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
            bytes,
        })
    }

    #[wasm_bindgen]
    pub fn open_message(&self, mut message: Vec<u8>) -> Result<FlatReceivedTspMessage, Error> {
        self.0
            .open_message(&mut message)
            .map(FlatReceivedTspMessage::from)
            .map_err(Error)
    }
}

#[wasm_bindgen]
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
}

impl From<&tsp::ReceivedTspMessage> for ReceivedTspMessageVariant {
    fn from(value: &tsp::ReceivedTspMessage) -> Self {
        match value {
            tsp::ReceivedTspMessage::GenericMessage { .. } => Self::GenericMessage,
            tsp::ReceivedTspMessage::RequestRelationship { .. } => Self::RequestRelationship,
            tsp::ReceivedTspMessage::AcceptRelationship { .. } => Self::AcceptRelationship,
            tsp::ReceivedTspMessage::CancelRelationship { .. } => Self::CancelRelationship,
            tsp::ReceivedTspMessage::ForwardRequest { .. } => Self::ForwardRequest,
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
            Some(inner) => match inner {
                Some(data) => serde_wasm_bindgen::to_value(data).unwrap(),
                None => JsValue::NULL,
            },
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn message(&self) -> JsValue {
        match dbg!(&self.message) {
            Some(data) => serde_wasm_bindgen::to_value(data).unwrap(),
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn route(&self) -> JsValue {
        match &self.route {
            Some(inner) => match inner {
                Some(routes) => serde_wasm_bindgen::to_value(routes).unwrap(),
                None => JsValue::NULL,
            },
            None => JsValue::NULL,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn nested_vid(&self) -> JsValue {
        match &self.nested_vid {
            Some(inner) => match inner {
                Some(vid) => JsValue::from_str(vid),
                None => JsValue::NULL,
            },
            None => JsValue::NULL,
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
            #[cfg(feature = "async")]
            tsp::ReceivedTspMessage::PendingMessage { .. } => {
                unreachable!()
            }
        };

        this
    }
}

from dataclasses import dataclass

import tsp_python
from tsp_python import OwnedVid, ReceivedTspMessageVariant, FlatReceivedTspMessage, CryptoType, SignatureType

class Store:
    inner: tsp_python.Store

    def __init__(self):
        self.inner = tsp_python.Store()

    def add_private_vid(self, *args, **kwargs):
        return self.inner.add_private_vid(*args, **kwargs)

    def add_verified_vid(self, *args, **kwargs):
        return self.inner.add_verified_vid(*args, **kwargs)

    def set_relation_for_vid(self, *args, **kwargs):
        return self.inner.set_relation_for_vid(*args, **kwargs)

    def set_route_for_vid(self, *args, **kwargs):
        return self.inner.set_route_for_vid(*args, **kwargs)

    def seal_message(self, *args, **kwargs):
        return self.inner.seal_message(*args, **kwargs)

    def open_message(self, *args, **kwargs):
        flat_message = self.inner.open_message(*args, **kwargs)
        return ReceivedTspMessage.from_flat(flat_message)

    def make_relationship_request(self, *args, **kwargs):
        return self.inner.make_relationship_request(*args, **kwargs)

    def make_relationship_accept(self, *args, **kwargs):
        return self.inner.make_relationship_accept(*args, **kwargs)

    def make_relationship_cancel(self, *args, **kwargs):
        return self.inner.make_relationship_cancel(*args, **kwargs)

    def make_nested_relationship_request(self, *args, **kwargs):
        return self.inner.make_nested_relationship_request(*args, **kwargs)

    def make_nested_relationship_accept(self, *args, **kwargs):
        return self.inner.make_nested_relationship_accept(*args, **kwargs)

    def forward_routed_message(self, *args, **kwargs):
        return self.inner.forward_routed_message(*args, **kwargs)

class ReceivedTspMessage:
    @staticmethod
    def from_flat(msg: FlatReceivedTspMessage):
        match msg.variant:
            case ReceivedTspMessageVariant.GenericMessage:
                return GenericMessage(msg.sender, msg.nonconfidential_data, bytes(msg.message), msg.crypto_type, msg.signature_type)

            case ReceivedTspMessageVariant.RequestRelationship:
                return RequestRelationship(msg.sender, msg.route, msg.nested_vid, msg.thread_id)

            case ReceivedTspMessageVariant.AcceptRelationship:
                return AcceptRelationship(msg.sender, msg.nested_vid)

            case ReceivedTspMessageVariant.CancelRelationship:
                return CancelRelationship(msg.sender)

            case ReceivedTspMessageVariant.ForwardRequest:
                return ForwardRequest(msg.sender, msg.next_hop, msg.route, msg.opaque_payload)

            case ReceivedTspMessageVariant.PendingMessage:
                raise ValueError("todo!")

            case other:
                raise ValueError(f"Unrecognized variant: {other}")

@dataclass
class GenericMessage(ReceivedTspMessage):
    sender: str
    nonconfidential_data: str
    message: str
    crypto_type: str
    signature_type: str

@dataclass
class AcceptRelationship(ReceivedTspMessage):
    sender: str
    nested_vid: str

@dataclass
class CancelRelationship(ReceivedTspMessage):
    sender: str

@dataclass
class RequestRelationship(ReceivedTspMessage):
    sender: str
    route: str
    nested_vid: str
    thread_id: str

@dataclass
class ForwardRequest(ReceivedTspMessage):
    sender: str
    next_hop: str
    route: str
    opaque_payload: str

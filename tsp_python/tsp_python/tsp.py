from dataclasses import dataclass
import requests

from tsp_python import tsp_python

OwnedVid = tsp_python.OwnedVid
ReceivedTspMessageVariant = tsp_python.ReceivedTspMessageVariant
FlatReceivedTspMessage = tsp_python.FlatReceivedTspMessage
CryptoType = tsp_python.CryptoType
SignatureType = tsp_python.SignatureType


def color_print(message: bytes):
    return tsp_python.color_print(message)


class Wallet:
    def __init__(self, store):
        self.inner = store.inner

    def __enter__(self):
        self.inner.read_wallet()

    def __exit__(self, type, value, traceback):
        self.inner.write_wallet()


class SecureStore:
    inner: tsp_python.Store

    def __init__(self):
        self.inner = tsp_python.Store()

    def add_private_vid(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.add_private_vid(*args, **kwargs)

    def add_verified_owned_vid(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.add_verified_owned_vid(*args, **kwargs)

    def resolve_alias(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.resolve_alias(*args, **kwargs)

    def verify_vid(self, did: str, alias=None) -> str:
        """Verify did document, add vid to store, and return endpoint"""
        with Wallet(self):
            return self.inner.verify_vid(did, alias)

    def get_vid_endpoint(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.get_vid_endpoint(*args, **kwargs)

    def set_relation_for_vid(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.set_relation_for_vid(*args, **kwargs)

    def set_route_for_vid(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.set_route_for_vid(*args, **kwargs)

    def seal_message(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.seal_message(*args, **kwargs)

    def send_message(
        self,
        sender: str,
        receiver: str,
        message: bytes,
        nonconfidential_data: bytes | None = None,
    ) -> requests.Response:
        with Wallet(self):
            url, message = self.inner.seal_message(
                sender, receiver, message, nonconfidential_data
            )
            if not url.startswith("http"):
                raise Exception(
                    "The Python SDK currently only supports HTTP(S) transport"
                )

            return requests.post(url, data=message)

    def get_sender_receiver(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.get_sender_receiver(*args, **kwargs)

    def open_message(self, *args, **kwargs):
        with Wallet(self):
            flat_message = self.inner.open_message(*args, **kwargs)
            return ReceivedTspMessage.from_flat(flat_message)

    def make_relationship_request(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.make_relationship_request(*args, **kwargs)

    def make_relationship_accept(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.make_relationship_accept(*args, **kwargs)

    def make_relationship_cancel(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.make_relationship_cancel(*args, **kwargs)

    def make_nested_relationship_request(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.make_nested_relationship_request(*args, **kwargs)

    def make_nested_relationship_accept(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.make_nested_relationship_accept(*args, **kwargs)

    def forward_routed_message(self, *args, **kwargs):
        with Wallet(self):
            return self.inner.forward_routed_message(*args, **kwargs)


class ReceivedTspMessage:
    @staticmethod
    def from_flat(msg: FlatReceivedTspMessage):
        match msg.variant:
            case ReceivedTspMessageVariant.GenericMessage:
                return GenericMessage(
                    msg.sender,
                    msg.nonconfidential_data,
                    bytes(msg.message),
                    msg.crypto_type,
                    msg.signature_type,
                )

            case ReceivedTspMessageVariant.RequestRelationship:
                return RequestRelationship(
                    msg.sender, msg.route, msg.nested_vid, msg.thread_id
                )

            case ReceivedTspMessageVariant.AcceptRelationship:
                return AcceptRelationship(msg.sender, msg.nested_vid)

            case ReceivedTspMessageVariant.CancelRelationship:
                return CancelRelationship(msg.sender)

            case ReceivedTspMessageVariant.ForwardRequest:
                return ForwardRequest(
                    msg.sender, msg.next_hop, msg.route, msg.opaque_payload
                )

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

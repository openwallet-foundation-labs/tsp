from dataclasses import dataclass

from tsp_python import tsp_python

OwnedVid = tsp_python.OwnedVid
ReceivedTspMessageVariant = tsp_python.ReceivedTspMessageVariant
FlatReceivedTspMessage = tsp_python.FlatReceivedTspMessage
CryptoType = tsp_python.CryptoType
SignatureType = tsp_python.SignatureType


def color_print(message: bytes) -> str:
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

    def __init__(self, *args, **kwargs):
        self.inner = tsp_python.Store(*args, **kwargs)

    def add_private_vid(
        self, vid: str, alias: str | None = None, metadata: dict[str, any] | None = None
    ):
        with Wallet(self):
            self.inner.add_private_vid(vid, alias, metadata)

    def forget_vid(self, vid: str):
        with Wallet(self):
            self.inner.forget_vid(vid)

    def add_verified_owned_vid(
        self, vid: str, alias: str | None = None, metadata: dict | None = None
    ):
        with Wallet(self):
            self.inner.add_verified_owned_vid(vid, alias, metadata)

    def resolve_alias(self, alias: str) -> str | None:
        with Wallet(self):
            return self.inner.resolve_alias(alias)

    def verify_vid(self, did: str, alias: str | None = None) -> str:
        """Verify did document, add vid to store, and return endpoint"""
        with Wallet(self):
            return self.inner.verify_vid(did, alias)

    def set_route_for_vid(self, vid: str, route: list[str]):
        with Wallet(self):
            self.inner.set_route_for_vid(vid, route)

    def seal_message(
        self,
        sender: str,
        receiver: str,
        message: bytes,
        nonconfidential_data: bytes | None = None,
    ) -> tuple[str, bytes]:
        with Wallet(self):
            return self.inner.seal_message(
                sender, receiver, message, nonconfidential_data
            )

    def send(
        self,
        sender: str,
        receiver: str,
        message: bytes,
        nonconfidential_data: bytes | None = None,
    ):
        with Wallet(self):
            self.inner.send(sender, receiver, message, nonconfidential_data)

    def receive(self, vid: str):
        with Wallet(self):
            message = self.inner.receive(vid)
            if message is None:
                return None
            return ReceivedTspMessage.from_flat(message)

    def get_sender_receiver(self, message: bytes) -> tuple[str, str]:
        with Wallet(self):
            return self.inner.get_sender_receiver(message)

    def open_message(self, message: bytes):
        with Wallet(self):
            flat_message = self.inner.open_message(message)
            return ReceivedTspMessage.from_flat(flat_message)

    def make_relationship_request(
        self, sender: str, receiver: str, route: list[str] | None = None
    ) -> tuple[str, bytes]:
        with Wallet(self):
            return self.inner.make_relationship_request(sender, receiver, route)

    def make_relationship_accept(
        self,
        sender: str,
        receiver: str,
        thread_id: bytes,
        route: list[str] | None = None,
    ) -> tuple[str, bytes]:
        with Wallet(self):
            return self.inner.make_relationship_accept(
                sender, receiver, thread_id, route
            )

    def make_relationship_cancel(self, sender: str, receiver: str) -> tuple[str, bytes]:
        with Wallet(self):
            return self.inner.make_relationship_cancel(sender, receiver)

    def make_nested_relationship_request(
        self, parent_sender: str, receiver: str
    ) -> tuple[tuple[str, bytes], tsp_python.OwnedVid]:
        with Wallet(self):
            return self.inner.make_nested_relationship_request(parent_sender, receiver)

    def make_nested_relationship_accept(
        self, sender: str, receiver: str, thread_id: bytes
    ) -> tuple[tuple[str, bytes], tsp_python.OwnedVid]:
        with Wallet(self):
            return self.inner.make_nested_relationship_accept(
                sender, receiver, thread_id
            )

    def forward_routed_message(
        self, next_hop: str, route: list[bytes], opaque_payload: bytes
    ):
        with Wallet(self):
            return self.inner.forward_routed_message(next_hop, route, opaque_payload)


class ReceivedTspMessage:
    @staticmethod
    def from_flat(msg: tsp_python.FlatReceivedTspMessage):
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

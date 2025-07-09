from dataclasses import dataclass
from typing import Any

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


# ANCHOR: secure-store-init-mdBook
class SecureStore:
    inner: tsp_python.Store

    def __init__(self, wallet_url="sqlite://wallet.sqlite", wallet_password="unsecure"):
        self.inner = tsp_python.Store(wallet_url, wallet_password)
        # ANCHOR_END: secure-store-init-mdBook

    # ANCHOR: manage-vids-mdBook
    def verify_vid(self, did: str, alias: str | None = None) -> str:
        """Resolve DID document, verify it, add vid to the wallet, and its return endpoint"""
        with Wallet(self):
            return self.inner.verify_vid(did, alias)

    def add_private_vid(
        self,
        vid: OwnedVid,
        alias: str | None = None,
        metadata: dict[Any, Any] | None = None,
    ):
        """Adds a private `vid` to the wallet"""
        with Wallet(self):
            self.inner.add_private_vid(vid, alias, metadata)

    def forget_vid(self, vid: str):
        """Remove a `vid` from the wallet"""
        with Wallet(self):
            self.inner.forget_vid(vid)

    def resolve_alias(self, alias: str) -> str | None:
        """Resolve alias to its corresponding DID (if it exists in the wallet)"""
        with Wallet(self):
            return self.inner.resolve_alias(alias)
        # ANCHOR_END: manage-vids-mdBook

    def add_verified_owned_vid(
        self,
        vid: OwnedVid,
        alias: str | None = None,
        metadata: dict[Any, Any] | None = None,
    ):
        """Add `vid` to the wallet, but without the private keys"""
        with Wallet(self):
            self.inner.add_verified_owned_vid(vid, alias, metadata)

    def set_route_for_vid(self, vid: str, route: list[str]):
        """Adds a route to an already existing VID, making it a nested VID"""
        with Wallet(self):
            self.inner.set_route_for_vid(vid, route)

    # ANCHOR: open-seal-mdBook
    def seal_message(
        self,
        sender: str,
        receiver: str,
        message: bytes,
        nonconfidential_data: bytes | None = None,
    ) -> tuple[str, bytes]:
        """
        Seal a TSP message.

        The message is encrypted, encoded, and signed using the key material
        of the sender and receiver, specified by their VIDs.
        """
        with Wallet(self):
            return self.inner.seal_message(
                sender, receiver, message, nonconfidential_data
            )

    def open_message(self, message: bytes):
        """Decode an encrypted `message`"""
        with Wallet(self):
            flat_message = self.inner.open_message(message)
            return ReceivedTspMessage.from_flat(flat_message)
        # ANCHOR_END: open-seal-mdBook

    # ANCHOR: send-receive-mdBook
    def send(
        self,
        sender: str,
        receiver: str,
        message: bytes,
        nonconfidential_data: bytes | None = None,
    ):
        """
        Send a TSP message given earlier resolved VIDs

        Encodes, encrypts, signs, and sends a TSP message
        """
        with Wallet(self):
            self.inner.send(sender, receiver, message, nonconfidential_data)

    def receive(self, vid: str):
        """Receive a single TSP messages for the private VID identified by `vid`, using the appropriate transport mechanism for it."""
        with Wallet(self):
            message = self.inner.receive(vid)
            return None if message is None else ReceivedTspMessage.from_flat(message)
        # ANCHOR_END: send-receive-mdBook

    def get_sender_receiver(self, message: bytes) -> tuple[str, str]:
        """Get the sender and receiver DIDs for an encoded TSP message"""
        with Wallet(self):
            return self.inner.get_sender_receiver(message)

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

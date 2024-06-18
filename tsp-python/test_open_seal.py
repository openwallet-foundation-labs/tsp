from dataclasses import dataclass

import tsp_python
from tsp_python import OwnedVid, ReceivedTspMessageVariant, FlatReceivedTspMessage, MessageType

class Store:
    inner: tsp_python.Store

    def __init__(self):
        self.inner = tsp_python.Store()

    def add_private_vid(self, *args, **kwargs):
        return self.inner.add_private_vid(*args, **kwargs)

    def seal_message(self, *args, **kwargs):
        return self.inner.seal_message(*args, **kwargs)

    def open_message(self, *args, **kwargs):
        flat_message = self.inner.open_message(*args, **kwargs)
        return ReceivedTspMessage.from_flat(flat_message)

class ReceivedTspMessage:
    @staticmethod
    def from_flat(msg: FlatReceivedTspMessage):
        match msg.variant:
            case ReceivedTspMessageVariant.GenericMessage:
                return GenericMessage(msg.sender, msg.nonconfidential_data, bytes(msg.message), msg.message_type)

            case ReceivedTspMessageVariant.RequestRelationship:
                raise ValueError("todo!")

            case ReceivedTspMessageVariant.AcceptRelationship:
                return AcceptRelationship(msg.sender, msg.nested_vid)

            case ReceivedTspMessageVariant.CancelRelationship:
                return CancelRelationship(msg.sender)

            case ReceivedTspMessageVariant.ForwardRequest:
                raise ValueError("todo!")

            case ReceivedTspMessageVariant.PendingMessage:
                raise ValueError("todo!")

            case other:
                raise ValueError(f"Unrecognized variant: {other}")

@dataclass
class GenericMessage(ReceivedTspMessage):
    sender: str
    nonconfidential_data: str
    message: str
    message_type: str 

@dataclass
class AcceptRelationship(ReceivedTspMessage):
    sender: str
    nested_vid: str

@dataclass
class CancelRelationship(ReceivedTspMessage):
    sender: str

def main():
    def new_vid():
        return OwnedVid.new_did_peer("tcp://127.0.0.1:1337")

    store = Store()
    alice = new_vid()
    bob = new_vid()

    store.add_private_vid(alice)
    store.add_private_vid(bob)

    message = b"hello world"

    (url, sealed) = store.seal_message(alice.identifier(), bob.identifier(), None, message)

    assert url == "tcp://127.0.0.1:1337"

    received = store.open_message(sealed)

    match received:
        case GenericMessage(sender, _, received_message, message_type):
            assert sender == alice.identifier()
            assert received_message == message
            assert message_type == MessageType.SignedAndEncrypted
            print("success:", received_message)

        case other:
            print(f"unexpected message type {other}")
            assert False

if __name__ == '__main__':
    main()

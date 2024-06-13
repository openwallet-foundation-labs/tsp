from dataclasses import dataclass

import tsp_python
from tsp_python import AsyncStore, OwnedVid, ReceivedTspMessageVariant, FlatReceivedTspMessage

class ReceivedTspMessage:
    pass

    @staticmethod
    def from_flat(msg: FlatReceivedTspMessage):
        match msg.variant:
            case ReceivedTspMessageVariant.GenericMessage:
                return AcceptRelationship(msg.sender, msg.nonconfidential_data, msg.message, msg.message_type)
            case ReceivedTspMessageVariant.RequestRelationship:
                raise ValueError("todo!")
            case ReceivedTspMessageVariant.AcceptRelationship:
                return AcceptRelationship(msg.sender)
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
    nonconfidential_data = None
    message = [] 
    message_type = None


@dataclass
class AcceptRelationship(ReceivedTspMessage):
    sender: str

@dataclass
class AcceptRelationship(ReceivedTspMessage):
    sender: str

@dataclass
class CancelRelationship(ReceivedTspMessage):
    sender: str

class AsyncStore:
    inner: tsp_python.AsyncStore

    def __init__(self):
        self.inner = tsp_python.AsyncStore()

    async def receive(self, address):
        return ReceivedTspMessageStream(await self.inner.receive(address))

    def add_private_vid(self, *args, **kwargs):
        return self.inner.add_private_vid(*args, **kwargs)

    def verify_vid(self, *args, **kwargs):
        return self.inner.verify_vid(*args, **kwargs)

    async def send(self, *args, **kwargs):
        return await self.inner.send(*args, **kwargs)

class ReceivedTspMessageStream:
    def __init__(self, future):
        self.future = future

    def __aiter__(self):
        return self

    async def __anext__(self):
        result = await self.future.next()
        if result is None:  
            raise StopAsyncIteration
        else:
            return ReceivedTspMessage.from_flat(result)

async def main():
    # bob database
    print("bob database");
    bob_db = AsyncStore();
    bob_vid = await OwnedVid.from_file("../examples/test/bob.json")
    bob_db.add_private_vid(bob_vid)
    await bob_db.verify_vid("did:web:did.tsp-test.org:user:alice")

    bobs_messages = await bob_db.receive("did:web:did.tsp-test.org:user:bob")
    print("got the stream")

    # alice database
    print("alice database");
    alice_db = AsyncStore();
    alice_vid = await OwnedVid.from_file("../examples/test/alice.json")
    alice_db.add_private_vid(alice_vid)
    await alice_db.verify_vid("did:web:did.tsp-test.org:user:bob")

    # send a message
    print("send a message")

    await alice_db.send(
        "did:web:did.tsp-test.org:user:alice",
        "did:web:did.tsp-test.org:user:bob",
        b"extra non-confidential data",
        b"hello world",
    )

    print("receive message")

    match await anext(bobs_messages):
        case GenericMessage(message):
            print("success: {}", message)

        case other:
            print(f"failure {other}")

import asyncio

loop = asyncio.get_event_loop()
loop.run_until_complete(main())

import unittest
from tsp import * 

def new_vid():
        return OwnedVid.new_did_peer("tcp://127.0.0.1:1337")

class AliceBob(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.alice = new_vid()
        self.bob = new_vid()

        self.store.add_private_vid(self.alice)
        self.store.add_private_vid(self.bob)

    def test_open_seal(self):
        message = b"hello world"

        url, sealed = self.store.seal_message(self.alice.identifier(), self.bob.identifier(), None, message)

        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)

        match received:
            case GenericMessage(sender, _, received_message, message_type):
                self.assertEqual(sender, self.alice.identifier())
                self.assertEqual(received_message, message)
                self.assertEqual(message_type, MessageType.SignedAndEncrypted)

            case other:
                self.fail(f"unexpected message type {other}")

    def test_make_relationship_request(self):
        url, sealed = self.store.make_relationship_request(self.alice.identifier(), self.bob.identifier(), None)

        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)

        match received:
            case RequestRelationship(sender, _route, _nested_vid, _thread_id):
                self.assertEqual(sender, self.alice.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

    def test_make_relationship_accept(self):
        url, sealed = self.store.make_relationship_request(self.alice.identifier(), self.bob.identifier(), None)
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)
        match received:
            case RequestRelationship(sender, _route, _nested_vid, thread_id):
                self.assertEqual(sender, self.alice.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        url, sealed = self.store.make_relationship_accept(self.bob.identifier(), self.alice.identifier(), thread_id, None)
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)
        match received:
            case AcceptRelationship(sender, _nested_vid):
                self.assertEqual(sender, self.bob.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

    @unittest.skip
    def test_make_relationship_cancel(self):
        url, sealed = self.store.make_relationship_request(self.alice.identifier(), self.bob.identifier(), None)
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)
        match received:
            case RequestRelationship(sender, _route, _nested_vid, thread_id):
                self.assertEqual(sender, self.alice.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        url, sealed = self.store.make_relationship_accept(self.bob.identifier(), self.alice.identifier(), thread_id, None)
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)
        match received:
            case AcceptRelationship(sender, _nested_vid):
                self.assertEqual(sender, self.bob.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        url, sealed = self.store.make_relationship_cancel(self.bob.identifier(), self.alice.identifier())
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)
        match received:
            case CancelRelationship(sender):
                self.assertEqual(sender, self.bob.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

if __name__ == '__main__':
    unittest.main()

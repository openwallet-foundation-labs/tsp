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

    def test_routed(self):
        a_store = Store()
        b_store = Store()
        c_store = Store()
        d_store = Store()

        nette_a = new_vid()
        sneaky_a = new_vid()

        b = new_vid()

        mailbox_c = new_vid()
        c = new_vid()

        sneaky_d = new_vid()
        nette_d = new_vid()

        a_store.add_private_vid(nette_a)
        a_store.add_private_vid(sneaky_a)
        b_store.add_private_vid(b)
        c_store.add_private_vid(mailbox_c)
        c_store.add_private_vid(c)
        d_store.add_private_vid(sneaky_d)
        d_store.add_private_vid(nette_d)

        a_store.add_verified_vid(b)
        a_store.add_verified_vid(sneaky_d)

        b_store.add_verified_vid(nette_a)
        b_store.add_verified_vid(c)

        c_store.add_verified_vid(b)
        c_store.add_verified_vid(nette_d)

        d_store.add_verified_vid(sneaky_a)
        d_store.add_verified_vid(mailbox_c)

        # relations

        a_store.set_relation_for_vid(b.identifier(), nette_a.identifier())

        a_store.set_relation_for_vid(sneaky_d.identifier(), sneaky_a.identifier())

        a_store.set_route_for_vid(
            sneaky_d.identifier(),
            [b.identifier(), c.identifier(), mailbox_c.identifier()],
        )

        b_store.set_relation_for_vid(c.identifier(), b.identifier())

        c_store.set_relation_for_vid(mailbox_c.identifier(), nette_d.identifier())

        # that was all the setup, now let's run some things

        hello_world = b"hello world";

        _, sealed = a_store.seal_message(sneaky_a.identifier(), sneaky_d.identifier(), None, hello_world)
        received = b_store.open_message(sealed)

        match received:
            case ForwardRequest(sender, next_hop, route, opaque_payload):
                self.assertEqual(sender, nette_a.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        _url, sealed = b_store.forward_routed_message(next_hop, route, opaque_payload)
        received = c_store.open_message(sealed)

        match received:
            case ForwardRequest(sender, next_hop, route, opaque_payload):
                self.assertEqual(sender, b.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        _url, sealed = c_store.forward_routed_message(next_hop, route, opaque_payload)
        received = d_store.open_message(sealed)

        match received:
            case GenericMessage(sender, nonconfidential_data, message, message_type):
                self.assertEqual(sender, sneaky_a.identifier())
                self.assertEqual(nonconfidential_data, None)
                self.assertEqual(message, hello_world)
                self.assertEqual(message_type, MessageType.SignedAndEncrypted)

            case other:
                self.fail(f"unexpected message type {other}")



if __name__ == '__main__':
    unittest.main()

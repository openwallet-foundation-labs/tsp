import os
import unittest

import tsp_python as tsp


def new_vid():
    return tsp.OwnedVid.new_did_peer("tcp://127.0.0.1:1337")


class AliceBob(unittest.TestCase):
    def setUp(self):
        self.store = tsp.SecureStore(wallet_url="sqlite://test_wallet.sqlite")
        self.alice = new_vid()
        self.bob = new_vid()

        self.store.add_private_vid(self.alice)
        self.store.add_private_vid(self.bob)

    def tearDown(self):
        os.remove("test_wallet.sqlite")

    def test_open_seal(self):
        message = b"hello world"

        url, sealed = self.store.seal_message(
            self.alice.identifier(), self.bob.identifier(), message
        )

        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)

        match received:
            case tsp.GenericMessage(
                sender, receiver, _, received_message, crypto_type, signature_type
            ):
                self.assertEqual(sender, self.alice.identifier())
                self.assertEqual(receiver, self.bob.identifier())
                self.assertEqual(received_message, message)
                self.assertNotEqual(crypto_type, tsp.CryptoType.Plaintext)
                self.assertNotEqual(signature_type, tsp.SignatureType.NoSignature)

            case other:
                self.fail(f"unexpected message type {other}")

    def test_make_relationship_request(self):
        url, sealed = self.store.make_relationship_request(
            self.alice.identifier(), self.bob.identifier(), None
        )

        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)

        match received:
            case tsp.RequestRelationship(
                sender, receiver, _route, _nested_vid, _thread_id
            ):
                self.assertEqual(sender, self.alice.identifier())
                self.assertEqual(receiver, self.bob.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

    def test_make_relationship_accept(self):
        url, sealed = self.store.make_relationship_request(
            self.alice.identifier(), self.bob.identifier(), None
        )
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)
        match received:
            case tsp.RequestRelationship(
                sender, receiver, _route, _nested_vid, thread_id
            ):
                self.assertEqual(sender, self.alice.identifier())
                self.assertEqual(receiver, self.bob.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        url, sealed = self.store.make_relationship_accept(
            self.bob.identifier(), self.alice.identifier(), thread_id, None
        )
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)
        match received:
            case tsp.AcceptRelationship(sender, receiver, _nested_vid):
                self.assertEqual(sender, self.bob.identifier())
                self.assertEqual(receiver, self.alice.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

    def test_make_relationship_cancel(self):
        url, sealed = self.store.make_relationship_request(
            self.alice.identifier(), self.bob.identifier(), None
        )
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)
        match received:
            case tsp.RequestRelationship(
                sender, receiver, _route, _nested_vid, thread_id
            ):
                self.assertEqual(sender, self.alice.identifier())
                self.assertEqual(receiver, self.bob.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        url, sealed = self.store.make_relationship_accept(
            self.bob.identifier(), self.alice.identifier(), thread_id, None
        )
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)
        match received:
            case tsp.AcceptRelationship(sender, receiver, _nested_vid):
                self.assertEqual(sender, self.bob.identifier())
                self.assertEqual(receiver, self.alice.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        url, sealed = self.store.make_relationship_cancel(
            self.bob.identifier(), self.alice.identifier()
        )
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = self.store.open_message(sealed)
        match received:
            case tsp.CancelRelationship(sender, receiver):
                self.assertEqual(sender, self.bob.identifier())
                self.assertEqual(receiver, self.alice.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

    def test_routed(self):
        a_store = tsp.SecureStore(wallet_url="sqlite://test_wallet_a.sqlite")
        b_store = tsp.SecureStore(wallet_url="sqlite://test_wallet_b.sqlite")
        c_store = tsp.SecureStore(wallet_url="sqlite://test_wallet_c.sqlite")
        d_store = tsp.SecureStore(wallet_url="sqlite://test_wallet_d.sqlite")

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

        a_store.add_verified_owned_vid(b)
        a_store.add_verified_owned_vid(sneaky_d)

        b_store.add_verified_owned_vid(nette_a)
        b_store.add_verified_owned_vid(c)

        c_store.add_verified_owned_vid(b)
        c_store.add_private_vid(nette_d)
        # TODO: fix routed mode (should not require private vid for setting drop off)

        d_store.add_verified_owned_vid(sneaky_a)
        d_store.add_verified_owned_vid(mailbox_c)

        # relations

        a_store.make_relationship_request(nette_a.identifier(), b.identifier(), None)

        a_store.make_relationship_request(
            sneaky_a.identifier(), sneaky_d.identifier(), None
        )

        a_store.set_route_for_vid(
            sneaky_d.identifier(),
            [b.identifier(), c.identifier(), mailbox_c.identifier()],
        )

        b_store.make_relationship_request(b.identifier(), c.identifier(), None)

        c_store.make_relationship_request(
            nette_d.identifier(), mailbox_c.identifier(), None
        )

        # that was all the setup, now let's run some things

        hello_world = b"hello world"
        _, sealed = a_store.seal_message(
            sneaky_a.identifier(), sneaky_d.identifier(), hello_world
        )
        received = b_store.open_message(sealed)

        match received:
            case tsp.ForwardRequest(sender, receiver, next_hop, route, opaque_payload):
                self.assertEqual(sender, nette_a.identifier())
                self.assertEqual(receiver, b.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        _url, sealed = b_store.forward_routed_message(next_hop, route, opaque_payload)
        received = c_store.open_message(sealed)

        match received:
            case tsp.ForwardRequest(sender, receiver, next_hop, route, opaque_payload):
                self.assertEqual(sender, b.identifier())
                self.assertEqual(receiver, c.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        _url, sealed = c_store.forward_routed_message(next_hop, route, opaque_payload)
        received = d_store.open_message(sealed)

        os.remove("test_wallet_a.sqlite")
        os.remove("test_wallet_b.sqlite")
        os.remove("test_wallet_c.sqlite")
        os.remove("test_wallet_d.sqlite")

        match received:
            case tsp.GenericMessage(
                sender,
                receiver,
                nonconfidential_data,
                message,
                crypto_type,
                signature_type,
            ):
                self.assertEqual(sender, sneaky_a.identifier())
                self.assertEqual(receiver, sneaky_d.identifier())
                self.assertEqual(nonconfidential_data, None)
                self.assertEqual(message, hello_world)
                self.assertNotEqual(crypto_type, tsp.CryptoType.Plaintext)
                self.assertNotEqual(signature_type, tsp.SignatureType.NoSignature)

            case other:
                self.fail(f"unexpected message type {other}")

    def test_nested_automatic(self):
        a_store = tsp.SecureStore(wallet_url="sqlite://test_wallet_a.sqlite")
        b_store = tsp.SecureStore(wallet_url="sqlite://test_wallet_b.sqlite")

        a = new_vid()
        b = new_vid()

        a_store.add_private_vid(a)
        b_store.add_private_vid(b)

        a_store.add_verified_owned_vid(b)
        b_store.add_verified_owned_vid(a)

        url, sealed = a_store.make_relationship_request(
            a.identifier(), b.identifier(), None
        )
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = b_store.open_message(sealed)
        match received:
            case tsp.RequestRelationship(
                sender, receiver, _route, _nested_vid, thread_id
            ):
                self.assertEqual(sender, a.identifier())
                self.assertEqual(receiver, b.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        url, sealed = b_store.make_relationship_accept(
            b.identifier(), a.identifier(), thread_id, None
        )
        self.assertEqual(url, "tcp://127.0.0.1:1337")

        received = a_store.open_message(sealed)
        match received:
            case tsp.AcceptRelationship(sender, receiver, _nested_vid):
                self.assertEqual(sender, b.identifier())
                self.assertEqual(receiver, a.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        (_url, sealed), nested_a = a_store.make_nested_relationship_request(
            a.identifier(), b.identifier()
        )

        match b_store.open_message(sealed):
            case tsp.RequestRelationship(
                sender, receiver, _route, nested_vid_1, thread_id
            ):
                self.assertEqual(sender, a.identifier())
                self.assertEqual(receiver, b.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        (_url, sealed), nested_b = b_store.make_nested_relationship_accept(
            b.identifier(), nested_vid_1, thread_id
        )

        match a_store.open_message(sealed):
            case tsp.AcceptRelationship(sender, receiver, nested_vid_2):
                self.assertEqual(sender, b.identifier())

            case other:
                self.fail(f"unexpected message type {other}")

        self.assertEqual(nested_a.identifier(), nested_vid_1)
        self.assertEqual(nested_b.identifier(), nested_vid_2)
        hello_world = b"hello world"
        _url, sealed = a_store.seal_message(
            nested_a.identifier(), nested_b.identifier(), hello_world
        )

        received = b_store.open_message(sealed)

        os.remove("test_wallet_a.sqlite")
        os.remove("test_wallet_b.sqlite")

        match received:
            case tsp.GenericMessage(
                sender, receiver, _, received_message, crypto_type, signature_type
            ):
                self.assertEqual(sender, nested_a.identifier())
                self.assertEqual(receiver, nested_b.identifier())
                self.assertEqual(received_message, hello_world)
                self.assertNotEqual(crypto_type, tsp.CryptoType.Plaintext)
                self.assertNotEqual(signature_type, tsp.SignatureType.NoSignature)

            case other:
                self.fail(f"unexpected message type {other}")


if __name__ == "__main__":
    unittest.main()

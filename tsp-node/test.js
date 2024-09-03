const assert = require('assert');

const tsp = require('./tsp');
const { Store, OwnedVid, CryptoType, SignatureType, GenericMessage, RequestRelationship, AcceptRelationship, CancelRelationship, ForwardRequest} = tsp;

function new_vid() {
    return OwnedVid.new_did_peer("tcp://127.0.0.1:1337");
}

describe('tsp node tests', function() {
    it("open and seal", function() {
        let store = new Store();

        let alice = new_vid();
        let bob = new_vid();

        let alice_identifier = alice.identifier();
        let bob_identifier = bob.identifier();

        store.add_private_vid(alice);
        store.add_private_vid(bob);

        let message = "hello world";

        let { url, sealed } = store.seal_message(alice_identifier, bob_identifier, null, message);

        assert.strictEqual(url, "tcp://127.0.0.1:1337");

        let received = store.open_message(sealed);

        if (received instanceof GenericMessage) {
            const { sender, message: messageBytes, crypto_type, signature_type } = received;
            assert.strictEqual(sender, alice_identifier, "Sender does not match Alice's identifier");
            let receivedMessage = String.fromCharCode.apply(null, messageBytes);
            assert.strictEqual(receivedMessage, message, "Received message does not match");
            assert.notStrictEqual(crypto_type, CryptoType.Plaintext, "Crypto type should not be Plaintext");
            assert.notStrictEqual(signature_type, SignatureType.NoSignature, "Signature type should not be NoSignature");
        } else {
            assert.fail(`Unexpected message type: ${received}`);
        }
    });

    it("relationship accept", function() {
        let store = new Store();
        let alice = new_vid();
        let bob = new_vid();

        store.add_private_vid(alice);
        store.add_private_vid(bob);

        // Alice wants to establish a relationship
        let { url, sealed } = store.make_relationship_request(alice.identifier(), bob.identifier(), null);

        assert.strictEqual(url, "tcp://127.0.0.1:1337");

        let received = store.open_message(sealed);

        if (received instanceof RequestRelationship) {
            const { sender, thread_id } = received;
            assert.strictEqual(sender, alice.identifier());
        } else {
            assert.fail(`Unexpected message type: ${received}`);
        }

        // Bob accepts the relationship
        ({ url, sealed } = store.make_relationship_accept(bob.identifier(), alice.identifier(), received.thread_id, null));

        assert.strictEqual(url, "tcp://127.0.0.1:1337");

        received = store.open_message(sealed);

        if (received instanceof AcceptRelationship) {
            const { sender } = received;
            assert.strictEqual(sender, bob.identifier());
        } else {
            assert.fail(`Unexpected message type: ${received}`);
        }
    });

    it("relationship cancel", function() {
        let store = new Store();
        let alice = new_vid();
        let bob = new_vid();

        store.add_private_vid(alice);
        store.add_private_vid(bob);

        // Alice wants to establish a relationship
        let { url, sealed } = store.make_relationship_request(alice.identifier(), bob.identifier(), null);

        assert.strictEqual(url, "tcp://127.0.0.1:1337");

        let received = store.open_message(sealed);

        if (received instanceof RequestRelationship) {
            const { sender, thread_id } = received;
            assert.strictEqual(sender, alice.identifier());
        } else {
            assert.fail(`Unexpected message type: ${received}`);
        }

        // Bob accepts the relationship
        ({ url, sealed } = store.make_relationship_accept(bob.identifier(), alice.identifier(), received.thread_id, null));

        assert.strictEqual(url, "tcp://127.0.0.1:1337");

        received = store.open_message(sealed);

        if (received instanceof AcceptRelationship) {
            const { sender } = received;
            assert.strictEqual(sender, bob.identifier());
        } else {
            assert.fail(`Unexpected message type: ${received}`);
        }

        // now bob cancels the relation
        ({ url, sealed } = store.make_relationship_cancel(bob.identifier(), alice.identifier()));

        assert.strictEqual(url, "tcp://127.0.0.1:1337");
        received = store.open_message(sealed);

        if (received instanceof CancelRelationship ) {
            const { sender } = received;
            assert.strictEqual(sender, bob.identifier());
        } else {
            assert.fail(`Unexpected message type: ${received}`);
        }
    });

    it("routed", function() {
        // Create stores and identities
        let a_store = new Store();
        let b_store = new Store();
        let c_store = new Store();
        let d_store = new Store();

        let nette_a = new_vid();
        let sneaky_a = new_vid();

        let b = new_vid();

        let mailbox_c = new_vid();
        let c = new_vid();

        let sneaky_d = new_vid();
        let nette_d = new_vid();

        // Add identities to stores
        a_store.add_private_vid(nette_a);
        a_store.add_private_vid(sneaky_a);
        b_store.add_private_vid(b);
        c_store.add_private_vid(mailbox_c);
        c_store.add_private_vid(c);
        d_store.add_private_vid(sneaky_d);
        d_store.add_private_vid(nette_d);

        // Set verified relations
        a_store.add_private_as_verified_vid(b);
        a_store.add_private_as_verified_vid(sneaky_d);
        b_store.add_private_as_verified_vid(nette_a);
        b_store.add_private_as_verified_vid(c);
        c_store.add_private_as_verified_vid(b);
        c_store.add_private_as_verified_vid(nette_d);
        d_store.add_private_as_verified_vid(sneaky_a);
        d_store.add_private_as_verified_vid(mailbox_c);

        // Set relations and routes
        a_store.set_relation_for_vid(b.identifier(), nette_a.identifier());
        a_store.set_relation_for_vid(sneaky_d.identifier(), sneaky_a.identifier());
        a_store.set_route_for_vid(sneaky_d.identifier(), [b.identifier(), c.identifier(), mailbox_c.identifier()]);

        b_store.set_relation_for_vid(c.identifier(), b.identifier());

        c_store.set_relation_for_vid(mailbox_c.identifier(), nette_d.identifier());

        // Prepare a message to be sent from a_store
        let hello_world = "hello world";

        // Seal the message from a_store
        let { url, sealed } = a_store.seal_message(sneaky_a.identifier(), sneaky_d.identifier(), null, Buffer.from(hello_world));

        // Open the sealed message in b_store
        let received = b_store.open_message(sealed);

        // Check the received message in b_store
        if (received instanceof ForwardRequest) {
            const { sender, next_hop, route, opaque_payload } = received;
            assert.strictEqual(sender, nette_a.identifier());

            // Forward the routed message from b_store to c_store
            let { url, sealed } = b_store.forward_routed_message(next_hop, route.map(s => Buffer.from(s)), opaque_payload);

            // Open the sealed message in c_store
            received = c_store.open_message(sealed);

            // Check the received message in c_store
            if (received instanceof ForwardRequest) {
                const { sender, next_hop, route, opaque_payload } = received;
                assert.strictEqual(sender, b.identifier());

                // Forward the routed message from c_store to d_store
                let { url, sealed } = c_store.forward_routed_message(next_hop, route.map(s => Buffer.from(s)), opaque_payload);

                // Open the sealed message in d_store
                received = d_store.open_message(sealed);

                // Check the final received message in d_store
                if (received instanceof GenericMessage) {
                    const { sender, nonconfidential_data: _, message: messageBytes, crypto_type, signature_type } = received;
                    assert.strictEqual(sender, sneaky_a.identifier());
                    message = String.fromCharCode.apply(null, messageBytes);
                    assert.strictEqual(message, hello_world, "Received message does not match");
                    assert.notStrictEqual(crypto_type, CryptoType.Plaintext, "Crypto type should not be Plaintext");
                    assert.notStrictEqual(signature_type, SignatureType.NoSignature, "Signature type should not be NoSignature");
                } else {
                    assert.fail(`Unexpected message type in d_store: ${received.type}`);
                }
            } else {
                assert.fail(`Unexpected message type in c_store: ${received.type}`);
            }
        } else {
            assert.fail(`Unexpected message type in b_store: ${received.type}`);
        }
    });

    it("nested automatic", function() {
        // Create stores and VIDs
        let a_store = new Store();
        let b_store = new Store();

        let a = new_vid();
        let b = new_vid();

        // Add private and verified VIDs
        a_store.add_private_vid(a);
        b_store.add_private_vid(b);

        a_store.add_private_as_verified_vid(b);
        b_store.add_private_as_verified_vid(a);

        // Make relationship request from 'a' to 'b'
        let {url, sealed} = a_store.make_relationship_request(a.identifier(), b.identifier(), null);
        let received = b_store.open_message(sealed);

        // Pattern match for RequestRelationship in received message
        if (received instanceof RequestRelationship) {
            let { thread_id } = received;

            // Make relationship accept from 'b' to 'a'
            ({url, sealed} = b_store.make_relationship_accept(b.identifier(), a.identifier(), thread_id, null));
            received = a_store.open_message(sealed);

            // Pattern match for AcceptRelationship in received message
            if (received instanceof AcceptRelationship) {
                // Make nested relationship request from 'a' to 'b'
                ({url, sealed} = a_store.make_nested_relationship_request(a.identifier(), b.identifier()));
                let received_1 = b_store.open_message(sealed);

                // Pattern match for RequestRelationship with nested_vid in received message
                if (received_1 instanceof RequestRelationship) {
                    let { nested_vid: nested_vid_1, thread_id: thread_id_1 } = received_1;

                    // Make nested relationship accept from 'b' with nested_vid_1 to 'a'
                    ({url, sealed} = b_store.make_nested_relationship_accept(b.identifier(), nested_vid_1, thread_id_1));
                    let received_2 = a_store.open_message(sealed);

                    // Pattern match for AcceptRelationship with nested_vid in received message
                    if (received_2 instanceof AcceptRelationship) {
                        let { nested_vid: nested_vid_2 } = received_2;

                        // Seal and open a message from 'a' to 'b'
                        let hello_world = "hello world";
                        ({ url: _, sealed: sealed_hello_world } = a_store.seal_message(
                            nested_vid_1,
                            nested_vid_2,
                            null,
                            hello_world,
                        ));

                        let received_3 = b_store.open_message(sealed_hello_world);

                        // Pattern match for GenericMessage in received message
                        if (received_3 instanceof GenericMessage) {
                            let { sender, nonconfidential_data, message: messageBytes, crypto_type, signature_type } = received_3;

                            // Assertions for GenericMessage
                            assert.strictEqual(sender, nested_vid_1);
                            assert.strictEqual(nonconfidential_data, null);
                            message = String.fromCharCode.apply(null, messageBytes);
                            assert.strictEqual(message, hello_world, "Received message does not match");
                            assert.notStrictEqual(crypto_type, CryptoType.Plaintext, "Crypto type should not be Plaintext");
                            assert.notStrictEqual(signature_type, SignatureType.NoSignature, "Signature type should not be NoSignature");
                        } else {
                            throw new Error("Unexpected message type");
                        }
                    } else {
                        throw new Error("Expected AcceptRelationship with nested_vid in received message");
                    }
                } else {
                    throw new Error("Expected RequestRelationship with nested_vid in received message");
                }
            } else {
                throw new Error("Expected AcceptRelationship in received message");
            }
        } else {
            throw new Error("Expected RequestRelationship in received message");
        }
    });
});

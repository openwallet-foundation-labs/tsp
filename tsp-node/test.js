const assert = require('assert');

const tsp = require('./tsp');
const { Store, OwnedVid, MessageType, GenericMessage, RequestRelationship, AcceptRelationship, CancelRelationship} = tsp;

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

        let sealed = store.seal_message(alice_identifier, bob_identifier, null, message);

        assert.strictEqual(sealed.url, "tcp://127.0.0.1:1337");

        let received = store.open_message(sealed.bytes);

        if (received instanceof GenericMessage) {
            const { sender, message: messageBytes, messageType } = received;
            assert.strictEqual(sender, alice_identifier, "Sender does not match Alice's identifier");
            let receivedMessage = String.fromCharCode.apply(null, messageBytes);
            assert.strictEqual(receivedMessage, message, "Received message does not match");
            assert.strictEqual(messageType, MessageType.SignedAndEncrypted, "Message type does not match SignedAndEncrypted");
            console.log("success:", receivedMessage);
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
        let { url, bytes: sealed } = store.make_relationship_request(alice.identifier(), bob.identifier(), null);

        assert.strictEqual(url, "tcp://127.0.0.1:1337");

        let received = store.open_message(sealed);

        if (received instanceof RequestRelationship) {
            const { sender, thread_id } = received;
            assert.strictEqual(sender, alice.identifier());
        } else {
            assert.fail(`Unexpected message type: ${received}`);
        }

        // Bob accepts the relationship
        ({ url, bytes: sealed } = store.make_relationship_accept(bob.identifier(), alice.identifier(), received.thread_id, null));

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
        let { url, bytes: sealed } = store.make_relationship_request(alice.identifier(), bob.identifier(), null);

        assert.strictEqual(url, "tcp://127.0.0.1:1337");

        let received = store.open_message(sealed);

        if (received instanceof RequestRelationship) {
            const { sender, thread_id } = received;
            assert.strictEqual(sender, alice.identifier());
        } else {
            assert.fail(`Unexpected message type: ${received}`);
        }

        // Bob accepts the relationship
        ({ url, bytes: sealed } = store.make_relationship_accept(bob.identifier(), alice.identifier(), received.thread_id, null));

        assert.strictEqual(url, "tcp://127.0.0.1:1337");

        received = store.open_message(sealed);

        if (received instanceof AcceptRelationship) {
            const { sender } = received;
            assert.strictEqual(sender, bob.identifier());
        } else {
            assert.fail(`Unexpected message type: ${received}`);
        }    

        // now bob cancels the relation
        ({ url, bytes: sealed } = store.make_relationship_cancel(bob.identifier(), alice.identifier()));

        assert.strictEqual(url, "tcp://127.0.0.1:1337");
        received = store.open_message(sealed);

        if (received instanceof CancelRelationship ) {
            const { sender } = received;
            assert.strictEqual(sender, bob.identifier());
        } else {
            assert.fail(`Unexpected message type: ${received}`);
        }    
    });
});

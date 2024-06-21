const wasm = require('tsp-javascript');

const MessageType = {
    Signed: 0, 
    SignedAndEncrypted: 1, 
};

class Store {
    constructor() {
        this.inner = new wasm.Store();
    }

    add_private_vid(...args) {
        return this.inner.add_private_vid(...args);
    }

    seal_message(sender, receiver, nonconfidential_data, message) {
        let byteArray;
        
        if (typeof message === 'string') {
            const encoder = new TextEncoder();
            byteArray = encoder.encode(message);
        } else if (message instanceof Uint8Array) {
            byteArray = message;
        } else {
            throw new TypeError("Message must be a string or a Uint8Array");
        }

        return this.inner.seal_message(sender, receiver, nonconfidential_data, byteArray);
    }

    open_message(...args) {
        const flatMessage = this.inner.open_message(...args);
        return ReceivedTspMessage.fromFlat(flatMessage);
    }
}

class ReceivedTspMessage {
    static fromFlat(msg) {
        switch (msg.variant) {
            case 0:
                return new GenericMessage(
                    msg.sender,
                    msg.nonconfidential_data,
                    new Uint8Array(msg.message),
                    msg.message_type
                );

            case 1: 
                throw new Error("todo!");

            case 2: 
                return new AcceptRelationship(
                    msg.sender,
                    msg.nested_vid
                );

            case 3: 
                return new CancelRelationship(
                    msg.sender
                );

            case 4: 
                throw new Error("todo!");

            case 5: 
                throw new Error("todo!");

            default:
                throw new Error(`Unrecognized variant: ${msg.variant}`);
        }
    }
}

class GenericMessage extends ReceivedTspMessage {
    constructor(sender, nonconfidentialData, message, messageType) {
        super();
        this.sender = sender;
        this.nonconfidentialData = nonconfidentialData;
        this.message = message;
        this.messageType = messageType;
    }
}

class AcceptRelationship extends ReceivedTspMessage {
    constructor(sender, nestedVid) {
        super();
        this.sender = sender;
        this.nestedVid = nestedVid;
    }
}

class CancelRelationship extends ReceivedTspMessage {
    constructor(sender) {
        super();
        this.sender = sender;
    }
}

function arraysEqual(arr1, arr2) {
    if (arr1.length !== arr2.length) {
        return false;
    }
    for (let i = 0; i < arr1.length; i++) {
        if (arr1[i] !== arr2[i]) {
            return false;
        }
    }
    return true;
}

function main() {
    function new_vid() {
        return wasm.OwnedVid.new_did_peer("tcp://127.0.0.1:1337");
    }

    let store = new Store();

    let alice = new_vid()
    let bob = new_vid()

    let alice_identifier = alice.identifier();
    let bob_identifier = bob.identifier();

    store.add_private_vid(alice)
    store.add_private_vid(bob)

    let message = "hello world"

    let sealed = store.seal_message(alice_identifier, bob_identifier, null, message);

    console.assert(sealed.url == "tcp://127.0.0.1:1337");

    let received = store.open_message(sealed.bytes);

    if (received instanceof GenericMessage) {
        const { sender, message: messageBytes, messageType } = received;
        console.assert(sender === alice_identifier, "Sender does not match Alice's identifier");
        let receivedMessage = String.fromCharCode.apply(null, messageBytes);
        console.assert(receivedMessage == message, "Received message does not match");
        console.assert(messageType === MessageType.SignedAndEncrypted, "Message type does not match SignedAndEncrypted");
        console.log("success:", receivedMessage);
    } else {
        console.log(`unexpected message type`, received);
        console.assert(false, "Unexpected message type");
    }
}

main()

const wasm = require('tsp-javascript');
const { OwnedVid } = wasm;

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

    make_relationship_request(...args) {
        return this.inner.make_relationship_request(...args);
    }

    make_relationship_accept(...args) {
        return this.inner.make_relationship_accept(...args);
    }

    make_relationship_cancel(...args) {
        return this.inner.make_relationship_cancel(...args);
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
                return new RequestRelationship(
                    msg.sender,
                    msg.route,
                    msg.nested_vid,
                    msg.thread_id,
                );

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

class RequestRelationship extends ReceivedTspMessage {
    constructor(sender, route, nested_vid, thread_id) {
        super();
        this.sender = sender;
        this.route = route;
        this.nested_vid = nested_vid;
        this.thread_id = thread_id;
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

module.exports = {
    MessageType,
    Store,
    OwnedVid,
    ReceivedTspMessage,
    GenericMessage,
    AcceptRelationship,
    CancelRelationship,
    RequestRelationship,
};


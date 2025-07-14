const wasm = require('tsp-javascript');
const { OwnedVid } = wasm;

const CryptoType = {
    Plaintext: 0,
    HpkeAuth: 1,
    HpkeEssr: 2,
    NaclAuth: 3,
    NaclEssr: 4,
};

const SignatureType = {
    NoSignature: 0,
    Ed25519: 1,
}

class Store {
    constructor() {
        this.inner = new wasm.Store();
    }

    add_private_vid(...args) {
        return this.inner.add_private_vid(...args);
    }

    add_verified_vid(...args) {
        return this.inner.add_verified_vid(...args);
    }

    set_relation_for_vid(...args) {
        return this.inner.set_relation_for_vid(...args);
    }

    set_route_for_vid(...args) {
        return this.inner.set_route_for_vid(...args);
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

    make_nested_relationship_accept(...args) {
        return this.inner.make_nested_relationship_accept(...args);
    }

    make_nested_relationship_request(...args) {
        return this.inner.make_nested_relationship_request(...args);
    }

    forward_routed_message(...args) {
        return this.inner.forward_routed_message(...args);
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
                    msg.receiver,
                    msg.nonconfidential_data,
                    new Uint8Array(msg.message),
                    msg.message_type
                );

            case 1: 
                return new RequestRelationship(
                    msg.sender,
                    msg.receiver,
                    msg.route,
                    msg.nested_vid,
                    msg.thread_id,
                );

            case 2: 
                return new AcceptRelationship(
                    msg.sender,
                    msg.receiver,
                    msg.nested_vid
                );

            case 3: 
                return new CancelRelationship(
                    msg.sender
                );

            case 4: 
                return new ForwardRequest(
                    msg.sender,
                    msg.receiver,
                    msg.next_hop,
                    msg.route,
                    msg.opaque_payload,
                );

            case 5: 
                throw new Error("todo!");

            default:
                throw new Error(`Unrecognized variant: ${msg.variant}`);
        }
    }
}

class GenericMessage extends ReceivedTspMessage {
    constructor(sender, receiver, nonconfidential_data, message, message_type) {
        super();
        this.sender = sender;
        this.receiver = receiver;
        this.nonconfidential_data = nonconfidential_data;
        this.message = message;
        this.message_type = message_type;
    }
}

class RequestRelationship extends ReceivedTspMessage {
    constructor(sender, receiver, route, nested_vid, thread_id) {
        super();
        this.sender = sender;
        this.receiver = receiver;
        this.route = route;
        this.nested_vid = nested_vid;
        this.thread_id = thread_id;
    }
}

class AcceptRelationship extends ReceivedTspMessage {
    constructor(sender, receiver, nested_vid) {
        super();
        this.sender = sender;
        this.receiver = receiver;
        this.nested_vid = nested_vid;
    }
}

class CancelRelationship extends ReceivedTspMessage {
    constructor(sender, receiver) {
        super();
        this.sender = sender;
        this.receiver = receiver;
    }
}

class ForwardRequest extends ReceivedTspMessage {
    constructor(sender, receiver, next_hop, route, opaque_payload) {
        super();
        this.sender = sender;
        this.receiver = receiver;
        this.next_hop = next_hop;
        this.route = route;
        this.opaque_payload = opaque_payload;
    }
}

module.exports = {
    CryptoType,
    SignatureType,
    Store,
    OwnedVid,
    ReceivedTspMessage,
    GenericMessage,
    AcceptRelationship,
    CancelRelationship,
    RequestRelationship,
    ForwardRequest,
};

const wasm = require('tsp-javascript');
const {
    OwnedVid,
    Vid,
    RelationshipForm,
    RelationshipDelivery,
} = wasm;

const CryptoType = {
    Plaintext: 0,
    HpkeBase: 1,
    SealedBox: 2,
};

const SignatureType = {
    NoSignature: 0,
    Ed25519: 1,
}

// How an upper layer's own payload is protected. TSP's control messages are
// always encrypted, whatever this says. SignedOnly is only meaningful under
// nesting: the enclosing envelope is confidential either way, but the payload's
// confidentiality then rests on the enclosing relationship's keys rather than
// its own (spec 4).
const PayloadConfidentiality = {
    Confidential: 0,
    SignedOnly: 1,
};

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

    // `confidentiality` is optional and defaults to encrypt-and-sign; pass
    // PayloadConfidentiality.SignedOnly to sign a nested payload without
    // encrypting it, which leaves its confidentiality resting on the enclosing
    // relationship's keys rather than its own (spec 4).
    seal_message(sender, receiver, message, confidentiality) {
        let byteArray;
        
        if (typeof message === 'string') {
            const encoder = new TextEncoder();
            byteArray = encoder.encode(message);
        } else if (message instanceof Uint8Array) {
            byteArray = message;
        } else {
            throw new TypeError("Message must be a string or a Uint8Array");
        }

        return this.inner.seal_message(sender, receiver, byteArray, confidentiality);
    }

    make_relationship_request(...args) {
        return this.inner.make_relationship_request(...args);
    }

    make_relationship_accept(...args) {
        return this.inner.make_relationship_accept(...args);
    }

    make_parallel_relationship_request(...args) {
        return this.inner.make_parallel_relationship_request(...args);
    }

    make_parallel_relationship_accept(...args) {
        return this.inner.make_parallel_relationship_accept(...args);
    }

    make_relationship_cancel(...args) {
        return this.inner.make_relationship_cancel(...args);
    }

    make_relationship_cancel_reply(...args) {
        return this.inner.make_relationship_cancel_reply(...args);
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
                    new Uint8Array(msg.message),
                    msg.crypto_type,
                    msg.signature_type,
                    msg.enclosing_crypto_type
                );

            case 1: 
                return new RequestRelationship(
                    msg.sender,
                    msg.receiver,
                    msg.thread_id,
                    msg.form,
                    msg.delivery,
                    msg.nested_vid,
                    msg.new_vid,
                );

            case 2: 
                return new AcceptRelationship(
                    msg.sender,
                    msg.receiver,
                    msg.thread_id,
                    msg.reply_thread_id,
                    msg.form,
                    msg.delivery,
                    msg.nested_vid,
                    msg.new_vid,
                );

            case 3: 
                return new CancelRelationship(
                    msg.sender,
                    msg.receiver,
                    msg.thread_id,
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
    // `enclosing_crypto_type` is how the message this one arrived inside was
    // encrypted, or undefined when it was not nested. A message whose
    // crypto_type is Plaintext but which has an enclosing type was still
    // confidential on the wire, under the enclosing relationship's keys rather
    // than its own (spec 4).
    constructor(sender, receiver, message, crypto_type, signature_type, enclosing_crypto_type) {
        super();
        this.sender = sender;
        this.receiver = receiver;
        this.message = message;
        this.crypto_type = crypto_type;
        this.signature_type = signature_type;
        this.enclosing_crypto_type = enclosing_crypto_type;
    }
}

class RequestRelationship extends ReceivedTspMessage {
    constructor(sender, receiver, thread_id, form, delivery, nested_vid, new_vid) {
        super();
        this.sender = sender;
        this.receiver = receiver;
        this.thread_id = thread_id;
        this.form = form;
        this.delivery = delivery;
        this.nested_vid = nested_vid;
        this.new_vid = new_vid;
    }
}

class AcceptRelationship extends ReceivedTspMessage {
    constructor(sender, receiver, thread_id, reply_thread_id, form, delivery, nested_vid, new_vid) {
        super();
        this.sender = sender;
        this.receiver = receiver;
        this.thread_id = thread_id;
        this.reply_thread_id = reply_thread_id;
        this.form = form;
        this.delivery = delivery;
        this.nested_vid = nested_vid;
        this.new_vid = new_vid;
    }
}

class CancelRelationship extends ReceivedTspMessage {
    constructor(sender, receiver, thread_id) {
        super();
        this.sender = sender;
        this.receiver = receiver;
        this.thread_id = thread_id;
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
    PayloadConfidentiality,
    RelationshipForm,
    RelationshipDelivery,
    Store,
    OwnedVid,
    Vid,
    ReceivedTspMessage,
    GenericMessage,
    AcceptRelationship,
    CancelRelationship,
    RequestRelationship,
    ForwardRequest,
};

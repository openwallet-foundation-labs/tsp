# Intermediary server

In the context of the TSP an intermediary server routes TSP messages.
See [the specification](https://trustoverip.github.io/tswg-tsp-specification/#routed-messages-through-intermediaries).
This document provides some guidelines on how to set up an intermediary.

## Example

The directory `examples/` contains the source code for an example
intermediary server, see `examples/src/intermediary.rs`.

This server listens on a specified port and starts a web server to accept
TSP messages over an HTTP(S) transport. A receiver (client) can
set up a websocket connection to this intermediary to be able to receive messages
when no public address can be exposed, behind a firewall.

### Public demo intermediaries

We host two demo intermediaries publicly for testing:

- [Intermediary P](https://p.teaspoon.world/), which has the identifier `did:web:p.teaspoon.world`
- [Intermediary Q](https://q.teaspoon.world/), which has the identifier `did:web:q.teaspoon.world`

These two instances both run the `examples/src/intermediary.rs` server.

The `cli-demo-routed-external.sh` script in the `examples/` directory creates two local end-points A and B, and then sends a message from A to B via the public intermediaries P and Q. To do this, it first sets up relations between A and P and between B and Q. Additionally, for the final drop-off to work, B creates a nested relation between B and Q, resulting into two nested DIDs B2 and Q2. The final route of the message from A then becomes `P,Q,Q2`, where Q2 will drop off the message at B2.

For a step-by-step example of how you can send a message over the intermediaries using the CLI, see the documentation page about [routed mode](./cli/routed.md).

### Running demo intermediaries locally

You can also run your own intermediaries servers on localhost. To get HTTPS to work, we use an SSL proxy using the certificates in the `examples/test/` folder. You can start this proxy by running the following command in the `examples/test/` folder:

```
npx local-ssl-proxy --config ./ssl-proxy.json
```

We use the feature flag `tsp/use_local_certificate` to load in the certificates used by the proxy into the intermediary and the CLI. Run the following two commands in two separate terminals to start intermediaries P and Q locally:

```
cargo run --features tsp/use_local_certificate --bin demo-intermediary -- --port 3011 localhost:3001
cargo run --features tsp/use_local_certificate --bin demo-intermediary -- --port 3012 localhost:3002
```

This runs the intermediaries on <http://localhost:3011/> and <http://localhost:3012/>. The SSL proxy makes these accessible via HTTPS at <https://localhost:3001/> and <https://localhost:3002/>, so DIDs we should use are `did:web:localhost%3A3001` for P and `did:web:localhost%3A3002` for Q.

The `cli-demo-routed-local.sh` script in the `examples/` directory creates two local end-points A and B, and sends a message from A to B via the local intermediaries P and Q. This works the same as the demo using our publicly accessible intermediaries.

## TSP library usage for intermediaries

An intermediary can use the same interface as other TSP-Rust applications,
namely the `Store` or the `AsyncStore`. Use the `AsyncStore` as a high-level
interface, with built-in transport methods. Use the `Store` if you have different
or specific transportation methods and only use this crate to seal and unseal TSP messages.

An intermediary basically needs to hold key material of its users and forwards/routes
messages. To add / manage user key material use the default store methods, like
`add_verified_vid` or `verify_id`. The server itself also needs an identity and
key material. Populate a store to manage these identities.

The primary method to route messages is `route_message`
which takes a sender and a receiver vid (string slice) and an owned message as bytes.
In the `AsyncStore` this method will send the resulting message immediately,
in the `Store` it will return the new message as bytes, in which case the
caller needs to send the message over a (custom) transport.

Note that the sender/receiver VIDs of an incoming message get be retrieved using
`tsp::cesr::get_sender_receiver`. Another method that might be useful is
`has_private_vid` to check whether an incoming message is actually addressed to
the current intermediary.



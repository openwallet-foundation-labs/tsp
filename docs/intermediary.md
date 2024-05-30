# Intermediary server

In the context of the TSP an intermediary server routes TSP messages.
See [the specification](https://trustoverip.github.io/tswg-tsp-specification/#routed-messages-through-intermediaries).
This document provides some guidelines on how to setup an intermediary.

## Example

The directory `examples/` contains the source code for an example
intermediary server, see `examples/src/intermediary.rs`.

This server listens on a specified port and starts a web server to accept
TSP messages over a HTTP(S) transport. A receiver (client) can
setup a websocket connection to this intermediary to be able to receive messages
when no public address can be exposed, behind a firewall.

## TSP library usage for intermediaries

An intermediary can use the same interface as other TSP-Rust applications,
namely the `Store` or the `AsyncStore`. Use the `AsyncStore` as a high-level
interface, with build-in transport methods. Use the `Store` if you have different
or specific transportation methods and only use this crate to seal and unseal TSP messages.

An intermediary basically needs to hold key material of its users and forwards/routes
messages. To add / manage user key material use the default store methods, like
`add_verified_vid` or `verify_id`. The server itself also needs an identity and
key material. Populate a store to manage these identities.

The primary method to route messages is `route_message`
which takes a sender and a receiver vid (string slice) and an owned message as bytes.
In the `AsyncStore` this method wil send the resulting message immediately,
in the `Store` it wil return the new message as bytes, in which case the
caller needs to send the message over a (custom) transport.

Note that the sender/receiver VIDs of an incoming message get be retrieved using
`tsp::cesr::get_sender_receiver`. Another method that might be useful is
`has_private_vid` to check whether an incoming message is actually addressed to
the current intermediary.

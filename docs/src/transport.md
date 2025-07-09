# Transport layers

TSP uses a transport layer to transfer TSP messages between end-points. The TSP SDK provides some built-in transport options, but it is also possible to use your own transport solution.

## Built-in transport options

The TSP SDK provides the following transport options:

- HTTP(S), which uses a combination of WebSockets (for receiving messages) and POST requests (to send messages) to get around firewalls for clients which are not necessarily publicly available — this works best when using an [intermediary server](./intermediary.md) to route messages
- TCP, which requires a direct network connection between clients
- TLS, which requires valid TLS certificates and a direct connection
- QUIC, which also requires valid certificates and a direct connection

These transports are used by the `AsyncSecureStore`'s `send` and `receive` methods, which pick the appropriate transport based on the transport URL's scheme.

## Using custom transport

It is also possible to use your own custom transport solution by using the low level TSP API. Use the `seal_message` and `open_message` functions (as described [here](./sdk-apis.md#seal-and-open-a-tsp-message)) to seal and open TSP messages.

Sending a message from Alice to Bob via your own transport layer should work as follows:

1. Alice resolves Bob's DID (if not yet known)
2. Alice seals the message into a TSP message
3. Alice sends the TSP message to Bob using your preferred method of transport
4. Bob resolves Alice's DID (if not yet known)
5. Bob opens the TSP message, retrieving Alice's message

This allows you to use TSP over any transport mechanism, including for example WebSockets, MQTT, email, or any other method of transport available in your particular application. For example, [TMCP](./tmcp.md) (MCP with TSP) uses this approach to secure the communication between AI agents and MCP servers.

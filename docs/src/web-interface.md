# Web interface

A short demo of the web interface:

<iframe width="754" height="430" frameborder="0"  src="https://www.youtube.com/embed/gYC3rX4VIN8?si=nqADjKEgVZHIM5V9" allowfullscreen></iframe>

## Overview

Go to <https://demo.teaspoon.world/>

This interface allows us to create VIDs and send and receive messages.

The VID type used for this demo is `did:web`. When a new identity
is created, the corresponding `did.json` document is published on the DID support server (<https://did.teaspoon.world/endpoint/{username}/did.json>).

The transport used for this demo is HTTPS and web sockets (WSS). The server also acts as a transport backbone. 

## Getting started

## Create an identity

To get started, create an identity:

- In the top left corner enter a username, e.g. `alice`
- Press "Create test VID"

In the list of identities on the left, your VID with the corresponding
key material will be shown. This identity will also be stored in the local
storage of your browser. The next time you visit this page, it will be
loaded automatically.

## Resolve and verify a VID

To resolve a VID, follow the instructions below.

Note that VIDs of the type `did:webvh`, `did:web` and `did:peer` are supported.

In order to be able to resolve a VID you could open the web interface
in an "Incognito" browser window and create a new VID. You should use
"Incognito" to prevent the identities in your local storage from being overwritten.
This way you can have a window for a sender and a window for a receiver 
identity and test sending messages from one to the other.

Note that this will also work over the internet,
sending messages from one device to the other.

<div class="warning">
The demo server on <demo.teaspoon.world> should not be used in a production use of TSP. In particular
there are no guarantees about persistent storage. Generated VIDs might only persist until the server
is restarted, which happens at least once a week.
</div>

Enter a full VID in the field "Resolve and verify VID" and push the button.
For example, endpoint `bob` might have identifier `did:web:did.teaspoon.world:endpoint:bob`.
You can also verify identifiers from other external DID Web servers. For example, the identifier `did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a` points to [this did.json](https://raw.githubusercontent.com/openwallet-foundation-labs/tsp/refs/heads/main/examples/test/a/did.json) in the TSP GitHub repository and can also be verified by the demo server.
The resolved and verified VID will be displayed in the "Identities" column.

## Sending / receiving messages

Use the "Send message" for to send messages. The "Sender" and "Receiver" fields
must be filled in with fully qualified VIDs, that exist in the "Identities"
column. 

For example, we could fill in `did:web:did.teaspoon.world:endpoint:alice` as sender and
`did:web:did.teaspoon.world:endpoint:bob` as receiver if we have the private VID for
`did:web:did.teaspoon.world:endpoint:alice` and the Public VID for `did:web:did.teaspoon.world:endpoint:bob`.

The contents in the "Non-confidential data" will be added to the TSP unencrypted.
The contents of the field "Message" will always be encrypted.

A browser window with the private VID of the receiver will show all
messages addressed to this VID in the "Received" column.

## Select sender / receiver

Instead of entering the full VID in the "Sender" / "Receiver" fields, you can
also use the "Select sender" and "Select receiver" buttons in the "Identities"
column.

## Ad-hoc verification

If a message is received from an unknown sender the button "Verify" can be pressed
to resolve and verify the sender VID and decrypt / verify the message contents.

## Message debug print

Each message is shown in the CESR text domain. The individual parts,
the selectors and possibly the plaintext variants of these parts are shown below.

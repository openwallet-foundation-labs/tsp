# Web interface

A short demo of the web interface:

<iframe width="754" height="430" frameborder="0"  src="https://www.youtube.com/embed/gYC3rX4VIN8?si=nqADjKEgVZHIM5V9" allowfullscreen></iframe>

## Overview

Go to https://tsp-test.org/

This interface allows us to create VIDs and send and receive messages.

The VID type used for this demo is `did:web`. When a new identity
is created, the corresponding `did.json` document is published on the same
domain (tsp-test.org).

The transport used for this demo is HTTPS and web sockets (WSS). The server
(tsp-test.org) also acts as a transport backbone. 

## Getting started

## Create an identity

To get started, create an identity:

- In the top left corner enter an username, e.g. `alice`
- Press "Create test VID"

In the list of identities on the left your VID with the corresponding
key material wil be shown. This identity will also be stored in the local
storage of your browser. The next time you visit this page it will be
loaded automatically.

## Resolve and verify a VID

To resolve a vid follow the instructions below.

Note that only VIDs of the type `did:web` or `did:peer` are supported.

In order to be able to resolve a VID you could open the web interface
in an "Incognito" browser window and create a new VID. You should use
"Incognito" to prevent the identities in your local storage to be overwritten.
This way you can have a window for a sender and a window for a receiver 
identity en test sending messages from one to the other.

Note that this will also work over the internet,
sending messages from one device to the other.

<div class="warning">
The demo server on tsp-test.org does not have persistent storage. Generated VIDs
will only persist until the server is restarted, which happens at least once a week.
</div>

Enter a full VID in the field "Resolve and verify VID" and push the button.
For example `did:web:tsp-test.org:user:bob`.
The resolved and verified VID wil be displayed in the identities column.

## Sending / receiving messages

Use the "Send message" for to send messages. The "Sender" and "Receiver" fields
must be filled in with fully qualified VIDs, that exist in the "Identities"
column. 

For example, we could fill in `did:web:tsp-test.org:user:alice` as sender and
`did:web:tsp-test.org:user:bob` as receiver if we have the private VID for
`did:web:tsp-test.org:user:alice` and the Public VID for `did:web:tsp-test.org:user:bob`.

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

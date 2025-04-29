# Usage

## Create a first identity

The `tsp` command line tool will store its wallet encrypted using [Askar](https://github.com/openwallet-foundation/askar) in the current directory. See the [custom secure storage](../custom-secure-storage.md) page for documentation about how to implement custom secure storage solutions.

<div class="warning">
The TSP command is used as an example and 'playground' to explore TSP, and as an
example for programmers on how to use the SDK to build TSP applications. It does not
expose all the functionality of the TSP SDK (e.g., TLS or QUICK transport), neither
should it used to build production applications.
</div>

To create a test `did:web` identity run the following command:

```sh
tsp create example
```

Output:
``` 
INFO tsp: created new wallet
INFO tsp: created identity did:web:did.teaspoon.world:user:example
```

**Note:** the DIDs need to be unique. If you try to create an endpoint that already exists on did.teaspoon.world, you will get an error.

We can add an alias to a VID using the --alias argument:

```sh
tsp create example --alias example
```

In subsequent commands we can type `example` instead of `did:web:did.teaspoon.world:user:example`.

Every `tsp` subcommand also supports the `--verbose` flag for a more verbose output:

```sh
tsp --verbose create example --alias example
```

Output:
``` 
TRACE tsp: opened wallet wallet
 INFO tsp: added alias example -> did:web:did.teaspoon.world:user:example
 INFO tsp: created identity did:web:did.teaspoon.world:user:example
DEBUG tsp: DID server responded with status code 200 OK
TRACE tsp: published DID document for did:web:did.teaspoon.world:user:example
TRACE tsp: persisted wallet
```

## Show wallet content
In some cases it might be helpful to check what the wallet contains to understand the behavior of TSP.
Therefore, the CLI provides a `show` command.
The `show local` command will print all the local VIDs stored in the wallet,
including their alias, transport, and parent.

```
did:peer:2.Vz6MurhTjqX5uhQ5bJbAaoEwSDFcKDwVJTvoii51JBtSPpKzX.Ez6LbvBvy92yWENk8xKYmaX9X9nzMtQCQ2EqgdLKv2YkcpHo7.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0
	 Alias: None
	 Transport: did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b
	 DID doc: None
	 public enc key: XwZQDosAabkk61UmCcLaQKrvlgM6RLX+9bsVe2TCplo=
	 public sign key: AeQsHfFqfWT/tuImrIoanqkui0rvVezHP4gBfCA2g6g=

did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b
	 Alias: b
	 Transport: https://q.teaspoon.world/transport/did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b
	 DID doc: https://raw.githubusercontent.com/openwallet-foundation-labs/tsp/main/examples/test/b/did.json
	 public enc key: JY/sQu1c8LJq6aTR9TlUMdNDf6xEzqkZeuJH6berxFk=
	 public sign key: EAA90CN5qEnTUXyNpPRmVsME2Qyxjj/KlRbP2DcXrF4=
```

Additionally, `tsp show relations <local VID or alias>`
will provide all resolved VIDs that the local VID has a relation with,
including the alias, relation status, and transport.

```
did:web:q.teaspoon.world
	 Relation Status: Bidirectional
	 Alias: q
	 Transport: https://q.teaspoon.world/transport/did:web:q.teaspoon.world
	 DID doc: https://q.teaspoon.world/.well-known/did.json
	 public enc key: slqqOWKP1WhCN+X/tuGgoUkrryA6F//f5rV6cqXsL3Q=
	 public sign key: djnK+ljzZsA2gX/X/IUy1Y06+j5Souo1bzTDZ9RoJxc=
```

## Resolve a VID

VIDs created with the `tsp` tool are published on __did.teaspoon.world__.
Currently, Rust TSP is able to verify `did:web` and `did:peer` VIDs

To resolve and verify a VID, run the following:

```sh
tsp verify did:web:did.teaspoon.world:user:example
```

Output:
```
 INFO tsp: did:web:did.teaspoon.world:user:example is verified and added to the wallet
```

The verify command also support the alias argument:

```sh
tsp verify did:web:did.teaspoon.world:user:example --alias example
```

## Send a message

For this example we will create two identities with separate wallets - __alice__ and __bob__.

You could perform the operations for __alice__ and __bob__ on different computers, for this example
we will separate them by using distinct wallets.

Use the `--wallet` flag to specify the file name of the wallet.

First create the identity for __alice__:

```sh
tsp --wallet alice create alice --alias alice
```

Then create the identity for __bob__:

```sh
tsp --wallet bob create bob --alias bob
```

Let __alice__ verify __bob__'s VID and add it to the wallet `alice`:

```sh
tsp --wallet alice verify did:web:did.teaspoon.world:user:bob --alias bob
```

Let __bob__ verify __alice__'s VID and add it to the wallet `bob`:

```sh
tsp --wallet bob verify did:web:did.teaspoon.world:user:alice --alias alice
```

Let __bob__  start listening for a message:

```sh
tsp --wallet bob receive --one bob
```

The `--one` argument makes the command exit when the first message is received.

Since the above command will block / wait for a first message we should use
a new / different terminal to send the message from __alice__.

To send a message run the following:

```sh
echo "Hello Bob!" | tsp --wallet alice send --sender-vid alice --receiver-vid bob
```

Note that `alice` and `bob` are aliases of `did:web:did.teaspoon.world:user:alice`
and `did:web:did.teaspoon.world:user:bob`.

We can also use aliases for the argument, for example:

```sh
echo "Hello Bob!" | tsp -w alice send -s alice -r bob
```

In the other terminal window the message should appear:

```sh
tsp --wallet bob receive --one bob
```

```
 INFO tsp: listening for messages...
 INFO tsp: received message (11 bytes) from did:web:did.teaspoon.world:user:alice
Hello Bob!
```

### DID types supported

The TSP CLI example application supports two types of decentralized identifiers:

* `did:web`, created using `tsp create`. These are resolved by finding a `.json` file on a server and checking its contents.
* `did:peer`, created using `tsp create-peer`. These are essentially self-signed identifiers.

The TSP CLI can use two types of transport:

* `https`, which forces the use of a broadcast server application (see `demo-server.rs`),
   but will work well across firewalls.

* `tcp`, which requires a direct network connection between two instances of the TSP CLI.
   In practice, you can use this only on a local network (or the same machine, if you use different ports), but
   this functionality is added to demonstrate the flexibility of having multiple transports. This transport mode
   is only available to `did:peer`. To use TCP transport, use the `--tcp address:port` flag to `tcp create-peer`.

### Pretty print messages

The CLI has a `--verbose` flag.
For the `send` command, this will output the CESR-encoded TSP message that is sent.

Continuing with the __alice__ and __bob__ example:

```sh
echo "Hello Bob!" | tsp --verbose -w alice send -s alice -r bob
```

Output:
```
 INFO tsp::async_store: sending message to https://demo.teaspoon.world/user/did:web:did.teaspoon.world:user:bob
CESR-encoded message:
-EABXAAA9VIDAAALAAAZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjphbGljZQ8VIDAAAKAAZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjpib2I4CAX7ngr3YHl2z91L-anFBYxbQhM48CT_wqrCCRNdsN5fm-oshqvwqnKDK5rLkn_kvVI8aWZ7SEhiaiB8N6e-bjInrBbhNII0BAceo-mZoSvG3MY_UEqrgzP4kpeLJJK9MdQx53c4nxKh6_jvB2DuXJ6TBNjj-lXszyTH8yDAMSioDRluucSBpPAg
 INFO tsp: sent message (11 bytes) from did:web:did.teaspoon.world:user:alice to did:web:did.teaspoon.world:user:bob
```

In a terminal window supporting colors this will look like the following:

<code style="display: block; line-break: anywhere; padding: 1rem;">
<strong style="color: #F66151;">-EABXAAA</strong><span style="color: #C061CB;"><strong>9VIDAAALAAA</strong>ZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjphbGljZQ</span><span style="color: #2A7BDE;"><strong>8VIDAAAKAA</strong>ZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjpib2I</span><span style="color: #E9AD0C;"><strong>4CAX</strong>5I7ozAGaFVqTxz8PJve0Tscor80fvds6hCf3yDUtOnHpXZ84uXFGXM-PcfLDWsRWvH7SoOG4UwQU8H-zEfBFs0skhjtk</span><span style="color: #33C7DE;"><strong>0BA</strong>trMgdWXM9Mfdgiq2awx6VAWCUUYCfjv1tdQqnjNc4eB-IOdBVA459uAFX2EGfdWWGp2OxxwbAutneudE9zYUBg</span>
</code>

The first red part is the TSP prefix. The purple part is the sender VID, the blue
part the receiver VID, the yellow is the ciphertext, and the cyan part is the signature.

The bold characters note the CESR selector of the part.

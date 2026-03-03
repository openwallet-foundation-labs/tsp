# Base mode

## Create a first identity

The `tsp` command line tool will store its wallet encrypted using [Askar](https://github.com/openwallet-foundation/askar) in the current directory. See the [custom secure storage](../custom-secure-storage.md) page for documentation about how to implement custom secure storage solutions.

<div class="warning">
The TSP command is used as an example and 'playground' to explore TSP, and as an
example for programmers on how to use the SDK to build TSP applications. It does not
expose all the functionality of the TSP SDK (e.g., TLS or QUICK transport), neither
should it used to build production applications.
</div>

To create a test `did:web` identity with the username `example` run the following command:

```sh
tsp create --type web example
```

Output:

```
INFO tsp: created new wallet
INFO tsp: created identity did:web:did.teaspoon.world:endpoint:example
```

**Note:** the DIDs need to be unique. You may need to use a different username if `example` already exist on the DID server.

We can add an alias to a VID using the --alias argument:

```sh
tsp create --type web example --alias example
```

In subsequent commands we can type `example` instead of `did:web:did.teaspoon.world:endpoint:example`.

Every `tsp` subcommand also supports the `--verbose` flag for a more verbose output:

```sh
tsp --verbose create --type web example --alias example
```

Output:

```
TRACE tsp: opened wallet wallet
 INFO tsp: added alias example -> did:web:did.teaspoon.world:endpoint:example
 INFO tsp: created identity did:web:did.teaspoon.world:endpoint:example
DEBUG tsp: DID server responded with status code 200 OK
TRACE tsp: published DID document for did:web:did.teaspoon.world:endpoint:example
TRACE tsp: persisted wallet
```

## Show wallet content

In some cases, it might be helpful to check what the wallet contains to understand the behavior of TSP.
Therefore, the CLI provides a `show` command.
The `tsp show local` command will print all the local VIDs stored in the wallet,
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

VIDs created with the `tsp` tool are published on **did.teaspoon.world** (unless you specify a different DID support server using the `--did-server` option).
Currently, Rust TSP is able to verify `did:webvh`, `did:web` and `did:peer` VIDs.

You can use the `tsp discover` command to discover DIDs that are hosted the DID server:

```sh
tsp discover
```

To resolve and verify a VID, run the following:

```sh
tsp verify did:web:did.teaspoon.world:endpoint:example
```

Output:

```
 INFO tsp: did:web:did.teaspoon.world:endpoint:example is verified and added to the wallet
```

The verify command also supports the alias argument:

```sh
tsp verify did:web:did.teaspoon.world:endpoint:example --alias example
```

## Send a message

For this example, we will create two identities with separate wallets - **alice** and **bob**.

You could perform the operations for **alice** and **bob** on different computers, for this example
we will separate them by using distinct wallets.

Use the `--wallet` flag to specify the file name of the wallet.

First create the identity for **alice**:

```sh
tsp --wallet alice create --type web alice --alias alice
```

Then create the identity for **bob**:

```sh
tsp --wallet bob create --type web bob --alias bob
```

Let **alice** verify **bob**'s VID and add it to the wallet `alice`:

```sh
tsp --wallet alice verify did:web:did.teaspoon.world:endpoint:bob --alias bob
```

Let **bob** verify **alice**'s VID and add it to the wallet `bob`:

```sh
tsp --wallet bob verify did:web:did.teaspoon.world:endpoint:alice --alias alice
```

Let **bob** start listening for a message:

```sh
tsp --wallet bob receive bob
```

Since the above command will block / wait for messages we should use
a new / different terminal to send the message from **alice**.

To send a message run the following:

```sh
echo "Hello Bob!" | tsp --wallet alice send --sender-vid alice --receiver-vid bob
```

Note that `alice` and `bob` are aliases of `did:web:did.teaspoon.world:endpoint:alice`
and `did:web:did.teaspoon.world:endpoint:bob`.

On the receiving side you should see:

```
 INFO tsp: received relationship request from did:web:did.teaspoon.world:endpoint:alice3, thread-id 'lrQoJ1qYIK6HEHZKvpq3p+it6djYE2YIe++5mqhASnE'
did:web:did.teaspoon.world:endpoint:alice3      lrQoJ1qYIK6HEHZKvpq3p+it6djYE2YIe++5mqhASnE
 INFO tsp: received confidential message (11 bytes) from did:web:did.teaspoon.world:endpoint:alice3 (HPKE ESSR, Ed25519 signature)
Hello Bob!
```

### Supported DID types

The TSP CLI example application supports two types of decentralized identifiers:

- `did:web`, created using `tsp create --type web`. These are resolved by finding a `.json` file on a server and checking its contents.
- `did:webvh`, created using `tsp create --type webvh`. These are resolved by finding a `.json` file on a server and checking its contents.
- `did:peer`, created using `tsp create --type peer`. These are essentially self-signed identifiers.

The TSP CLI can use two types of transport:

- `https`, which forces the use of a broadcast server application (see `server.rs`),
  but will work well across firewalls.

- `tcp`, which requires a direct network connection between two instances of the TSP CLI.
  In practice, you can use this only on a local network (or the same machine, if you use different ports), but
  this functionality is added to demonstrate the flexibility of having multiple transports.
  To use TCP transport, use the `--tcp address:port` flag to `tcp create`.

The TSP SDK also provides a couple more transport types and provides methods to use custom transport solutions (see [transport layers](../transport.md)), although these are not available through the CLI.

### Transport benchmark traffic (`bench`)

The CLI includes an `iperf`-like benchmark mode for sustained traffic tests.

Quick start:

```sh
tsp --wallet bob bench server
```

```sh
tsp --wallet alice bench client \
  --profile local-tcp \
  --payload-size 1KiB \
  --duration 30s
```

For profiles, HTTP baseline commands, latency mode, and output details, see
[Network Traffic Benchmark](../network-traffic-benchmark.md).

### Pretty print messages

The CLI has a `--verbose` flag.
For the `send` command, this will output the CESR-encoded TSP message that is sent.

Continuing with the **alice** and **bob** example:

```sh
echo "Hello Bob!" | tsp --verbose -w alice send -s alice -r bob
```

Output:

```
 INFO tsp::async_store: sending message to https://demo.teaspoon.world/endpoint/did:web:did.teaspoon.world:endpoint:bob
CESR-encoded message:
-EABXAAA9VIDAAALAAAZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjphbGljZQ8VIDAAAKAAZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjpib2I4CAX7ngr3YHl2z91L-anFBYxbQhM48CT_wqrCCRNdsN5fm-oshqvwqnKDK5rLkn_kvVI8aWZ7SEhiaiB8N6e-bjInrBbhNII0BAceo-mZoSvG3MY_UEqrgzP4kpeLJJK9MdQx53c4nxKh6_jvB2DuXJ6TBNjj-lXszyTH8yDAMSioDRluucSBpPAg
 INFO tsp: sent message (11 bytes) from did:web:did.teaspoon.world:endpoint:alice to did:web:did.teaspoon.world:endpoint:bob
```

In a terminal window supporting colors, this will look like the following:

<code style="display: block; line-break: anywhere; padding: 1rem;">
<strong style="color: #F66151;">-EABXAAA</strong><span style="color: #C061CB;"><strong>9VIDAAALAAA</strong>ZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjphbGljZQ</span><span style="color: #2A7BDE;"><strong>8VIDAAAKAA</strong>ZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjpib2I</span><span style="color: #E9AD0C;"><strong>4CAX</strong>5I7ozAGaFVqTxz8PJve0Tscor80fvds6hCf3yDUtOnHpXZ84uXFGXM-PcfLDWsRWvH7SoOG4UwQU8H-zEfBFs0skhjtk</span><span style="color: #33C7DE;"><strong>0BA</strong>trMgdWXM9Mfdgiq2awx6VAWCUUYCfjv1tdQqnjNc4eB-IOdBVA459uAFX2EGfdWWGp2OxxwbAutneudE9zYUBg</span>
</code>

The first red part is the TSP prefix. The purple part is the sender VID, the blue
part the receiver VID, the yellow is the ciphertext, and the cyan part is the signature.

The bold characters note the CESR selector of the part.

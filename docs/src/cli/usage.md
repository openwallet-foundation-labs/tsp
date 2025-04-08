# Usage

## Create a first identity

The `tsp` command line tool will store its state using the Aries-Askar interface
in a SQLite file in the current directory.

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
INFO tsp: created new database
INFO tsp: created identity did:web:did.teaspoon.world:user:example
```

**Note:** the DIDs need to be unique. If you try to create a user that already exists on did.teaspoon.world, you will get an error.

We can add an alias to a VID using the --alias argument:

```sh
tsp create example --alias example
```

In subsequent commands we can type `example` instead of `did:web:did.teaspoon.world:user:example`.

Every `tsp` subcommand also supports the `--verbose` or `-v` flag for a more
verbose output:

```sh
tsp --verbose create example
```

Output:
``` 
TRACE tsp: opened database database.sqlite
 INFO tsp: added alias example -> did:web:did.teaspoon.world:user:example
 INFO tsp: created identity did:web:did.teaspoon.world:user:example
TRACE tsp: published DID document to https://did.teaspoon.world/user/example/did.json
TRACE tsp: persisted database to database.sqlite
```

## Resolve a VID

VIDs created with the `tsp` tool are published on __did.teaspoon.world__.
Currently Rust TSP is able to verify `did:web` and `did:peer` VIDs

To resolve and verify a VID, run the following:

```sh
tsp verify did:web:did.teaspoon.world:user:example
```

Output:
```
 INFO tsp: did:web:did.teaspoon.world:user:example is verified and added to the database
```

The verify command also support the alias argument:

```sh
tsp verify did:web:did.teaspoon.world:user:example --alias example
```

## Send a message

For this example we will create two databases and identities - __alice__ and __bob__.

You could perform the operations for alice and bob on different computers, for this example
we will seperate them by using distinct databases.

Use the `--database` flag to specify the file name of the database.

First create the identity for __alice__:

```sh
tsp --database alice create alice --alias alice
```

Then create the identity for __bob__:

```sh
tsp --database bob create bob --alias bob
```

Let __alice__ verify __bob__'s VID and add it to the database `alice`:

```sh
tsp --database alice verify did:web:did.teaspoon.world:user:bob --alias bob
```

Let __bob__ verify __alice__'s VID and add it to the database `bob`:

```sh
tsp --database bob verify did:web:did.teaspoon.world:user:alice --alias alice
```

Let __bob__  start listening for a message:

```sh
tsp --database bob receive --one bob
```

The `--one` argument makes the command exit when the first message is received.

Since the above command will block / wait for a first message we should use
a new / different terminal to send the message from __alice__.

To send a message run the following:

```sh
echo "Hello Bob!" | tsp --database alice send --sender-vid alice --receiver-vid bob
```

Note that `alice` and `bob` are aliases of `did:web:did.teaspoon.world:user:alice`
and `did:web:did.teaspoon.world:user:bob`.

We can also use aliases for the argument, for example:

```sh
echo "Hello Bob!" | tsp -d alice send -s alice -r bob
```

In the other terminal window the message should appear:

```sh
tsp --database bob receive --one bob
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

The send command supports the `--pretty-print` argument.
This will output the CESR-encoded TSP message that is sent.

Continuing with the __alice__ and __bob__ example:

```sh
echo "Hello Bob!" | tsp --pretty-print -d alice send -s alice -r bob
```

Output:
```
 INFO tsp::async_store: sending message to https://demo.teaspoon.world/user/did:web:did.teaspoon.world:user:bob
CESR-encoded message:
-EABXAAA9VIDAAALAAAZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjphbGljZQ8VIDAAAKAAZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjpib2I4CAX7ngr3YHl2z91L-anFBYxbQhM48CT_wqrCCRNdsN5fm-oshqvwqnKDK5rLkn_kvVI8aWZ7SEhiaiB8N6e-bjInrBbhNII0BAceo-mZoSvG3MY_UEqrgzP4kpeLJJK9MdQx53c4nxKh6_jvB2DuXJ6TBNjj-lXszyTH8yDAMSioDRluucSBpPAg
 INFO tsp: sent message (11 bytes) from did:web:did.teaspoon.world:user:alice to did:web:did.teaspoon.world:user:bob
```

In a terminal window supporting colors this will look like the following:

<strong style="color:red">-EABXAAA</strong><span style="color:purple"><strong>9VIDAAALAAA</strong>ZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjphbGljZQ</span><span style="color:blue"><strong>8VIDAAAKAA</strong>ZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjpib2I</span><span style="color:yellow"><strong>4CAX</strong>5I7ozAGaFVqTxz8PJve0Tscor80fvds6hCf3yDUtOnHpXZ84uXFGXM-PcfLDWsRWvH7SoOG4UwQU8H-zEfBFs0skhjtk</span><span style="color:cyan"><strong>0BA</strong>trMgdWXM9Mfdgiq2awx6VAWCUUYCfjv1tdQqnjNc4eB-IOdBVA459uAFX2EGfdWWGp2OxxwbAutneudE9zYUBg</span>

The first red part is the TSP prefix. The purple part is the sender VID, the blue
part the receiver VID, the yellow is the ciphertext and the cyan part is the signature.

The bold characters note the CESR selector of the part.

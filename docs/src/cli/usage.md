# Usage

## Create a first identity

By default the `tsp` command line tool will store its state in a JSON file 
in the current directory.

<div class="warning">
Note that in a production (non-testing) setting this file should probably
be encrypted, since it contains private keys in plain-text. This tool
is intended for testing purposes only.
</div>

To create a test identity run the following command:

```sh
tsp create example
```

Output:
``` 
INFO tsp: created new database
INFO tsp: created identity did:web:tsp-test.org:user:example
```

We can add an alias to a VID using the --alias argument:

```sh
tsp create example --alias example
```

In subsequent commands we can type `example` instead of `did:web:tsp-test.org:user:example`.

Every `tsp` subcommand also supports the `--verbose` or `-v` flag for a more
verbose output:

```sh
tsp --verbose create example
```

Output:
``` 
TRACE tsp: opened database database.json
 INFO tsp: added alias example -> did:web:tsp-test.org:user:example
 INFO tsp: created identity did:web:tsp-test.org:user:example
TRACE tsp: published DID document to https://tsp-test.org/user/example/did.json
TRACE tsp: persisted database to database.json
```

## Resolve a VID

VIDs created with the `tsp` tool are published on __tsp-test.org__.
Currently Rust TSP is able to verify `did:web` and `did:peer` VIDs

To resolve and verify a VID, run the following:

```sh
tsp verify did:web:tsp-test.org:user:example
```

Output:
```
 INFO tsp: did:web:tsp-test.org:user:example is verified and added to database.json
```

The verify command also support the alias argument:

```sh
tsp verify did:web:tsp-test.org:user:example --alias example
```

## Send a message

For this example we will create two databases and identities - __alice__ and __bob__.

You could perform the operations for alice and bob on different computers, for this example
we will seperate them by using distinct databases.

Use the `--database` flag to specify the file name of the database.

First create the identity for __alice__:

```sh
tsp --database alice.json create alice --alias alice
```

Then create the identity for __bob__:

```sh
tsp --database bob.json create bob --alias bob
```

Let __alice__ verify __bob__'s VID and add it to the database `alice.json`:

```sh
tsp --database alice.json verify did:web:tsp-test.org:user:bob --alias bob
```

Let __bob__ verify __alice__'s VID and add it to the database `bob.json`:

```sh
tsp --database bob.json verify did:web:tsp-test.org:user:alice --alias alice
```

Let __bob__  start listening for a message:

```sh
tsp --database bob.json receive --one bob
```

The `--one` argument makes the command exit when the first message is received.

Since the above command will block / wait for a first message we should use
a new / different terminal to send the message from __alice__.

To send a message run the following:

```sh
echo "Hello Bob!" | tsp --database alice.json send --sender-vid alice --receiver-vid bob
```

Note that `alice` and `bob` are aliases of `did:web:tsp-test.org:user:alice`
and `did:web:tsp-test.org:user:bob`.

We can also use aliases for the argument, for example:

```sh
echo "Hello Bob!" | tsp -d alice.json send -s alice -r bob
```

In the other terminal window the message should appear:

```sh
tsp --database bob.json receive --one bob
```

```
 INFO tsp: listening for messages...
 INFO tsp: received message (11 bytes) from did:web:tsp-test.org:user:alice
Hello Bob!
```

### Pretty print messages

The send command supports the `--pretty-print` argument.
This wil output the CESR-encoded TSP mesage that is sent.

Continuing with the __alice__ and __bob__ example:

```sh
echo "Hello Bob!" | tsp --pretty-print -d alice.json send -s alice -r bob
```

Output:
```
 INFO tsp::async_store: sending message to https://tsp-test.org/user/bob
CESR-encoded message:
-EABXAAA9VIDAAALAAAZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjphbGljZQ8VIDAAAKAAZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjpib2I4CAX7ngr3YHl2z91L-anFBYxbQhM48CT_wqrCCRNdsN5fm-oshqvwqnKDK5rLkn_kvVI8aWZ7SEhiaiB8N6e-bjInrBbhNII0BAceo-mZoSvG3MY_UEqrgzP4kpeLJJK9MdQx53c4nxKh6_jvB2DuXJ6TBNjj-lXszyTH8yDAMSioDRluucSBpPAg
 INFO tsp: sent message (11 bytes) from did:web:tsp-test.org:user:alice to did:web:tsp-test.org:user:bob
```

In a terminal window supporting colors this will look like the following:

<strong style="color:red">-EABXAAA</strong><span style="color:purple"><strong>9VIDAAALAAA</strong>ZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjphbGljZQ</span><span style="color:blue"><strong>8VIDAAAKAA</strong>ZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjpib2I</span><span style="color:yellow"><strong>4CAX</strong>5I7ozAGaFVqTxz8PJve0Tscor80fvds6hCf3yDUtOnHpXZ84uXFGXM-PcfLDWsRWvH7SoOG4UwQU8H-zEfBFs0skhjtk</span><span style="color:cyan"><strong>0BA</strong>trMgdWXM9Mfdgiq2awx6VAWCUUYCfjv1tdQqnjNc4eB-IOdBVA459uAFX2EGfdWWGp2OxxwbAutneudE9zYUBg</span>

The first red part is the TSP prefix. The purple part is the sender VID, the blue
part the receiver VID, the yellow is the ciphertext and the cyan part is the signature.

The bold characters note the CESR selector of the part.

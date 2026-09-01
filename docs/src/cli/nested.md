# Nested mode

Over time, sustained message exchanges enable external observers to gather and analyze significant data.
To counter this threat, TSP provides a technique to encapsulate a specific conversation within an additional TSP envelope.

To try out TSP in nested mode, the command line interface can be used. A nested relationship can be set up by
exchanging relationship messages (the preferred way), but it can also be tested by manually
setting up identifiers, having both sides explicitly verify each other’s identities
and establishing a relationship between those identifiers.

If you want to create a second independent relationship via referral instead of a private inner relationship, see [Parallel relationships](./parallel.md).

Everything in this chapter runs on one machine and talks to no server: the identifiers are
`did:peer`, which are self-certifying, and the transport is TCP on localhost. Every line of
output below is from a real run, so you can follow along and compare — your identifiers will
differ, since each one is a hash of freshly generated keys.

## A note on the two forms of a `did:peer`

A `did:peer` has a **short form**, which is the identifier itself, and a **long form**, which is
the short form followed by the document holding its keys. The short form is a hash of that
document, so the long form can be checked against it and nothing has to be fetched.

Which form appears where matters when following the commands below:

- `tsp print` emits the **long form** — that is what you hand to someone who does not know the
  identifier yet, and it is what travels on the wire when a nested identity is introduced.
- `tsp verify` takes the long form, checks it, and stores the **short form**.
- Everything the CLI logs, and everything you pass to `accept` or `set-alias` afterwards, is the
  **short form**.

## Nested mode (using relationship control messages)

### Establishing an outer relationship

To send a nested TSP message, both sender and receiver should first establish a
direct relationship. This can be initiated by one party verifying the VID of the other
and sending a relationship request.

First create the two identities, each with its own wallet and its own TCP port:

```sh
> tsp -w alice create --type peer --tcp 127.0.0.1:5601 alice --alias alice
 INFO tsp: created peer identity did:peer:4zQmSf8cCgkfPZUrGZpkPkcwsHaubEmwduGzmBPXuq7HK2sN
 INFO tsp: created VID did:peer:4zQmSf8cCgkfPZUrGZpkPkcwsHaubEmwduGzmBPXuq7HK2sN
```

```sh
> tsp -w bob create --type peer --tcp 127.0.0.1:5602 bob --alias bob
 INFO tsp: created peer identity did:peer:4zQmdRKSG825qsPm24E7wxQKw3sD5e6oXwgGWsV9nRh9RUY7
 INFO tsp: created VID did:peer:4zQmdRKSG825qsPm24E7wxQKw3sD5e6oXwgGWsV9nRh9RUY7
```

Each has to learn about the other. `print` emits the long form, and `xargs` feeds it to `verify`:

```sh
> tsp -w bob print bob | xargs tsp -w alice verify --alias bob
 INFO tsp: did:peer:4zQmdRKSG825qsPm24E7wxQKw3sD5e6oXwgGWsV9nRh9RUY7:z2kCqs4oURbyPVxWvLGsQbAdjk8rSFaHh3WrHx3BhMyxctozJVLhk8RTXhxMySbJbzBktUG1A5NFknC4vtqSuS2XsU7uvAcHCqu8RpQ5xcQNHieTHAj6rN745QAfnjjzY4YTPBBiPJ8M2HDdPV8AWFuuYXXrAFvymCLkWgoVujXuqk2yTWeEGEat1fVaZioyT1YYQwxXZv3UzZeixFswr9x7dc313uzotpodPSyp8mvMnJcQTvftd2wn59LHjHyPoYPBTFbDQFNHWoemGmd1g9sUNC8jxgFBT4wwrGhwM8AKSDGQ6aZT2VtiNU7FPM4owCr1hVkC72h215SrpFLpsyKW5xL1S2LDmM6uogwVkLFMWxcnNscTy5FRxpKvKha1L7amGCCu5enw7QJtU1tdjdCkgJzKacsNJnBfZ8uQ5Uxb7W8z527ghRoSJHLnjkEydtwdNTrWVPSkiQbYnZmki2wofNEWiMDYmq4RkK2p1sRHp4a2dVS5kjTxuNBsfow8JwEoVcbB3NxfuZbZrymkom3EXXFQ2GFFqg1YpWqVbe1W9gt9NERaG1M3N8nbZm2pgc is verified and added to the wallet alice
```

```sh
> tsp -w alice print alice | xargs tsp -w bob verify --alias alice
 INFO tsp: did:peer:4zQmSf8cCgkfPZUrGZpkPkcwsHaubEmwduGzmBPXuq7HK2sN:z2kCqs4oURbyPVxWvLGsQbAdjk8rSFaHh3... is verified and added to the wallet bob
```

Then **alice** can send a relationship request. This requires **bob** to be listening, in a
separate window:

```sh
> tsp -w bob receive --one bob
 INFO tsp: listening for messages...
```

```sh
> tsp -w alice request --sender-vid alice --receiver-vid bob
 INFO tsp_sdk::async_store: sending message to tcp://127.0.0.1:5602
 INFO tsp: sent relationship request from alice to bob
```

On **bob**'s side, we will see:

```sh
 INFO tsp: received relationship request from did:peer:4zQmSf8cCgkfPZUrGZpkPkcwsHaubEmwduGzmBPXuq7HK2sN, thread-id 'TSWHY0oFR9pzecenLncuYgEoE6yfqctjO/GN1zOUCqk'
did:peer:4zQmSf8cCgkfPZUrGZpkPkcwsHaubEmwduGzmBPXuq7HK2sN	TSWHY0oFR9pzecenLncuYgEoE6yfqctjO/GN1zOUCqk
```

Notice how a thread-id was generated; we need this to confirm the relationship. This can be done
by sending a relationship acceptance message, which requires **alice** to be listening:

```sh
> tsp -w bob accept --sender-vid bob --receiver-vid alice --thread-id 'TSWHY0oFR9pzecenLncuYgEoE6yfqctjO/GN1zOUCqk'
 INFO tsp_sdk::async_store: sending message to tcp://127.0.0.1:5601
 INFO tsp: sent control message from bob to alice
```

On **alice**'s side, this will look like:

```sh
 INFO tsp: received accept relationship from did:peer:4zQmdRKSG825qsPm24E7wxQKw3sD5e6oXwgGWsV9nRh9RUY7
```

**alice** and **bob** now have a bidirectional relationship.

### Nesting the relationship

To establish the nested relationship follows the same procedure as above, except that the `request` and `accept` subcommands will
have to be passed the `--nested` parameter.

Let's say that **alice** again takes the initiative to nest the relationship, which starts the same as before:

```sh
> tsp -w alice request --nested --sender-vid alice --receiver-vid bob
 INFO tsp_sdk::async_store: sending message to tcp://127.0.0.1:5602
 INFO tsp: sent a nested relationship request to bob with new identity 'did:peer:4zQmQSZCofJmxYT4zZcR2fr46iKP1P2Dwx1UHdipC8Mv6T2t'
did:peer:4zQmQSZCofJmxYT4zZcR2fr46iKP1P2Dwx1UHdipC8Mv6T2t
 INFO tsp: sent relationship request from alice to bob
```

Notice that a new `did:peer` identifier was created, with its transport set to `tsp://`. The
identifier the CLI prints is the short form; the long form is what travelled inside the message,
so **bob** can check the keys without fetching anything.

On **bob**'s side, this message will appear:

```sh
> tsp -w bob receive --one bob
 INFO tsp: received nested relationship request from 'did:peer:4zQmQSZCofJmxYT4zZcR2fr46iKP1P2Dwx1UHdipC8Mv6T2t' (new identity for did:peer:4zQmSf8cCgkfPZUrGZpkPkcwsHaubEmwduGzmBPXuq7HK2sN), thread-id 'MJmu6JAfvGgFCp/2IpMYFKBJmKJI/GIuvlaJITAhudc'
did:peer:4zQmQSZCofJmxYT4zZcR2fr46iKP1P2Dwx1UHdipC8Mv6T2t	MJmu6JAfvGgFCp/2IpMYFKBJmKJI/GIuvlaJITAhudc
```

As before, **bob** can accept this using `tsp accept`:

```sh
> tsp -w bob accept --nested --sender-vid bob --receiver-vid did:peer:4zQmQSZCofJmxYT4zZcR2fr46iKP1P2Dwx1UHdipC8Mv6T2t --thread-id 'MJmu6JAfvGgFCp/2IpMYFKBJmKJI/GIuvlaJITAhudc'
 INFO tsp_sdk::async_store: sending message to tcp://127.0.0.1:5601
 INFO tsp: formed a nested relationship with did:peer:4zQmQSZCofJmxYT4zZcR2fr46iKP1P2Dwx1UHdipC8Mv6T2t with new identity 'did:peer:4zQmWtoqWaHFBJaZ5mY6oJczMTKfg7xtuTvo1Au5Nqt8iLff'
```

Instead of the `did:peer`, **bob** could also have used **alice**'s outer VID here. The TSP SDK will know which VID to use. Notice
how a new VID was also generated for **bob**. On **alice**'s side, this will look as follows:

```sh
 INFO tsp: received accept nested relationship from 'did:peer:4zQmWtoqWaHFBJaZ5mY6oJczMTKfg7xtuTvo1Au5Nqt8iLff' (new identity for did:peer:4zQmdRKSG825qsPm24E7wxQKw3sD5e6oXwgGWsV9nRh9RUY7)
did:peer:4zQmWtoqWaHFBJaZ5mY6oJczMTKfg7xtuTvo1Au5Nqt8iLff
```

Note that to make operation easier, we recommend using the alias mechanism to create better names for these essentially random inner identifiers:

```sh
> tsp -w alice set-alias inner_alice did:peer:4zQmQSZCofJmxYT4zZcR2fr46iKP1P2Dwx1UHdipC8Mv6T2t
 INFO tsp: added alias inner_alice -> did:peer:4zQmQSZCofJmxYT4zZcR2fr46iKP1P2Dwx1UHdipC8Mv6T2t
> tsp -w alice set-alias inner_bob did:peer:4zQmWtoqWaHFBJaZ5mY6oJczMTKfg7xtuTvo1Au5Nqt8iLff
 INFO tsp: added alias inner_bob -> did:peer:4zQmWtoqWaHFBJaZ5mY6oJczMTKfg7xtuTvo1Au5Nqt8iLff
```

And similarly for **bob**. Using these aliases, nested messages can simply be sent as for any other VID:

```sh
> echo "Hello Bob" | tsp -w alice send --sender-vid inner_alice --receiver-vid inner_bob
 INFO tsp_sdk::async_store: sending message to tcp://127.0.0.1:5602
 INFO tsp: sent message (10 bytes) from inner_alice to did:peer:4zQmWtoqWaHFBJaZ5mY6oJczMTKfg7xtuTvo1Au5Nqt8iLff
```

## Nested mode (manual setup)

To send a nested TSP message, both sender and receiver should
establish a pair of VIDs. One VID is used for the inner message and one for the outer.

This section starts over with fresh wallets, again `did:peer` over TCP on localhost:

```sh
> tsp -w alice create --type peer --tcp 127.0.0.1:6101 alice --alias alice
 INFO tsp: created peer identity did:peer:4zQme6haHzaq9px9yW1ZJ4R2XBLQMPSHxTHGTxCiUwGes1ih
> tsp -w bob create --type peer --tcp 127.0.0.1:6102 bob --alias bob
 INFO tsp: created peer identity did:peer:4zQmSHsbhkPa8EaHuJKvq9maPrny4DBb33WZ5Yo3rD1FocLE
> tsp -w bob print bob | xargs tsp -w alice verify --alias bob
> tsp -w alice print alice | xargs tsp -w bob verify --alias alice
```

First, we create an inner or nested VID for **alice**:

```sh
> tsp -w alice create --type peer --tcp 127.0.0.1:6103 alice-inner
 INFO tsp: created peer identity did:peer:4zQmZxraE9VfraPd5HygKsPyFV8xpXjsDvrzB7PjAYyq4BEd
 INFO tsp: created VID did:peer:4zQmZxraE9VfraPd5HygKsPyFV8xpXjsDvrzB7PjAYyq4BEd
```

This command creates a new identity and key material in the `did:peer` format.

The inner VID needs a transport of its own here, unlike in the control-message flow
above. In this manual setup the relationship between the inner VIDs is established
before either side knows they are nested, so that first `request` is delivered to the
inner VID directly. Once the parents are set, everything after it travels inside the
outer relationship and the inner transport is no longer used.

Next, we configure the newly created did:peer as a child of our main identity:

```sh
> tsp -w alice set-parent alice-inner alice
 INFO tsp: alice-inner is now a child of alice
```

We do the same for **bob**:

```sh
> tsp -w bob create --type peer --tcp 127.0.0.1:6104 bob-inner
 INFO tsp: created peer identity did:peer:4zQmRgud6TD55KTmw9zzoTECzq4c1HWMV8Qm6mB3W7Cu6BQi
 INFO tsp: created VID did:peer:4zQmRgud6TD55KTmw9zzoTECzq4c1HWMV8Qm6mB3W7Cu6BQi
```

```sh
> tsp -w bob set-parent bob-inner bob
 INFO tsp: bob-inner is now a child of bob
```

Next we resolve and verify **bob**'s inner VID. We use the `print` command to print
the long form of the VID and use `xargs` to feed the output as input for the `verify` command:

```sh
> tsp -w bob print bob-inner | xargs tsp -w alice verify --alias bob-inner
 INFO tsp: did:peer:4zQmRgud6TD55KTmw9zzoTECzq4c1HWMV8Qm6mB3W7Cu6BQi:z2kCqs4oURbyPVxWvLGsQbAdjk8rSFaHh3WrHx3BhMyxctozJVLhk8RTXhxMyS... is verified and added to the wallet alice
```

We do the same for the inner VID of **alice**:

```sh
> tsp -w alice print alice-inner | xargs tsp -w bob verify --alias alice-inner
 INFO tsp: did:peer:4zQmZxraE9VfraPd5HygKsPyFV8xpXjsDvrzB7PjAYyq4BEd:z2kCqs4oURbyPVxWvLGsQbAdjk8rSFaHh3WrHx3BhMyxctozJVLhk8RTXhxMyS... is verified and added to the wallet bob
```

We need to configure the association between **alice** and **bob**'s inner VIDs.
Use the `request` command to specify which VID should be used to send messages
a certain VID. **bob** should be listening on `bob-inner` for this one:

```sh
> tsp -w alice request --sender-vid alice-inner --receiver-vid bob-inner
 INFO tsp_sdk::async_store: sending message to tcp://127.0.0.1:6104
 INFO tsp: sent relationship request from alice-inner to bob-inner
```

Then set the parent/child relationship of **bob**'s VIDs in **alice**'s wallet:

```sh
> tsp -w alice set-parent bob-inner bob
 INFO tsp: bob-inner is now a child of bob
```

Now we are ready to send a nested message. From here on **bob** listens on his
*outer* VID, since that is what carries the traffic:

```sh
tsp -w bob receive --one bob
```

Then send a nested message from **alice**:

```sh
echo "Hi Bob!" | tsp --verbose -w alice send -s alice-inner -r bob-inner
```

Output:

```
 INFO tsp_sdk::async_store: sending message to tcp://127.0.0.1:6102
CESR-encoded message:
-EDDYTSP-AAB4BATZGlkOnBlZXI6NHpRbWU2aGFIemFxOXB4OXlXMVpKNFIyWEJMUU1QU0h4VEhHVHh
DaVV3R2VzMWlo4BATZGlkOnBlZXI6NHpRbVNIc2Joa1BhOEVhSHVKS3ZxOW1hUHJueTREQmIzM1daNV
lvM3JEMUZvY0xF4CCYIaGcjGW0_r-FnQf3FacIdOB64RtQ9M0Yzeew3bOqtkMBEMV5-EPhvvcRQJnt_
7xlGJpOV1o6j2E9RJFLVAN-FRtAW1rkkkFWQH8Htrtu-XnACFR2oEKutlwFp0a-71FaTeLNEXHPWS4x
yiflnmnYwH__BrGdPkfaDGyYoj2BljnIcKKvYxyVIu4GRrYEvub-74ZsnFwFqKsYZJ1mRRDltFenQy6
KICryOEMqpfL_wb4TXqJse2CFvNaNNwSdurZMjtNea7rURlAmEHoR9LJW3pUOhHnku3tA5MG23_dvYm
ZFUk0f_DJv4FVXc1rSRezhmcoIECqkO4NyJlhFKLuVvussxFsV8zHwur_uhw1yyhQOfxgbzIgVvKrPe
QPhGVW9pQ5lgvaU1uoCte6DUT10us9v8JOwfkYRw9lE018DfKDXJ7T5KWnwnxU_adB1jjMLY3zGjoNm
lvfjKTOxjcvsZ7vg912Yn8pqkfZdp3omlwy6ZjaA1M5dRNviiGPqZMAT9UHfY2TWR1yV4A_77fvUdyC
iqxuro8RjpGWRmMC7UE-qwjo_BcC9MUzpgn5nvMBtTkxxSiRdl8yoBrh123XF6gPoxQrr3Thx-CAX-K
AWBABQFxcRT1jHtL5TQFBZvmWSc8_CA1FQYvhS0RyWdlNz6jqY3KhyE0KLA24mMXKhAjU7omIuKb6V7
O8brgyEapQF
 INFO tsp: sent message (8 bytes) from alice-inner to did:peer:4zQmRgud6TD55KTmw9zzoTECzq4c1HWMV8Qm6mB3W7Cu6BQi
```

The outer envelope names the *outer* VIDs — `4zQme6ha…` sending to `4zQmSHsb…` — and the
whole nested message sits inside its ciphertext. An observer sees only that the two outer
identities exchanged something; the inner identities are not on the wire.

The output on **bob**'s end:

```
 INFO tsp: listening for messages...
 INFO tsp: received confidential message (8 bytes) from did:peer:4zQmZxraE9VfraPd5HygKsPyFV8xpXjsDvrzB7PjAYyq4BEd (Sealed Box, Ed25519 signature)
Hi Bob!
```

Both envelopes are encrypted: the outer one to **bob**, the inner one to `bob-inner`.
Section 4 does permit a signed-only inner message, since the outer envelope already
conceals it in transit — but then the inner payload's confidentiality rests on the
*outer* relationship's keys rather than the inner relationship's, so the SDK encrypts
by default.

A caller that wants the other behaviour asks for it explicitly. From the CLI:

```sh
> echo "Hi Bob!" | tsp -w alice send -s alice-inner -r bob-inner --confidentiality sign-only
```

which **bob** reports for what it is:

```
 INFO tsp: received confidential only within its enclosing message (8 bytes) from did:peer:4zQmZxraE9VfraPd5HygKsPyFV8xpXjsDvrzB7PjAYyq4BEd (signed only, enclosed in Sealed Box, Ed25519 signature)
Hi Bob!
```

Nothing went over the wire in the clear either way — the difference is *whose keys*
protect it. In Rust the same choice is `AsyncSecureStore::send_with_confidentiality`;
the Python and JavaScript bindings take an optional `confidentiality` argument on
`send`/`seal_message`, and report the enclosing type back as `enclosing_crypto_type`.

See [CESR encoding](../cesr.md) for what each code in the dump above means.

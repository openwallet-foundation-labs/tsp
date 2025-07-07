# Nested mode

To try out TSP in nested mode, the command line interface can be used. A nested relationship can be set up by
exchanging relationship messages (the preferred way), but it can also be tested by manually
setting up identifiers, having both sides explicitly verify each other’s identities
and establishing a relationship between those identifiers.

## Nested mode (using relationship control messages)

### Establishing an outer relationship

To send a nested TSP message, both sender and receiver should first establish a
direct relationship. This can be initiated by one party verifying the VID of the other
and sending a relationship request.

We use the same **alice** and **bob** aliases as in the previous chapter.

First, **alice** will have to learn about **bob**'s existence:

```sh
> tsp -w alice verify --alias bob did:web:did.teaspoon.world:endpoint:bob
 INFO tsp: did:web:did.teaspoon.world:endpoint:bob is verified and added to the wallet alice
```

Then she can send a relationship request message. This requires **bob** to be listening as
shown in the previous chapter (i.e., running `tsp -w bob receive bob` in a separate window):

```sh
> tsp -w alice request --sender-vid alice --receiver-vid bob --wait
 INFO tsp::async_store: sending message to https://did.teaspoon.world/endpoint/bob
 INFO tsp: sent relationship request from did:web:did.teaspoon.world:endpoint:alice to did:web:did.teaspoon.world:endpoint:bob, waiting for response...
```

On **bob**'s side, we will see:

```sh
> tsp -w bob receive --one bob
 INFO tsp: listening for messages...
 INFO tsp: received relationship request from did:web:did.teaspoon.world:endpoint:alice, thread-id 'JZla6+N6FP/In7ywOp8yQD2GfXemCn1e4b6tFVWaLxg'
```

Notice how a thread-id was generated; we need this to confirm the relationship. This can be done by sending a relationship acceptance message (this requires **alice** to be listening, which the CLI does automatically after sending a relationship request):

```sh
> tsp -w bob accept --sender-vid bob --receiver-vid alice --thread-id 'JZla6+N6FP/In7ywOp8yQD2GfXemCn1e4b6tFVWaLxg'
```

On **alice**'s side, this will look like:

```sh
 INFO tsp: received accept relationship from did:web:did.teaspoon.world:endpoint:bob
```

**alice** and **bob** now have a bidirectional relationship.

### Nesting the relationship

To establish the nested relationship follows the same procedure as above, except that the `request` and `accept` subcommands will
have to be passed the `--nested` parameter.

Let's say that **alice** again takes the initiative to nest the relationship, which starts the same as before:

```sh
> tsp -w alice request --nested --sender-vid alice --receiver-vid bob --wait
 INFO tsp: sent a nested relationship request to did:web:did.teaspoon.world:endpoint:bob with new identity 'did:peer:2.Vz6Mv3HRDr8nQ28LZxXHrU1zaUdXVJVjQzhuVcFB4pyF5rweQ.Ez6Lc6URPHMVN1vswnk32ND5zNcAb5o2QA1Hs4NThH2YzAuVL.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0'
```

Notice that a new `did:peer` identifier was created. This will have a transport set to `tsp://`. Let's create an alias for it:

On **bob**'s side, this message will appear:

```sh
> tsp -w bob receive bob --one
 INFO tsp: received nested relationship request from 'did:peer:2.Vz6Mv3HRDr8nQ28LZxXHrU1zaUdXVJVjQzhuVcFB4pyF5rweQ.Ez6Lc6URPHMVN1vswnk32ND5zNcAb5o2QA1Hs4NThH2YzAuVL.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0' (new identity for did:web:did.teaspoon.world:endpoint:alice), thread-id 'cR9RznAELgbp9XZ+VFFjq7vYv4v+ITaGrxa7L2ddCPw'
```

As before, **bob** can accept this using `tsp accept`:

```sh
> tsp -w bob accept --nested --sender-vid bob --receiver-vid did:peer:2.Vz6Mv3HRDr8nQ28LZxXHrU1zaUdXVJVjQzhuVcFB4pyF5rweQ.Ez6Lc6URPHMVN1vswnk32ND5zNcAb5o2QA1Hs4NThH2YzAuVL.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0 --thread-id 'cR9RznAELgbp9XZ+VFFjq7vYv4v+ITaGrxa7L2ddCPw'
 INFO tsp: formed a nested relationship with did:peer:2.Vz6Mv3HRDr8nQ28LZxXHrU1zaUdXVJVjQzhuVcFB4pyF5rweQ.Ez6Lc6URPHMVN1vswnk32ND5zNcAb5o2QA1Hs4NThH2YzAuVL.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0 with new identity 'did:peer:2.Vz6MuvAXTdNjiSV4DkbMUXAzShqiL2wvFNf2Dg4mr34JkQqk6.Ez6LbyVXwzoVNbRVm7X1Bpa4BqM5Aa5QYXyT4j6iRCxJAo4Fc.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0'
```

Instead of the `did:peer`, **bob** could also have used **alice**'s outer VID here. The TSP SDK will know which VID to use. Notice
how a new VID was also generated for **bob**. On **alice**'s side, this will look as follows:

```sh
 INFO tsp: received accept nested relationship from 'did:peer:2.Vz6MuvAXTdNjiSV4DkbMUXAzShqiL2wvFNf2Dg4mr34JkQqk6.Ez6LbyVXwzoVNbRVm7X1Bpa4BqM5Aa5QYXyT4j6iRCxJAo4Fc.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0' (new identity for did:web:did.teaspoon.world:endpoint:bob)
```

Note that to make operation easier, we recommend using the alias mechanism to create better names for these essentially random inner identifiers:

```sh
> tsp -w alice set-alias inner_alice did:peer:2.Vz6Mv3HRDr8nQ28LZxXHrU1zaUdXVJVjQzhuVcFB4pyF5rweQ.Ez6Lc6URPHMVN1vswnk32ND5zNcAb5o2QA1Hs4NThH2YzAuVL.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0
> tsp -w alice set-alias inner_bob did:peer:2.Vz6MuvAXTdNjiSV4DkbMUXAzShqiL2wvFNf2Dg4mr34JkQqk6.Ez6LbyVXwzoVNbRVm7X1Bpa4BqM5Aa5QYXyT4j6iRCxJAo4Fc.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0
```

And similarly for **bob**. Using these aliases, nested messages can simply be sent as for any other VID:

```sh
echo "Hello Bob" | tsp -w alice send --sender-vid inner_alice --receiver-vid inner_bob
```

## Nested mode (manual setup)

To send a nested TSP message, both sender and receiver should
establish a pair of VIDs. One VID is used for the inner message and one for the outer.

We use the same **alice** and **bob** example as in the previous chapter.

First, we create an inner or nested VID for **alice**:

```sh
tsp -w alice create --type peer alice-inner
```

Output:

```
 INFO tsp: created peer identity did:peer:2.Vz6Mv1MHPrewz2y6ntLZwbWdMc2C3Ny6Tk
 hA8mQouGsvNEgDK.Ez6Lbs5PeCs6VCbCjnPFV412nS3SDqjnHYB8sLB69XFQwUUkF.SeyJzIjp7In
 VyaSI6Imh0dHBzOi8vdHNwLXRlc3Qub3JnL3VzZXIvYWxpY2UtaW5uZXIifSwidCI6InRzcCJ9
```

This command creates a new identity and key material in the `did:peer` format.

Next, we configure the newly created did:peer as a child of our main identity:

```sh
tsp -w alice set-parent alice-inner alice
```

Output:

```
 INFO tsp: did:peer:2.Vz6MutdCU73wbCRc4Uypzg1a3gU5vAfwsLjHWbgArHzjqWzpw.Ez6Lbwx
 U56UYuE9EwTPgVJFX2nB3UcssbLk7nnrEF8qQNEZQv.SeyJzIjp7InVyaSI6Imh0dHBzOi8vdHNwLX
 Rlc3Qub3JnL3VzZXIvYWxpY2UtaW5uZXIifSwidCI6InRzcCJ9
 is now a child of did:web:did.teaspoon.world:endpoint:alice
```

We do the same for **bob**:

```sh
tsp -w bob create --type peer bob-inner
```

Output:

```
 INFO tsp: created peer identity did:peer:2.Vz6Mv49Sf4ui8iG5C7VTjMS2bXq7EZDhyK
 SDNbcQhcvUmGLLW.Ez6Lc2RywGrd9ARMmfLBGL3QFsoijt1PmYMMFrPRk6QMfwTEr.SeyJzIjp7In
 VyaSI6Imh0dHBzOi8vdHNwLXRlc3Qub3JnL3VzZXIvYm9iLWlubmVyIn0sInQiOiJ0c3AifQ
```

```sh
tsp -w bob set-parent bob-inner bob
```

Output:

```
 INFO tsp: did:peer:2.Vz6Mv49Sf4ui8iG5C7VTjMS2bXq7EZDhyKSDNbcQhcvUmGLLW.Ez6Lc2R
 ywGrd9ARMmfLBGL3QFsoijt1PmYMMFrPRk6QMfwTEr.SeyJzIjp7InVyaSI6Imh0dHBzOi8vdHNwLX
 Rlc3Qub3JnL3VzZXIvYm9iLWlubmVyIn0sInQiOiJ0c3AifQ
 is now a child of did:web:did.teaspoon.world:endpoint:bob
```

Next we resolve and verify **bob**'s inner VID. We use the `print` command to print
the full VID and use `xargs` to feed the output as input for the `verify` command:

```sh
tsp -w bob print bob-inner | xargs tsp -w alice verify --alias bob-inner
```

Output:

```
 INFO tsp: did:peer:2.Vz6Mv49Sf4ui8iG5C7VTjMS2bXq7EZDhyKSDNbcQhcvUmGLLW.Ez6Lc2
 RywGrd9ARMmfLBGL3QFsoijt1PmYMMFrPRk6QMfwTEr.SeyJzIjp7InVyaSI6Imh0dHBzOi8vdHNw
 LXRlc3Qub3JnL3VzZXIvYm9iLWlubmVyIn0sInQiOiJ0c3AifQ
 is verified and added to the wallet alice
```

We do the same for the inner VID of **alice**:

```sh
tsp -w alice print alice-inner | xargs tsp -w bob verify --alias alice-inner
```

Output:

```
 INFO tsp: did:peer:2.Vz6MutdCU73wbCRc4Uypzg1a3gU5vAfwsLjHWbgArHzjqWzpw.Ez6Lbw
 xU56UYuE9EwTPgVJFX2nB3UcssbLk7nnrEF8qQNEZQv.SeyJzIjp7InVyaSI6Imh0dHBzOi8vdHNw
 LXRlc3Qub3JnL3VzZXIvYWxpY2UtaW5uZXIifSwidCI6InRzcCJ9
 is verified and added to the wallet bob
```

We need to configure the association between **alice** and **bob**'s inner VIDs.
Use the `request` command to specify which VID should be used to send messages
a certain VID:

```sh
tsp -w alice request --sender-vid alice-inner --receiver-vid bob-inner
```

Then set the parent/child relationship of **bob**'s VIDs in **alice**'s wallet:

```sh
tsp -w alice set-parent bob-inner bob
```

Now we are ready to send a nested message. First start listening for messages from **bob**'s side:

```sh
tsp -w bob receive --one bob
```

Then send a nested message from **alice**:

```sh
echo "Hi Bob!" | tsp --verbose -w alice send -s alice-inner -r bob-inner
```

Output:

```
 INFO tsp::async_store: sending message to https://demo.teaspoon.world/endpoint/did:web:did.teaspoon.world:endpoint:bob
CESR-encoded message:
-EABXAAA9VIDAAALAAAZGlkOndlYjp0c3AtdGVzdC5vcmc6dXNlcjphbGljZQ8VIDAAAKAAZGlkOnd
lYjp0c3AtdGVzdC5vcmc6dXNlcjpib2I4CC2TF93f5Igkjgp4feBYOas18w-GhN_Q7oCRNStEbbdVK
aN7Uqr2DK3-A3xf7b9px6KchftsEsIx7AM2fVO1V4KJ8OixmVPoPK59q9TpoioCiL2XmmZLT3Gj4X0
MIbYCIyJWSBQNwVyH3h434Ja86xSx8rR87H48sX9MtKSgRwkP_iU4FiJOzg27vIUVtzLZacp2Bwvti
p_WATvkQm4uecQwb-0dCpC8x_TjDyyARLglahjQrz2DPImn-_UzJKZqv1kqLKTED0dD-7WqOtY-1Ll
gasteOVKQlH6DtcvNPqUCWnZJtT0vJvpVpogeQ_5Ky_WdPRflUOyic4lE93lbDgPWxGdZ5Qnu8lTG3
XntZMCLh95r89hr6oTMJwQoWdlS0NEH-UEQt2NLxeYwXH_rG0uoZW2k4YC1PvmJ5zdAhW721IkSuKg
y0STK0eDk4q0EZagBn4iFUnye1m34TZb5F7hmzVmNolhgojXmPmT9PdC8a90Z6c-AS9xYHVZHkUjF2
gYPuYHu6RdKJ8fT2OZJ_hbfBXeYHA6-hloFBHqLMShCGFZKrY6uw6dWZ6DB96WRa0ubakV3fDDNyLu
Rol52q133vSkgspyN7hYEtUEojnOyrOVsX8yrVoONHxCZ-3g1oe6LJNnLC8CxmF2n1-WQgvaQBwj3Q
a8EQDX0n2VWnhG0xWZeclCG54qJSC6YEiNS1XGfe6m2ZFEWqmLZDmr1PbxhO4m0BA9BEqEHLumN0cx
ip0iXo-yHjrA5EP_ka8Y4pkQdTpr5yJZJqHjyThVwgvbbQX9ORRND-qV6Tl0MRcJ8lTWAhbDw
 INFO tsp: sent message (8 bytes) from did:peer:2.Vz6MutdCU73wbCRc4Uypzg1a3gU5
 vAfwsLjHWbgArHzjqWzpw.Ez6LbwxU56UYuE9EwTPgVJFX2nB3UcssbLk7nnrEF8qQNEZQv.SeyJz
 Ijp7InVyaSI6Imh0dHBzOi8vdHNwLXRlc3Qub3JnL3VzZXIvYWxpY2UtaW5uZXIifSwidCI6InRzc
 CJ9 to did:peer:2.Vz6Mv49Sf4ui8iG5C7VTjMS2bXq7EZDhyKSDNbcQhcvUmGLLW.Ez6Lc2Ryw
 Grd9ARMmfLBGL3QFsoijt1PmYMMFrPRk6QMfwTEr.SeyJzIjp7InVyaSI6Imh0dHBzOi8vdHNwLXR
 lc3Qub3JnL3VzZXIvYm9iLWlubmVyIn0sInQiOiJ0c3AifQ
```

The output on **bob**'s end:

```
 INFO tsp: listening for messages...
 INFO tsp: received message (8 bytes) from did:peer:2.Vz6MutdCU73wbCRc4Uypzg1a3
 gU5vAfwsLjHWbgArHzjqWzpw.Ez6LbwxU56UYuE9EwTPgVJFX2nB3UcssbLk7nnrEF8qQNEZQv.Sey
 JzIjp7InVyaSI6Imh0dHBzOi8vdHNwLXRlc3Qub3JnL3VzZXIvYWxpY2UtaW5uZXIifSwidCI6InRz
 cCJ9
Hi Bob!
```

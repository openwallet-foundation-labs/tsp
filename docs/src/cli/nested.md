# Nested mode

To send a nested TSP message both sender and and receiver should
establish a pair of VIDs. One VID is used for the inner message and one for the outer.

We use the same __alice__ and __bob__ example as in the previous chapter.

First, we create an inner or nested VID for __alice__:

```sh
tsp -d alice.json create-peer alice-inner
```

Output:
```
 INFO tsp: created peer identity did:peer:2.Vz6Mv1MHPrewz2y6ntLZwbWdMc2C3Ny6Tk
 hA8mQouGsvNEgDK.Ez6Lbs5PeCs6VCbCjnPFV412nS3SDqjnHYB8sLB69XFQwUUkF.SeyJzIjp7In
 VyaSI6Imh0dHBzOi8vdHNwLXRlc3Qub3JnL3VzZXIvYWxpY2UtaW5uZXIifSwidCI6InRzcCJ9
```

The `create-peer` command creates a new identity and key m,aterial in the `did:peer` format.

Next we configure the newly created did:peer as a child of our main identity:

```sh
tsp -d alice.json set-parent alice-inner alice
```

Output:
```
 INFO tsp: did:peer:2.Vz6MutdCU73wbCRc4Uypzg1a3gU5vAfwsLjHWbgArHzjqWzpw.Ez6Lbwx
 U56UYuE9EwTPgVJFX2nB3UcssbLk7nnrEF8qQNEZQv.SeyJzIjp7InVyaSI6Imh0dHBzOi8vdHNwLX
 Rlc3Qub3JnL3VzZXIvYWxpY2UtaW5uZXIifSwidCI6InRzcCJ9
 is now a child of did:web:tsp-test.org:user:alice
```

We do the same for __bob__:


```sh
tsp -d bob.json create-peer bob-inner
```

Output:
```
 INFO tsp: created peer identity did:peer:2.Vz6Mv49Sf4ui8iG5C7VTjMS2bXq7EZDhyK
 SDNbcQhcvUmGLLW.Ez6Lc2RywGrd9ARMmfLBGL3QFsoijt1PmYMMFrPRk6QMfwTEr.SeyJzIjp7In
 VyaSI6Imh0dHBzOi8vdHNwLXRlc3Qub3JnL3VzZXIvYm9iLWlubmVyIn0sInQiOiJ0c3AifQ
```

```sh
tsp -d bob.json set-parent bob-inner bob
```

Output:
```
 INFO tsp: did:peer:2.Vz6Mv49Sf4ui8iG5C7VTjMS2bXq7EZDhyKSDNbcQhcvUmGLLW.Ez6Lc2R
 ywGrd9ARMmfLBGL3QFsoijt1PmYMMFrPRk6QMfwTEr.SeyJzIjp7InVyaSI6Imh0dHBzOi8vdHNwLX
 Rlc3Qub3JnL3VzZXIvYm9iLWlubmVyIn0sInQiOiJ0c3AifQ
 is now a child of did:web:tsp-test.org:user:bob
```

Next we resolve and verify __bob__'s inner VID. We use the `print` command to print
the full VID and use `xargs` to feed the output as input for the `verify` command:

```sh
tsp -d bob.json print bob-inner | xargs tsp -d alice.json verify --alias bob-inner
```

Output:
```
 INFO tsp: did:peer:2.Vz6Mv49Sf4ui8iG5C7VTjMS2bXq7EZDhyKSDNbcQhcvUmGLLW.Ez6Lc2
 RywGrd9ARMmfLBGL3QFsoijt1PmYMMFrPRk6QMfwTEr.SeyJzIjp7InVyaSI6Imh0dHBzOi8vdHNw
 LXRlc3Qub3JnL3VzZXIvYm9iLWlubmVyIn0sInQiOiJ0c3AifQ
 is verified and added to the database alice.json
```

We do the same for the inner VID of __alice__:

```sh
tsp -d alice.json print alice-inner | xargs tsp -d bob.json verify --alias alice-inner
```

Output:
```
 INFO tsp: did:peer:2.Vz6MutdCU73wbCRc4Uypzg1a3gU5vAfwsLjHWbgArHzjqWzpw.Ez6Lbw
 xU56UYuE9EwTPgVJFX2nB3UcssbLk7nnrEF8qQNEZQv.SeyJzIjp7InVyaSI6Imh0dHBzOi8vdHNw
 LXRlc3Qub3JnL3VzZXIvYWxpY2UtaW5uZXIifSwidCI6InRzcCJ9
 is verified and added to the database bob.json
```

We need to configure the association between __alice__ and __bob__'s inner VIDs.
Use the `set-relation` command to soecify which VID should be used to send messages
a certain VID:

```sh
tsp -d alice.json set-relation bob-inner alice-inner
```

Then set the parent/child relationship of __bob__'s VIDs in __alice__'s database:

```sh
tsp -d alice.json set-parent bob-inner bob
```

Now we are ready to send a nested message. First start listening for messages from __bob__'s side:

```sh
tsp -d bob.json receive --one bob
```

Then send a nested message from __alice__:

```sh
echo "Hi Bob!" | tsp --pretty-print -d alice.json send -s alice-inner -r bob-inner
```

Output:
```
 INFO tsp::async_store: sending message to https://tsp-test.org/user/bob
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

The output on __bob__'s end:
```
 INFO tsp: listening for messages...
 INFO tsp: received message (8 bytes) from did:peer:2.Vz6MutdCU73wbCRc4Uypzg1a3
 gU5vAfwsLjHWbgArHzjqWzpw.Ez6LbwxU56UYuE9EwTPgVJFX2nB3UcssbLk7nnrEF8qQNEZQv.Sey
 JzIjp7InVyaSI6Imh0dHBzOi8vdHNwLXRlc3Qub3JnL3VzZXIvYWxpY2UtaW5uZXIifSwidCI6InRz
 cCJ9
Hi Bob!
```

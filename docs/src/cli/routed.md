# Routed mode

Like nested mode, routed mode can be set up by exchanging relationship messages between every hop in the node (for the most part), or more manually. Here, we will assume a setup with four nodes: a sender `a`, receiver `b`, and two intermediaries `p` and `q`.

In this document, we will use the CLI to simulate intermediaries. We also have a stand-alone example [intermediary server](../intermediary.md), which we will discuss in the next chapter.

## Routed mode (semi-automated set up)

To set up routed mode, the four nodes need to establish bidirectional outer relationships with each other using `tsp request` and
`tsp accept`, as shown in the chapter on nested mode. We will not repeat instructions on how to do that here and assume that all the one-to-one relationships have already
been formed.

What is special about routed mode, is that the final hop node `q`, needs to have a special VID (say `q2`) that is dedicated to sending
messages to the final recipient `b`. This can be achieved in two ways:

- Establishing a nested relationship between `q` and `b`, and then using the inner VID for `q` as the final hop. Nested relationships always have a "relation vid".
- Explicitly creating a separate public identity for the node `q` that is verified by `b` and has `b` as its "relation vid":

  ```sh
  > tsp -w q create --alias q2 q2
  > tsp -w q request --sender q2 --receiver b
  ```

When this set up is done, the only thing left to send a routed message from `a` to `b`, is to set up a route.

```sh
tsp -w a set-route b VID-FOR-P,VID-FOR-Q,VID-FOR-B2
```

The last entry is the *exit* of the route: `b`'s own VID at its intermediary `q`, not a VID of `q` itself
(spec 5.3.3). `q` delivers the message over the relationship it holds with that VID, which is how it knows
where the last hop goes.

Note, this requires `a` to have verified the VID of `p`, but it does not need to have verified the VID's `q` or `b2`. In fact, if
the VID `b2` is an inner vid for a nested relationship, `a` will not have a way to verify it at all.

When this route is set up properly, sending a message proceeds as normal:

```sh
echo "Routed Hello" | tsp -w a send --sender-vid a --receiver-vid b
```

## Routed mode (manual set up)

Routed mode is a bit more involved than direct or nested mode. We need to
set up correctly configured intermediary servers.

In this example we use preconfigured intermediaries from `teaspoon.world` instead of using the TSP CLI itself for the intermediaries.
We will use intermediaries `p` and `q` to send a message from `a` to `b`.
Here's an overview of what this looks like:

```
┌────────────────┐   ┌────────────────┐
│                │   │                │
│ Intermediary P ├──►│ Intermediary Q │
│                │   │                │
└────────────────┘   └────────┬───────┘
        ▲                     │
        │                     ▼
┌───────┴────────┐   ┌────────────────┐
│                │   │                │
│ A (sender)     │   │ B (receiver)   │
│                │   │                │
└────────────────┘   └────────────────┘
```

## Set up sender and receiver identities

Let's create two identities `a` and `b` such that `a` talks through intermediary `p` and `b` talks through intermediary `q`. The `--server` determines which server the clients use for transport:

```sh
tsp -w a --server p.teaspoon.world create a --type web --alias a
tsp -w b --server q.teaspoon.world create b --type web --alias b
```

You may need to use different usernames if `a` and/or `b` already exist on the DID server.

## Introduce the nodes to each other

The sender `a` resolves and verifies the receiver `b`:

```sh
tsp -w b print b | xargs tsp -w a verify --alias b
```

The sender `a` also resolves and verifies the first intermediary `p`, and requests a relationship with this intermediary:

```sh
tsp -w a verify did:web:p.teaspoon.world --alias p
tsp -w a request -s a -r p --wait
```

Our public demo intermediaries are configured to accept all incoming relationship requests.

The receiver `b` resolves and verifies the second intermediary `q`, and requests a relationship with this second intermediary:

```sh
tsp -w b verify did:web:q.teaspoon.world --alias q
tsp -w b request -s b -r q --wait
```

In order for the final drop-off to work, `b` needs to set up a nested relation with `q`, otherwise `q` would have no way of knowing were to deliver the message to in the last hop. The following command will read the nested DIDs into the bash environment variables `DID_B2` and `DID_Q2`:

```sh
read -d '' DID_B2 DID_Q2 <<< $(tsp -w b request --nested -s b -r q --wait)
echo "DID_B2=$DID_B2"
echo "DID_Q2=$DID_Q2"
```

## Send a message

Now that we have set up all the relations between the nodes, we can configure the route for messages that are to be delivered from `a` to `b`. We will route these messages via `p` to `q`, which drops them off at `b`'s nested VID `b2`:

```sh
tsp -w a set-route b "p,did:web:q.teaspoon.world,$DID_B2"
```

Sending the routed message is trivial, now we have configured the relations and route.

Let `b` listen for messages:

```sh
tsp -w b receive b
```

Let `a` sent a message:

```sh
echo "Hi b" | tsp --verbose -w a send -s a -r b
```

Output:

```
 INFO tsp_sdk::async_store: sending message to https://p.teaspoon.world/transport/did:web:p.teaspoon.world
CESR-encoded message:
-ECiYTSP-AAB6BANAABkaWQ6d2ViOmRpZC50ZWFzcG9vbi53b3JsZDplbmRwb2ludDph4BAIZGlkOndl
YjpwLnRlYXNwb29uLndvcmxk4CCI7rByvLY3ruvS_0J0wMsydnS4WLvcDQ1HCGvWZ5ZAMCvtif8mXl8C
owc1FxO2apuxgZVmEipiHBsITKQTH4VS7t7uSqtC_1OHC9OqIxsRS-zLtl00z_RvSpXSgws0pxE7-XdA
ZL0TVPpVIDjp3WvDUNnq5f7cyfHTX7N1GYA9SQy8chq4u3WBMK6PXDa7aaqQHq6rKDnpJuFljELjtmyb
6Zd8UoP3Gveag4Gq0TZXjwwZC_Nc9YkXlyCRnDknyxmDL_jncdM2V5SXOsHuS46NCH84YIF39SZ8GASZ
06YT_p8OY7HdlFgNeos_d7ltbXypofgVvHUwnqhJ6uYhpBJZeo_TIHIZbLEi1tx1qM3irQ0wNCL0tYgb
L7JUrOGGHatMbxz6DsJhVnRuZmN5DkymcNHuQEgJOpfCYNNPMUpymWC9G0d3gOo7IH0WymBYQ_ECkqeS
G-FbyxKTYowbFSHjbPiLmhWcFQyijLMXPyXoVABOXWIDvPBeG6gYHNC7xMSN8KrZ_MPbNjCrJw3U6VJp
hVFBzlLcvM78-CAX-KAWBABQ-d-4uoXxQruPS04SQ1hb7BBGs_vD7kp_ueCKw2dcE3ZCbv08tp-5jEOP
vSatyQTOK98eaauxqKZ5ybAfNpMI
 INFO tsp: sent message (5 bytes) from did:web:did.teaspoon.world:endpoint:a to did:web:did.teaspoon.world:endpoint:b
```

Note that the message is longer than a direct mode message, since the ciphertext contains another
TSP message.

Note also who the envelope names. `VID_sndr` is `a` and `VID_rcvr` is the *first intermediary*,
`did:web:p.teaspoon.world` — not `b`. The rest of the route and the message for `b` are inside the
ciphertext, which `p` decrypts to learn only the next hop and an opaque blob to forward. No
intermediary sees the message, and none of them sees the whole route. See
[CESR encoding](../cesr.md) for the codes.

The `cli-demo-routed-external.sh` script in the `examples/` folder performs all the previously described steps automatically. One small difference is that in the script `a` and `b` use <https://demo.teaspoon.world/> for transport, while the identities from the step-by-step tutorial above are configured to use intermediaries directly.

## Debug intermediaries

The example intermediary servers `p` and `q` maintain a brief log of recent events,
see <https://p.teaspoon.world/> and <https://q.teaspoon.world/> after sending a routed message.

See also the documentation for [intermediary servers](../intermediary.md).

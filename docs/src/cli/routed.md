# Routed mode

Like nested mode, routed mode can be set up by exchanging relationship messages between every hop in the node (for the most part), or more manually. Here, we will assume a setup with four nodes: a sender `a`, receiver `b`, and two intermediaries `p` and `q`.

In this document, we will use the CLI to simulate intermediaries. We also have a stand-alone example [intermediary server](../intermediary.md), which we will discuss in the next chapter.


## Routed mode (semi-automated set up)

To set up routed mode, the four nodes need to establish bidirectional outer relationships with each other using `tsp request` and
`tsp accept`, as shown in the chapter on nested mode. We will not repeat instructions on how to do that here and assume that all the one-to-one relationships have already
been formed.

What is special about routed mode, is that the final hop node `q`, needs to have a special VID (say `q2`) that is dedicated to sending
messages to the final recipient `b`. This can be achieved in two ways:

* Establishing a nested relationship between `q` and `b`, and then using the inner VID for `q` as the final hop. Nested relationships always have a "relation vid".
* Explicitly creating a separate public identity for the node `q` that is verified by `b` and has `b` as its "relation vid":

  ```sh
  > tsp -d q create --alias q2 q2
  > tsp -d q set-relation q2 b
  ```

When this set up is done, the only thing left to send a routed message from `a` to `b`, is to set up a route.

```sh
tsp -d a set-route b VID-FOR-P,VID-FOR-Q,VID-FOR-Q2
```
Note, this requires `a` to have verified the VID of `p`, but it does not need to have verified the VID's `q` or `q2`. In fact, if
the VID `q2` is an inner vid for a nested relationship, `a` will not have a way to verify it at all.

When this route is set up properly, sending a message proceeds as normal:
```sh
echo "Routed Hello" | tsp -d a send --sender-vid a --receiver-vid b
```

## Routed mode (manual set up)

Routed mode is a bit more involved than direct or nested mode. We need to
set up correctly configured intermediary servers.

In this example we use preconfigured identities and intermediaries from `teaspoon.world` instead of using the TSP CLI itself for the intermediaries.

We will use intermediaries `p` and `q` to send a message from `a` to `b`.
The key material for these can be found in the Rust TSP repository.

Overview:

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

Download key material for `a` and `b`:

```sh
curl -s https://raw.githubusercontent.com/openwallet-foundation-labs/tsp/main/examples/test/a/piv.json > identity-a.json
curl -s https://raw.githubusercontent.com/openwallet-foundation-labs/tsp/main/examples/test/b/piv.json > identity-b.json
```

Create a new identity (and database) for `a` based on the downloaded file using the `create-from-file` command:

```sh
tsp -d a create-from-file --alias a ./identity-a.json
```

And we also initialize `b`:

```sh
tsp -d b create-from-file --alias b ./identity-b.json
```

## Introduce the nodes to each other

The sender `a` resolves and verifies the receiver `b`:
```sh
tsp -d b print b | xargs tsp -d a verify --alias b
```

The sender `a` also resolves and verifies the first intermediary `p`, and requests a relationship with this intermediary:
```sh
tsp -d a verify did:web:p.teaspoon.world --alias p
tsp -d a request -s a -r p
```

Our public demo intermediaries are configured to accept all incoming relationship requests.

> Note that instead of requesting a relationship with `p`, `a` could also only set the relationship for itself, as for this example only one-way communication from `a` to `p` is needed.
> Passing the `--sender` argument configures which sender VID is used when sending messages to the passed VID. This is equivalent with an extra call to the `set-relation` command.
> So, instead of the previous two commands, you could also do the following instead:
> ```
> tsp -d a verify did:web:p.teaspoon.world --alias p --sender a
> ```

The receiver `b` resolves and verifies the second intermediary `q`, and requests a relationship with this second intermediary:
```sh
tsp -d b verify did:web:q.teaspoon.world --alias q
tsp -d b request -s b -r q
```

In order for the final drop-off to work, `b` needs to set up a nested relation with `q`, otherwise `q` would have no way of knowing were to deliver the message to in the last hop. The following command will read the nested DIDs into the bash environment variables `DID_B2` and `DID_Q2`:
```sh
read -d '' DID_B2 DID_Q2 <<< $(tsp -d b request --nested -s b -r q)
echo "DID_B2=$DID_B2"
echo "DID_Q2=$DID_Q2"
```

## Send a message

Now that we have set up all the relations between the nodes, we can configure the route for messages that are to be delivered from `a` to `b`. We will route these messages via `p` to `q`, and then `q2` will drop it off at `b`:
```sh
tsp -d a set-route b "p,did:web:q.teaspoon.world,$DID_Q2"
```

Sending the routed message is trivial, now we have configured the relations and route.

Let `b` listen for one message:

```sh
tsp -d b receive --one b
```

Let `a` sent a message:

```sh
echo "Hi b" | tsp --pretty-print -d a send -s a -r b
```

Output:
```
 INFO tsp::async_store: sending message to https://p.teaspoon.world/transport/did:web:p.teaspoon.world
CESR-encoded message:
-EABXAAA9VIDAAALAAAZGlkOndlYjpkaWQudHNwLXRlc3Qub3JnOnVzZXI6YQ9VIDAAALAAAZGlkOn
dlYjpkaWQudHNwLXRlc3Qub3JnOnVzZXI6cA4CB2WE2d08bhGjkJJUg3la1JbsK7apfaOSxH-otajv
YveQ093-rTQWvq3kUJokCH7dT_5gbIzJdDsLxTYDu6dz4IyJhGg6JzCpqrerG5GwMaoICtJGn9wPGN
WjJHuSzBoqdKY3OQpsGolHh03aenVrREZ0aqjn_z3cczWxBRhUiUCjtlTmbEZEMmCdqSdB50erIZd3
Vj0-mCA0-PKSa_Ij-IsX9S1HbXtitZftxIRpSqnuEOS0doudXWWKNhehLWteUTDPnjn11JpVJmfKEE
jvY1-qx5gmUmpG3zAS054q0YSIJWFB9t22LWp80n7HXjEKnm8WcQF4O9GmRWmYe_LR46-2JC_u9Yux
UXnZVrnUiGAq-xK331yfRd0X58M0B2d4qRrZMjfFvBFt5CGbp3WvYvynNLOM6NA3wp2j2Dy6B1FIBs
2rAnMfYR2wzSmwYQcbGOvRok4pdg9rI1EGPPgUKcRuoB0BA4XLvi8Yw-webwWRLW0GA7jNTfNSdmAm
sd_mGJp4hkMz_P9-R04we14TOl-v8dvCuOjcp_UIDrB-vjeAwqzyNBw
 INFO tsp: sent message (5 bytes) from did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a
 to did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b
```

Note that the message is longer than a direct mode message, since the ciphertext contains another
TSP message.

The `cli-demo-routed-external.sh` script in the `examples/` folder performs all the previously described steps automatically, but using random usernames for easy testing. 

## Debug intermediaries

The example intermediary servers `p` and `q` maintain a brief log of recent events,
see <https://p.teaspoon.world/> and <https://q.teaspoon.world/> after sending a routed message.

See also the documentation for [intermediary servers](../intermediary.md).

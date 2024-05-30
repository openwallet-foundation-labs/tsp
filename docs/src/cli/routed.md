# Routed mode

Routed mode is a bit more involved than direct or nested mode. We need to
setup correctly configured intermediary servers.

In this example we use preconfigured identities and intermediaries from `tsp-test.org`.

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

## Download key material for `a` and `b`:

```sh
curl -s https://raw.githubusercontent.com/wenjing/rust-tsp/main/examples/test/a.json > identity-a.json
curl -s https://raw.githubusercontent.com/wenjing/rust-tsp/main/examples/test/b.json > identity-b.json
```

## Configuration

Create a new identity (and database) for `a` based on the downloaded file using the
`create-from-file` command:

```sh
tsp -d a.json create-from-file --alias a ./identity-a.json
```

We also initialize `b`:

```sh
tsp -d b.json create-from-file --alias b ./identity-b.json
```

Resolve and verify the VID for `a` in the database for `b`:

```sh
tsp -d a.json print a | xargs tsp -d b.json verify --alias a
```

Resolve and verify the VID for `b` in the database for `a`,
and verify the VIDs for the intermediary servers `p` and `q`:

```sh
tsp -d b.json print b | xargs tsp -d a.json verify --alias b
tsp -d b.json verify did:web:did.tsp-test.org:user:q --alias q
```

Verify the VIDs foure the intermediaries and the endpoint.
Passing the `--sender` argument configures which sender VID is used when sending
messages to the passed VID. This is equivalent with an extra call to the `set-relation`
command.

```sh
tsp -d a.json verify did:web:did.tsp-test.org:user:p --alias p --sender a
tsp -d a.json verify did:web:did.tsp-test.org:user:b --alias b --sender a
tsp -d a.json verify did:web:did.tsp-test.org:user:q --alias q
tsp -d a.json set-route b p,q,q
```

The `set-route` command configures the route for the VID aliased by `b`.
Note that the last hop in the route, `q`, in practice should be VID that the intermediary
obnly uses to communicate with the receiver (`b`). For the sake of simplicity
we configured the intermediary `q` with a VID that is also configured as the
sender VID when communication with the VID of `b`.

## Send a message

Sending the routed message is trivial, now we have configured the relations and route.

Let `b` listen for one message:

```sh
tsp -d b.json receive --one b
```

Let `a` sent a message:

```sh
echo "Hi b" | tsp --pretty-print -d a.json send -s a -r b
```

Output:
```
 INFO tsp::async_store: sending message to https://p.tsp-test.org/transport/p
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
 INFO tsp: sent message (5 bytes) from did:web:did.tsp-test.org:user:a
 to did:web:did.tsp-test.org:user:b
```

Note that the message is longer than a direct mode message, since the ciphertext contains another
TSP message.

## Debug intermediaries

The example intermediary servers `p` and `q` maintain a brief log of recent messages,
see [https://p.tsp-test.org/](https://p.tsp-test.org/) and [https://q.tsp-test.org/](https://q.tsp-test.org/)
after sending a routed message.

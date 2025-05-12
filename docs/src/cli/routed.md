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
  > tsp -w q create --alias q2 q2
  > tsp -w q request --sender q2 --receiver b
  ```

When this set up is done, the only thing left to send a routed message from `a` to `b`, is to set up a route.

```sh
tsp -w a set-route b VID-FOR-P,VID-FOR-Q,VID-FOR-Q2
```
Note, this requires `a` to have verified the VID of `p`, but it does not need to have verified the VID's `q` or `q2`. In fact, if
the VID `q2` is an inner vid for a nested relationship, `a` will not have a way to verify it at all.

When this route is set up properly, sending a message proceeds as normal:
```sh
echo "Routed Hello" | tsp -w a send --sender-vid a --receiver-vid b
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

Create a new identity (and wallet) for `a` based on the downloaded file using the `import-piv` command:

```sh
tsp -w a import-piv --alias a ./identity-a.json
```

And we also initialize `b`:

```sh
tsp -w b import-piv --alias b ./identity-b.json
```

Note that this way of importing private VIDs is only meant for demo purposes to quickly set up some identities. As these identities are publicly available from our GitHub repository, any communication done with these identities is inherently unsafe as the key pairs publicly available. In practice, you would want to create new endpoints with their own private key pairs.

## Introduce the nodes to each other

The sender `a` resolves and verifies the receiver `b`:
```sh
tsp -w b print b | xargs tsp -w a verify --alias b
```

The sender `a` also resolves and verifies the first intermediary `p`:
```sh
tsp -w a verify did:web:p.teaspoon.world --alias p
```

Our public demo intermediaries are configured to accept all incoming relationship requests.

The receiver `b` resolves and verifies the second intermediary `q`, and requests a relationship with this second intermediary:
```sh
tsp -w b verify did:web:q.teaspoon.world --alias q
```

In order for the final drop-off to work, `b` needs to set up a nested relation with `q`, otherwise `q` would have no way of knowing were to deliver the message to in the last hop. The following command will read the nested DIDs into the bash environment variables `DID_B2` and `DID_Q2`:
```sh
read -d '' DID_B2 DID_Q2 <<< $(tsp -w b request --nested -s b -r q)
echo "DID_B2=$DID_B2"
echo "DID_Q2=$DID_Q2"
```

## Send a message

Now that we have set up all the relations between the nodes, we can configure the route for messages that are to be delivered from `a` to `b`. We will route these messages via `p` to `q`, and then `q2` will drop it off at `b`:
```sh
tsp -w a set-route b "p,did:web:q.teaspoon.world,$DID_Q2"
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
 INFO tsp::async_store: sending message to https://p.teaspoon.world/transport/did:
 web:p.teaspoon.world
CESR-encoded message:
-EABXAAAXAEB9VIDAAAdAAAZGlkOndlYjpyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tOm9wZW53YWxsZXQ
tZm91bmRhdGlvbi1sYWJzOnRzcDptYWluOmV4YW1wbGVzOnRlc3Q6YQ7VIDAAAIZGlkOndlYjpwLnRlYXN
wb29uLndvcmxk4CDBRPjQTLqVsN-QrMR5eVGgSO0Q6V491-GKJP7imcKJheAT1_madw21FHK49oJvINRYt
1GZX4dtZGCC5gB1EZCLZpqQJjzeuwQavXYUFBY3z3ygNw-780r4fltOtjVG0hybe8Y5YOf4rv1U_xD-Ajm
xbw7rOlJq7AWojJq2FbWQ6Ho2z90KUwQ8ki-hyYCE1woCDM1TAQu3Pvt8XsrRqr5TpeExIlh1Jx_vlt-rW
Dny4nbBv7SWHEovVBT7XXtVPWpEnBiBzm2mBsJ5CZsDy-EjXVONCEadUwDwwYaU8djEYt8pBHag8IGlpVZ
IUN2dtZyFhRKmvq7FsEcqSCpiSZR7jXiHNjghqUCBFwAIqwnAr1npW15fg7lREpiLTkcs8oSSZvmEhLaFT
BvhnhFvCzTP-CckvhFXOsUpK7Q5u3KBRFReEQYb32CfEq44yaKRVUAVknXJmS_HBOWv-VbnbgR-8q8TL5z
h2rOH2pGM8sQVlweWBg32JmACWzdOw2jCF17Ey4AYFQkYbiz8extJuAxg22aoE30azL-RU0I0bGW-ZCqLx
mK8jLH_zoYZ35nTQfwZYlFfe-cbempzw9gS685RloYBSKq9kdPIsV7h3DW-vBwEP6_ttaS024F2ZW90KMq
vQ3pRNr5pjmxWshlerIBjRcpTO7IjIYN6jU1Vg8-akcukC0J8vu8GJYZhu5n16DYAAcqQkmKmsTBD8OirJ
FldrEVWc1F5Bu0zd3FJuYq7K5OdQgw4JFrRPUgeVNIRCsdElnQP0BAYPtmDPJDfhx_-ab02_y2yD1FrhXE
SrBAkd6evt2M2Z2ugVyVwxTU-pVVXlcTa5p_-N05lWEZ0bdUBdR4upMUDA
 INFO tsp: sent message (5 bytes) fromdid:web:raw.githubusercontent.com:openwallet
 -foundation-labs:tsp:main:examples:test:a to did:web:raw.githubusercontent.com:
 openwallet-foundation-labs:tsp:main:examples:test:b
```

Note that the message is longer than a direct mode message, since the ciphertext contains another
TSP message.

The `cli-demo-routed-external.sh` script in the `examples/` folder performs all the previously described steps automatically, but using endpoints created on the teaspoon.world DID support server for easy testing. The only difference here is thus that in the script `a` and `b` use <https://demo.teaspoon.world/> for transport, while the identities from the step-by-step tutorial above are configured to use intermediaries directly.

## Debug intermediaries

The example intermediary servers `p` and `q` maintain a brief log of recent events,
see <https://p.teaspoon.world/> and <https://q.teaspoon.world/> after sending a routed message.

See also the documentation for [intermediary servers](../intermediary.md).

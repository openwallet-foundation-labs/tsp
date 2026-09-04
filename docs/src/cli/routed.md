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
tsp -w a --server p.teaspoon.world create a --type webvh --alias a
tsp -w b --server q.teaspoon.world create b --type webvh --alias b
```

You may need to use different usernames if `a` and/or `b` already exist on the DID server.

## Introduce the nodes to each other

The sender `a` resolves and verifies the receiver `b`:

```sh
tsp -w b print b | xargs tsp -w a verify --alias b
```

The sender `a` also resolves and verifies the first intermediary `p`, and requests a relationship with this intermediary:

Each intermediary publishes its own identifier on its home page, so read them from there rather
than copying them from here:

```sh
DID_P=  # the identifier shown at https://p.teaspoon.world/
DID_Q=  # the identifier shown at https://q.teaspoon.world/
```

```sh
tsp -w a verify "$DID_P" --alias p
tsp -w a request -s a -r p --wait
```

Our public demo intermediaries are configured to accept all incoming relationship requests.

The receiver `b` resolves and verifies the second intermediary `q`, and requests a relationship with this second intermediary:

```sh
tsp -w b verify "$DID_Q" --alias q
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
tsp -w a set-route b "p,$DID_Q,$DID_B2"
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
 INFO tsp_sdk::async_store: sending message to https://p.teaspoon.world/transport/did:webvh:QmX22wdsvULMiphZeHpZmdTJN82CobY7NJGWDpCCwyfjYw:did.teaspoon.world:endpoint:p
CESR-encoded message:
-EELYTSP-ABA6BAfAABkaWQ6d2Vidmg6UW1QYlc1QjlScE5QOGsyR0M0dkJzY2JkY3ZUVEJheFFS
a0w5ZUI1Mm5vYXdxZDpkaWQudGVhc3Bvb24ud29ybGQ6ZW5kcG9pbnQ6YTI2NTA05BAdAGRpZDp3
ZWJ2aDpRbVgyMndkc3ZVTE1pcGhaZUhwWm1kVEpOODJDb2JZN05KR1dEcENDd3lmall3OmRpZC50
ZWFzcG9vbi53b3JsZDplbmRwb2ludDpw4FDKcwGDfgH_B13GJM1-ZojR0xhP1uJXlMHvvKMHdPQy
bAP_I3cIC8wqKBZZRORNEnKNrecNPoCPw6rQlIO1_3Q0HSkCLYUj1Lj_OXMnSVJwaMnNEHnwfTw0
rpEBztCXFHzu18jCUpNFFgeApI_V2wYfw9zzV8McH7HPIu6U94xdvr-
kAwizSa9yZbOa99ibbRZwk1Bctd8Wv-5IqIaHgiYlNXROfXEJb6Q2pbhXTF11zF8SNcw-
NtsfuL4OFL69xBN6zwNqyBppcRRYVkSoal47XcziAMXlVijCeI1ZIOokRFmTKyC9ci80yGM-OI78
LQv2qxFOw631ZFbqLTA_O7xPGK-4IaTYFhWuMc6tpMK85Pyk1FO_9WON1WuYraegNkRjnOG8hYj_
iZLH5XKkJ12zGYvTdHJXyWUuM3TsavUC3U5NxFXA52b34GaaMawwNbFhBjtMBeYvLcKbwFwm5AQZ
b-H_dWs5sBIvm5cc_sdYyPfjOVnD-YXlbxwU0pSsSEGQ-sDBD9wcXXZdmJJ7zK944wMnaTf4QdLx
iSDTOaxd6Qp7VG84OcJkXWdt32tFvGwDHguE1AXMUv3ZgieZupSJQ5cyyMl8dHhcXKI9sEjaLDOP
-mBl473sIdlYU1ME-mYMugGaCZDr3SUohNSjucoawBSYjkiX9CzWG-4ahGjfAxnQn0taZQKyQLhC
N4J-wpUc02XlBXccW2ha-7v42jHP7Z1ydCgGYMmZKFsk-
Elgljie7-cQFCmQq30rSq1QFoizYo1XLSKwTblypAFDb3e_CmHgfgQQBwtgKunXv7c8-CAX-KAWB
AAlI7CsBCHc88Q-LAXoRNK5v-oeZ8wrlCP14wKCinJRg29vn4mCdZROTyYy0390Lv5ORP6kS6NDH
yZA6OMz-RkL
 INFO tsp_sdk::async_store: sending message to https://p.teaspoon.world/transport/did:webvh:QmX22wdsvULMiphZeHpZmdTJN82CobY7NJGWDpCCwyfjYw:did.teaspoon.world:endpoint:p
CESR-encoded message:
-ED8YTSP-ABA6BAfAABkaWQ6d2Vidmg6UW1QYlc1QjlScE5QOGsyR0M0dkJzY2JkY3ZUVEJheFFS
a0w5ZUI1Mm5vYXdxZDpkaWQudGVhc3Bvb24ud29ybGQ6ZW5kcG9pbnQ6YTI2NTA05BAdAGRpZDp3
ZWJ2aDpRbVgyMndkc3ZVTE1pcGhaZUhwWm1kVEpOODJDb2JZN05KR1dEcENDd3lmall3OmRpZC50
ZWFzcG9vbi53b3JsZDplbmRwb2ludDpw4FC7YRJ3CANvrxtL2ECeimpjhsAeAr75wT56O7PDR2CH
hWhs7y_98vQAZ1MOfovWhjf7dbga9Dyoslf9txL9q7yL_SUjinoaNfbtJJQGLB35YJAfAbunjtE5
aguBp43xj-p_kA_qkD0O9g9Oeo5bt-
WDv_szkU3dES2-3V2drH8QfutvS1SYM7fW7MX0s7Yo_mIvWTjArqUKVtMag4AmIvg-b10Y58dd-
aelx1GkDraIGxoNG5rjk7fFxeT8vl74ZDNQ0mQD8qlvldfhKao7S__A0YqJJwulZszK7vx_Q-Ruw
chXMNn6hFdrbeSj8bm_yV_4YAW6Ei3rY53_i3wjE1iqt7MFwflTDL0S2znpvfsEk8R7GyuNIAJNR
R2qsEXtjzp_yI9_kaI5JQRLSCxaS1ex272j2XPrskLTgU40xHiJPzh0xX675Pq_pBjzwYW3gcTtG
mYJem_TWOTGfIMXb_7PlLXqofQMluY2PzFUMDc5vi7IgHeKSbB8sc2wGnGayDbtWNoVrixkjZ_7v
ANRgxPAh3v7fJB0wYd6jHThLBcUCiUM2rnIcgpXTgwresE2JSgSiF29phD903HpUuTLxPIqyBofL
KHjfAenxw86giaSeVVnFwApAyHTT78DFtX1PCTeCcxq2R6wjAj7wt16XcQuiarA4WHDXPQJbfiIr
27EttugHQSxgQJVLMfWfJPRocPvfCQQgdeNYP2wC2u6zyNyzma24svBDGSPFYHsWBYPLWci-CAX-
KAWBACDd8jOnlMxXSiC0I7uKho-DwPccSjE3aeC9v4vdRCD6i_e5ql-ol7WOnsHif3eEqFK-
MJyY_zq4knF6-LTvIcD
 INFO tsp: sent message (5 bytes) from a to did:webvh:QmcLEZ4R1BUCeE1B7XaStqeLDySeJXzc82AfvpHVkFFYYo:did.teaspoon.world:endpoint:b28527
```

Two messages go out, not one. `a` has no relationship with `b` yet, so the first is a
relationship request, routed through `p` like everything else — asking for a relationship does
not disclose the endpoint the route exists to hide. The second is the message itself.

Note that the message is longer than a direct mode message, since the ciphertext contains another
TSP message.

Note also who the envelope names. `VID_sndr` is `a` and `VID_rcvr` is the *first intermediary* —
not `b`. The rest of the route and the message for `b` are inside the
ciphertext, which `p` decrypts to learn only the next hop and an opaque blob to forward. No
intermediary sees the message, and none of them sees the whole route. See
[CESR encoding](../cesr.md) for the codes.

The `cli-demo-routed-external.sh` script in the `examples/` folder performs all the previously described steps automatically. One small difference is that in the script `a` and `b` use <https://demo.teaspoon.world/> for transport, while the identities from the step-by-step tutorial above are configured to use intermediaries directly.

## Debug intermediaries

The example intermediary servers `p` and `q` maintain a brief log of recent events,
see <https://p.teaspoon.world/> and <https://q.teaspoon.world/> after sending a routed message.

See also the documentation for [intermediary servers](../intermediary.md).

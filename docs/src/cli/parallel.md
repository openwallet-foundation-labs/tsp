# Parallel relationships

Parallel relationship forming uses an existing bidirectional relationship as a referral to create a second relationship with a new VID pair.
This follows the "Parallel Relationship Forming" flow in the
[Trust Spanning Protocol specification](https://trustoverip.github.io/tswg-tsp-specification/).

Compared with [nested mode](./nested.md), the new VIDs are not coupled as inner VIDs of the outer relationship.
Use a parallel relationship when you want a second, separately addressable relationship, typically with a new directly reachable VID.

## Current CLI scope

The Rust SDK can both send and receive parallel relationship control messages.
The CLI currently supports:

- initiating a parallel relationship request with `tsp request --parallel --new-vid ...`
- receiving a parallel relationship request
- verifying the referred `new_vid`
- accepting the request with `tsp accept --parallel`

## Initiating a parallel relationship request

Assume **alice** and **bob** already have an outer bidirectional relationship, for example with the aliases `alice` and `bob`.
Before sending the request, **alice** creates or imports the local VID she wants to use for the new parallel relationship.
For example:

```sh
> tsp -w alice create --type web alice-alt --alias alice-alt
 INFO tsp: created identity did:web:did.teaspoon.world:endpoint:alice-alt
```

Now **alice** can initiate the referral:

```sh
> tsp -w alice request --parallel --sender-vid alice --receiver-vid bob --new-vid alice-alt --wait
 INFO tsp: sent a parallel relationship request from did:web:did.teaspoon.world:endpoint:alice to did:web:did.teaspoon.world:endpoint:bob with new identity 'alice-alt'
 INFO tsp: sent relationship request from did:web:did.teaspoon.world:endpoint:alice to did:web:did.teaspoon.world:endpoint:bob
 INFO tsp: waiting for response...
```

When `--wait` is present, the CLI listens on the proposed `new_vid`, because the corresponding `TSP_RFA` is returned over the new relationship.

## Accepting a parallel relationship request

Assume **alice** sent the request above and introduced the new VID `alice-alt`.

On **bob**'s side, listen on the outer relationship:

```sh
> tsp -w bob receive --one bob
 INFO tsp: listening for messages...
 INFO tsp: received parallel relationship request for 'did:web:did.teaspoon.world:endpoint:alice-alt' from did:web:did.teaspoon.world:endpoint:alice
 did:web:did.teaspoon.world:endpoint:alice-alt    JZla6+N6FP/In7ywOp8yQD2GfXemCn1e4b6tFVWaLxg
 INFO tsp: did:web:did.teaspoon.world:endpoint:alice-alt is verified and added to the wallet bob
```

The CLI prints two fields separated by a tab:

- the referred `new_vid`
- the `thread_id` that must be echoed in the accept message

Before accepting, **bob** needs a local VID for the new parallel relationship.
In practice this should usually be a directly reachable VID, such as a `did:web` or `did:webvh` identity:

```sh
> tsp -w bob create --type web bob-alt --alias bob-alt
 INFO tsp: created identity did:web:did.teaspoon.world:endpoint:bob-alt
```

Now **bob** can accept the referred relationship:

```sh
> tsp -w bob accept --parallel --sender-vid bob-alt --receiver-vid did:web:did.teaspoon.world:endpoint:alice-alt --thread-id 'JZla6+N6FP/In7ywOp8yQD2GfXemCn1e4b6tFVWaLxg'
 INFO tsp: sent control message from did:web:did.teaspoon.world:endpoint:bob-alt to did:web:did.teaspoon.world:endpoint:alice-alt
```

When **alice** receives the acceptance, the CLI will report the new remote VID:

```sh
 INFO tsp: received accept relationship from did:web:did.teaspoon.world:endpoint:bob (nested_vid: none, parallel_vid: did:web:did.teaspoon.world:endpoint:bob-alt)
 did:web:did.teaspoon.world:endpoint:bob-alt
```

At that point the new VID pair forms its own bidirectional relationship, separate from the outer one that was used as the referral.

## Notes

- The outer relationship must already be bidirectional before a parallel relationship can be formed.
- `tsp accept --parallel` uses the new local VID as the sender and the referred remote VID as the receiver.
- The original outer relationship remains in place after the new parallel relationship is established.

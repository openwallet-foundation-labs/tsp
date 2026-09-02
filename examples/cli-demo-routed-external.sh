#!/bin/bash

# this scripts sends a routed message from a -> p -> q -> q2 -> b
# where p and q run using the intermediary server on Google Cloud:
#
# https://p.teaspoon.world/
# https://q.teaspoon.world/

# install using default NaCl + ESSR build
cargo install --path . || exit 1

randuser() {
    head -c4 /dev/urandom | shasum | head -c8
}

echo "---- cleanup the wallet"
rm -f a.sqlite b.sqlite

echo
echo "==== create sender and receiver"
for entity in a b; do
	echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:web"
	tsp --wallet "${entity%%[0-9]*}" create --type web --alias $entity `randuser`
done
DID_A=$(tsp --wallet a print a)
# The intermediaries publish their own identifiers, so read them rather than hard-coding them:
# a did:webvh identifier is derived from its genesis log entry and is not predictable from the
# domain, and it changes if an intermediary is ever re-created.
did_of() {
	curl -s "https://did.teaspoon.world/endpoint/$1/did.json" \
		| grep -o '"id":"did:webvh:[^"]*"' | head -1 | cut -d'"' -f4
}
DID_P=$(did_of p)
DID_Q=$(did_of q)
DID_B=$(tsp --wallet b print b)

wait
sleep 5
echo
echo "==== let the nodes introduce each other"

echo "---- verify the address of the receiver"
tsp --wallet a verify --alias b "$DID_B"

echo "---- establish outer relation a<->p"
tsp --wallet a verify --alias p "$DID_P"
sleep 2 && tsp --wallet a request --wait -s a -r p

echo "---- establish outer relation q<->b"
tsp --wallet b verify --alias q "$DID_Q"
sleep 2 && tsp --wallet b request --wait -s b -r q

echo "---- establish nested outer relation q<->b" # required for drop-off
sleep 2 && read -d '' DID_B2 DID_Q2 <<< $(tsp --wallet b request --wait --nested -s b -r q)

echo "DID_B2=$DID_B2"
echo "DID_Q2=$DID_Q2"

echo "---- setup the route"
# the exit entry of the hop list is b's own VID at q (spec 5.3.3)
tsp --wallet a set-route b "p,$DID_Q,$DID_B2"

wait
sleep 5
echo
echo "==== send a routed message"

sleep 2 && echo -n "Indirect Message from A to B via P and Q was received!" | tsp --wallet a send -s a -r b &
tsp --yes --wallet b receive b &

# wait for message to be received
sleep 4

echo "---- cleanup wallets"
rm -f a.sqlite b.sqlite

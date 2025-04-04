#!/bin/bash

# this scripts sends a routed message from a -> p -> q -> q2 -> b
# where p and q run using the intermediary server on Google Cloud:
#
# https://p.teaspoon.world/
# https://q.teaspoon.world/

cargo install --path .

randuser() {
    head -c4 /dev/urandom | shasum | head -c8
}

echo "---- cleanup the database"
rm -f a.sqlite b.sqlite

echo
echo "==== create sender and receiver"
for entity in a b; do
	echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:web"
	tsp --database "${entity%%[0-9]*}" create --alias $entity `randuser`
done
DID_A=$(tsp --database a print a)
DID_P="did:web:p.teaspoon.world"
DID_Q="did:web:q.teaspoon.world"
DID_B=$(tsp --database b print b)

wait
sleep 5
echo
echo "==== let the nodes introduce each other"

echo "---- verify the address of the receiver"
tsp --database a verify --alias b "$DID_B"

echo "---- establish outer relation a<->p"
tsp --database a verify --alias p "$DID_P"
sleep 2 && tsp --database a request -s a -r p

echo "---- establish outer relation q<->b"
tsp --database b verify --alias q "$DID_Q"
sleep 2 && tsp --database b request -s b -r q

echo "---- establish nested outer relation q<->b" # required for drop-off
sleep 2 && read -d '' DID_B2 DID_Q2 <<< $(tsp --database b request --nested -s b -r q)

echo "DID_B2=$DID_B2"
echo "DID_Q2=$DID_Q2"

echo "---- setup the route"
tsp --database a set-route b "p,$DID_Q,$DID_Q2"

wait
sleep 5
echo
echo "==== send a routed message"

sleep 2 && echo -n "Indirect Message from A to B via P and Q was received!" | tsp --database a send -s a -r b &
tsp --yes --database b receive --one b

echo "---- cleanup databases"
rm -f a.sqlite b.sqlite

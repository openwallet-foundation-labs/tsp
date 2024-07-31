#!/bin/bash

# install using
cargo install --path .

randuser() {
    head -c4 /dev/urandom | shasum | head -c8
}

cointoss() {
    (( $RANDOM % 2 ))
}

echo "---- cleanup the database"
rm -f marlon.sqlite marc.sqlite p.sqlite q.sqlite

echo "---- create sender, receiver, and intermediaries"

for entity in marlon p q q2 marc; do
    if cointoss; then
	echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:web"
	tsp --database "${entity%%[0-9]*}" create --alias $entity `randuser`
    else
	if cointoss; then
	    echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:peer with https:// transport"
	    tsp --database "${entity%%[0-9]*}" create-peer $entity
	else
	    echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:peer with local transport"
	    port=$((RANDOM % 1000 + 1000))
	    tsp --database "${entity%%[0-9]*}" create-peer --tcp localhost:$port $entity
	fi
    fi
done
DID_MARLON=$(tsp --database marlon print marlon)
DID_P=$(tsp --database p print p)
DID_Q=$(tsp --database q print q)
DID_Q2=$(tsp --database q print q2)
DID_MARC=$(tsp --database marc print marc)

echo "---- verify the address of the receiver"
tsp --database marlon verify --alias marc "$DID_MARC"

echo "---- establish outer relation a<->p"
tsp --database marlon verify --alias p "$DID_P"

sleep 2 && tsp --database marlon request -s marlon -r p &
received=$(tsp --yes --database p receive --one p)
vid=$(echo "$received" | cut -f1)
thread_id=$(echo "$received" | cut -f2)

tsp --database p set-alias marlon "$vid"
sleep 2 && tsp --database p accept -s p -r marlon --thread-id "$thread_id" &
tsp --database marlon receive --one marlon

echo "---- establish outer relation p<->q"
tsp --database q verify --alias p "$DID_P"

sleep 2 && tsp --database q request -s q -r p &
received=$(tsp --yes --database p receive --one p)
vid=$(echo "$received" | cut -f1)
thread_id=$(echo "$received" | cut -f2)
tsp --database p set-alias q "$vid"

sleep 2 && tsp --database p accept -s p -r q --thread-id "$thread_id" &
tsp --database q receive --one q

echo "---- establish outer relation q2<->b"
tsp --database marc verify --alias q2 "$DID_Q2"

sleep 2 && tsp --database marc request -s marc -r q2 &
received=$(tsp --yes --database q receive --one q2)
vid=$(echo "$received" | cut -f1)
thread_id=$(echo "$received" | cut -f2)
tsp --database q set-alias marc "$vid"

sleep 2 && tsp --database q accept -s q2 -r marc --thread-id "$thread_id" &
tsp --database marc receive --one marc

echo "---- setup the route"
tsp --database marlon set-route marc "p,$DID_Q,$DID_Q2"
tsp --database marlon set-relation marc marlon
tsp --database marlon set-relation p marlon

tsp --database p set-relation q p
tsp --database q set-relation q2 marc

echo "---- send a routed message"

sleep 2 && echo -n "Indirect Message from Marlon to Marc was received!" | tsp --database marlon send -s marlon -r marc &
tsp --yes --database p receive --one p &
tsp --yes --database q receive --one q &
tsp --yes --database marc receive --one marc

echo "---- cleanup databases"
rm -f marlon.sqlite marc.sqlite p.sqlite q.sqlite

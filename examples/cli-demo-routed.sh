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
rm -f a.sqlite b.sqlite p.sqlite q.sqlite

echo
echo "==== create sender, receiver, and intermediaries"

if cointoss; then
    echo "------ drop off vid (q2) will be a public vid"
    Q2=q2
else
    echo "------ drop off vid will be a nested vid (out-of-band)"
fi

for entity in a p q $Q2 b; do
    if cointoss; then
	echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:web"
	tsp --database "${entity%%[0-9]*}" create --alias $entity `randuser`
    else
	if cointoss; then
	    echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:peer with https:// transport"
	    tsp --database "${entity%%[0-9]*}" create-peer $entity
	else
	    echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:peer with local transport"
	    port=$((${port:-1024} + RANDOM % 1000))
	    tsp --database "${entity%%[0-9]*}" create-peer --tcp localhost:$port $entity
	fi
    fi
done
DID_A=$(tsp --database a print a)
DID_P=$(tsp --database p print p)
DID_Q=$(tsp --database q print q)
[ "$Q2" ] && DID_Q2=$(tsp --database q print q2)
DID_B=$(tsp --database b print b)

wait
sleep 5
echo
echo "==== let the nodes introduce each other"

echo "---- verify the address of the receiver"
tsp --database a verify --alias b "$DID_B"

echo "---- establish outer relation a<->p"
tsp --database a verify --alias p "$DID_P"

sleep 2 && tsp --database a request -s a -r p &
read -d '\t' vid thread_id <<< $(tsp --yes --database p receive --one p)

tsp --database p set-alias a "$vid"
sleep 2 && tsp --database p accept -s p -r a --thread-id "$thread_id" &
tsp --database a receive --one a

echo "---- establish outer relation p<->q"
tsp --database q verify --alias p "$DID_P"

sleep 2 && tsp --database q request -s q -r p &
read -d '\t' vid thread_id <<< $(tsp --yes --database p receive --one p)
tsp --database p set-alias q "$vid"

sleep 2 && tsp --database p accept -s p -r q --thread-id "$thread_id" &
tsp --database q receive --one q

if [ "$Q2" ]; then
    echo "---- establish outer relation q2<->b"
    tsp --database b verify --alias q2 "$DID_Q2"

    sleep 2 && tsp --database b request -s b -r q2 &
    read -d '\t' vid thread_id <<< $(tsp --yes --database q receive --one q2)
    tsp --database q set-alias b "$vid"

    sleep 2 && tsp --database q accept -s q2 -r b --thread-id "$thread_id" &
    tsp --database b receive --one b

    tsp --database q set-relation q2 b
else
    echo "---- establish outer relation q<->b"
    tsp --database b verify --alias q "$DID_Q"

    sleep 2 && tsp --database b request -s b -r q &
    read -d '\t' vid thread_id <<< $(tsp --yes --database q receive --one q)
    tsp --database q set-alias b "$vid"

    sleep 2 && tsp --database q accept -s q -r b --thread-id "$thread_id" &
    tsp --database b receive --one b

    echo "---- establish nested relation q<->b"

    sleep 2 && tsp --database b request --nested -s b -r q > /dev/null &
    read -d '\t' nested_b thread_id <<< $(tsp --database q receive --one q)

    sleep 2 && tsp --database q accept --nested -s q -r "$nested_b" --thread-id "$thread_id" > /tmp/vid &
    DID_Q2=$(tsp --database b receive --one b)
fi

echo "---- setup the route"
tsp --database a set-route b "p,$DID_Q,$DID_Q2"

wait
sleep 5
echo
echo "==== send a routed message"

sleep 2 && echo -n "Indirect Message from A to B was received!" | tsp --database a send -s a -r b &
tsp --yes --database p receive --one p &
tsp --yes --database q receive --one q &
tsp --yes --database b receive --one b

echo "---- cleanup databases"
rm -f a.sqlite b.sqlite p.sqlite q.sqlite

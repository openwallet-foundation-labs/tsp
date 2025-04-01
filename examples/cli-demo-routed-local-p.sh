#!/bin/bash

# this scripts sends a routed message from a -> p -> q -> q2 -> b
# where p runs using the intermediary server on localhost:3001
#
# run a HTTPS proxy to get HTTPS to work on localhost:3001:
#
#    npx local-ssl-proxy --config ./ssl-proxy.json
#
# install the CLI using the feature "tsp/use_local_certificate" to add
# the local HTTPS certificate:

cargo install --path . --features tsp/use_local_certificate

# run the intermediary server with:
#
#    cargo run --bin demo-intermediary -- --port 3011 localhost:3001

echo "---- cleanup the database"
rm -f a.sqlite b.sqlite q.sqlite

echo
echo "==== create sender, receiver, and intermediaries"

echo "------ drop off vid (q2) will be a public vid"

for entity in a q q2 b; do
    echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:peer with local transport"
    port=$((${port:-1024} + RANDOM % 1000))
    tsp --database "${entity%%[0-9]*}" create-peer --tcp localhost:$port $entity
done
DID_A=$(tsp --database a print a)
DID_P="did:web:localhost%3A3001"
DID_Q=$(tsp --database q print q)
DID_Q2=$(tsp --database q print q2)
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

echo "---- establish outer relation p<->q"
tsp --database q verify --alias p "$DID_P"

sleep 2 && tsp --database q request -s q -r p

echo "---- establish outer relation q2<->b"
tsp --database b verify --alias q2 "$DID_Q2"

sleep 2 && tsp --database b request -s b -r q2 &
read -d '\t' vid thread_id <<< $(tsp --yes --database q receive --one q2)
tsp --database q set-alias b "$vid"
sleep 2 && tsp --database q accept -s q2 -r b --thread-id "$thread_id" &

tsp --database q set-relation q2 b

echo "---- setup the route"
tsp --database a set-route b "p,$DID_Q,$DID_Q2"

wait
sleep 5
echo
echo "==== send a routed message"

sleep 2 && echo -n "Indirect Message from A to B via P and Q was received!" | tsp --database a send -s a -r b &
tsp --yes --database q receive --one q &
tsp --yes --database b receive --one b

echo "---- cleanup databases"
rm -f a.sqlite b.sqlite p.sqlite q.sqlite

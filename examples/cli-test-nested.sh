#!/bin/bash

# install using
cargo install --path .

echo "---- cleanup databases"
rm -f a.json b.json

echo "---- load the sender identity"
tsp --database a.json create-from-file --alias a test/a.json
tsp --database a.json create-peer a-inner
tsp --database a.json set-parent a-inner a

echo "---- load the receiver identity"
tsp --database b.json create-from-file --alias b test/b.json
tsp --database b.json create-peer b-inner

echo "---- verify sender vids"
tsp --database a.json print a | xargs tsp --database b.json verify --alias a
tsp --database a.json print a-inner | xargs tsp --database b.json verify --alias a-inner

echo "---- verify receiver vids"
tsp --database b.json print b | xargs tsp --database a.json verify --alias b
tsp --database b.json print b-inner | xargs tsp --database a.json verify --alias b-inner
tsp --database a.json set-parent b-inner b

echo "---- configure relations"
tsp --database a.json set-relation b-inner a-inner

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Hi b" | tsp --database a.json send -s a-inner -r b-inner &

echo "---- receive the message"
tsp --database b.json receive --one b

echo "---- cleanup databases"
rm -f a.json b.json

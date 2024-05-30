#!/bin/bash

# install using
cargo install --path .

echo "---- cleanup databases"
rm -f a.json b.json

echo "---- load the sender identity"
tsp --database a.json create-from-file --alias a test/a.json

echo "---- load the receiver identity"
tsp --database b.json create-from-file --alias b test/b.json

echo "---- verify sender vids"
tsp --database a.json print a | xargs tsp --database b.json verify --alias a

echo "---- verify receiver vids"
tsp --database b.json print b | xargs tsp --database a.json verify --alias b
tsp --database b.json verify did:web:did.tsp-test.org:user:q --alias q

echo "---- configure route"
tsp --database a.json verify did:web:did.tsp-test.org:user:p --alias p --sender a
tsp --database a.json verify did:web:did.tsp-test.org:user:b --alias b --sender a
tsp --database a.json verify did:web:did.tsp-test.org:user:q --alias q
tsp --database a.json set-route b p,q,q

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Hi b" | tsp --database a.json send -s a -r b &

echo "---- receive the message"
tsp --database b.json receive --one b

echo "---- cleanup databases"
rm -f a.json b.json

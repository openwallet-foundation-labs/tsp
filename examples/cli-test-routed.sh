#!/bin/bash

# install using
cargo install --path .

echo "---- cleanup databases"
rm -f a.sqlite b.sqlite

echo "---- load the sender identity"
tsp --database a create-from-file --alias a test/a.json

echo "---- load the receiver identity"
tsp --database b create-from-file --alias b test/b.json

echo "---- verify sender vids"
tsp --database a print a | xargs tsp --database b verify --alias a

echo "---- verify receiver vids"
tsp --database b print b | xargs tsp --database a verify --alias b
tsp --database b verify did:web:did.tsp-test.org:user:q --alias q

echo "---- configure route"
tsp --database a verify did:web:did.tsp-test.org:user:p --alias p --sender a
tsp --database a verify did:web:did.tsp-test.org:user:b --alias b --sender a
tsp --database a verify did:web:did.tsp-test.org:user:q --alias q
tsp --database a set-route b p,q,q

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Hi b" | tsp --database a send -s a -r b &

echo "---- receive the message"
tsp --database b receive --one b

echo "---- cleanup databases"
rm -f a.sqlite b.sqlite

#!/bin/bash

# install using
cargo install --path .

echo "---- cleanup the database"
rm -f marlon.sqlite marc.sqlite

echo "---- create a new sender identity"
tsp --database marlon create --alias marlon marlon

echo "---- create a new receiver identity"
tsp --database marc create --alias marc marc

echo "---- verify the address of the receiver"
tsp --database marlon verify --alias marc did:web:tsp-test.org:user:marc

echo "---- verify the address of the sender"
tsp --database marc verify --alias marlon did:web:tsp-test.org:user:marlon

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Oh hello Marc" | tsp --database marlon send -s marlon -r marc &

echo "---- receive the message"
tsp --database marc receive --one marc

echo "---- cleanup databases"
rm -f marc.sqlite marlon.sqlite

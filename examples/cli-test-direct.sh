#!/bin/bash

# install using
cargo install --path .

echo "---- cleanup the database"
rm -f marlon.json marc.json

echo "---- create a new sender identity"
tsp --database marlon.json create --alias marlon marlon

echo "---- create a new receiver identity"
tsp --database marc.json create --alias marc marc

echo "---- verify the address of the receiver"
tsp --database marlon.json verify --alias marc did:web:tsp-test.org:user:marc

echo "---- verify the address of the sender"
tsp --database marc.json verify --alias marlon did:web:tsp-test.org:user:marlon

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Oh hello Marc" | tsp --database marlon.json send -s marlon -r marc &

echo "---- receive the message"
tsp --database marc.json receive --one marc

echo "---- cleanup databases"
rm -f marc.json marlon.json

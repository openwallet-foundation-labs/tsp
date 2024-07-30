#!/bin/bash

# install using
cargo install --path .

randuser() {
    head -c4 /dev/urandom | shasum | head -c8
}

echo "---- cleanup the database"
rm -f marlon.sqlite marc.sqlite

echo "---- create a new sender identity"
tsp --database marlon create --alias marlon `randuser`

echo "---- create a new receiver identity"
tsp --database marc create --alias marc `randuser`

DID_MARC=$(tsp --database marc print marc)
DID_MARLON=$(tsp --database marlon print marlon)

echo "---- verify the address of the receiver"
tsp --database marlon verify --alias marc "$DID_MARC"

echo "---- verify the address of the sender"
tsp --database marc verify --alias marlon "$DID_MARLON"

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Oh hello Marc" | tsp --database marlon send -s marlon -r marc &

echo "---- receive the message"
tsp --database marc receive --one marc

echo "---- cleanup databases"
rm -f marc.sqlite marlon.sqlite

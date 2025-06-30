#!/bin/bash

# install using
cargo install --path . --features pq

randuser() {
    head -c4 /dev/urandom | shasum | head -c8
}

echo "---- cleanup the wallet"
rm -f marlon.sqlite marc.sqlite

echo "---- create a new sender identity"
tsp --wallet marlon create --type web --alias marlon `randuser`

echo "---- create a new receiver identity"
tsp --wallet marc create --type web --alias marc `randuser`

DID_MARC=$(tsp --wallet marc print marc)
DID_MARLON=$(tsp --wallet marlon print marlon)

echo "---- verify the address of the receiver"
tsp --wallet marlon verify --alias marc "$DID_MARC"

echo "---- verify the address of the sender"
tsp --wallet marc verify --alias marlon "$DID_MARLON"

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Oh hello Marc" | tsp --wallet marlon send -s marlon -r marc &

echo "---- receive the message"
tsp --wallet marc receive --one marc

echo "---- cleanup wallets"
rm -f marc.sqlite marlon.sqlite

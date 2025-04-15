#!/bin/bash

# install using
cargo install --path .

randuser() {
    head -c4 /dev/urandom | shasum | head -c8
}

echo "---- cleanup the wallet"
rm -f marlon.sqlite marc.sqlite

echo "---- create a new sender identity"
tsp --wallet marlon create --alias marlon `randuser`
DID_MARLON=$(tsp --wallet marlon print marlon)

echo "---- create a new receiver identity"
tsp --wallet marc create --alias marc `randuser`
DID_MARC=$(tsp --wallet marc print marc)

echo "---- verify the address of the receiver"
tsp --wallet marlon verify --alias marc "$DID_MARC"

echo "---- establish an outer relation: send and receive an initial hello"
sleep 2 && tsp --wallet marlon request -s marlon -r marc &
read -d '\t' vid thread_id <<< $(tsp --yes --wallet marc receive --one marc)
tsp --wallet marc set-alias marlon "$vid"

echo "---- confirm the outer relation: send and process the reply"
sleep 1 && tsp --wallet marc accept -s marc -r marlon --thread-id "$thread_id"

echo "---- send and process a direct message"
sleep 2 && echo -n "Oh hello Marc" | tsp --wallet marlon send -s marlon -r marc &
tsp --wallet marc receive --one marc

echo "---- establish a nested relationship: send and receive nested hello"
(
    read -d '\t' nested_marc thread_id <<< $(tsp --wallet marlon receive --one marlon)
    sleep 1 && tsp --wallet marlon accept -s marlon -r "$nested_marc" --nested --thread-id "$thread_id"
) &
sleep 2 && read -d '' nested_marc nested_marlon <<< $(tsp --wallet marc request -s marc -r marlon --nested)

echo "---- send and process a nested message"
sleep 2 && echo "Oh hello Nested Marc" | tsp --wallet marlon send -s "$nested_marlon" -r "$nested_marc" &
tsp --wallet marc receive --one marc

echo "---- cleanup wallets"
rm -f marc.sqlite marlon.sqlite

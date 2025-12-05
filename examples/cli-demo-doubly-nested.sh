#!/bin/bash

# install using default NaCl + ESSR build
cargo install --path . || exit 1

randuser() {
    head -c4 /dev/urandom | shasum | head -c8
}

echo "---- cleanup the wallet"
rm -f marlon.sqlite marc.sqlite

echo "---- create identities"
tsp --wallet marlon create --type web --alias marlon `randuser`
DID_MARLON=$(tsp --wallet marlon print marlon)

tsp --wallet marc create --type web --alias marc `randuser`
DID_MARC=$(tsp --wallet marc print marc)

echo "---- make the initial connection"
tsp --wallet marlon verify --alias marc "$DID_MARC"

echo "---- establish an outer relation"
sleep 0.2 && tsp --wallet marlon request --wait -s marlon -r marc &
read -d '\t' marlon thread_id <<< $(tsp --yes --wallet marc receive --one marc)
sleep 1 && tsp --wallet marc accept -s marc -r "$marlon" --thread-id "$thread_id"

echo "---- establish a nested relationship"
(
    read -d '\t' nested_marlon thread_id <<< $(tsp --wallet marc receive --one marc)
    sleep 1 && tsp --wallet marc accept --nested -s marc -r "$nested_marlon" --thread-id "$thread_id"
) &
sleep 2 && read -d '' nested_marlon nested_marc <<< $(tsp --wallet marlon request --wait --nested -s marlon -r marc)

echo "---- establish a twice-nested relationship"
(
    read -d '\t' nested_nested_marlon thread_id <<< $(tsp --wallet marc receive --one marc)
    sleep 1 && tsp --wallet marc accept --nested -s "$nested_marc" -r "$nested_nested_marlon" --thread-id "$thread_id"
) &
sleep 2 && read -d '' nested_nested_marlon nested_nested_marc <<< $(tsp --wallet marlon request --wait --nested -s "$nested_marlon" -r "$nested_marc" -p "$marlon")

echo "---- send and process a twice-nested message"
echo Sender: "$nested_nested_marlon"
sleep 0.2 && echo "Oh hello Nested Marc" | tsp --wallet marlon send -s "$nested_nested_marlon" -r "$nested_nested_marc" &
tsp --wallet marc receive --one marc

echo "---- cleanup wallets"
rm -f marc.sqlite marlon.sqlite

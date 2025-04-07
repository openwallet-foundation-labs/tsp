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
DID_MARLON=$(tsp --database marlon print marlon)

echo "---- create a new receiver identity"
tsp --database marc create --alias marc `randuser`
DID_MARC=$(tsp --database marc print marc)

echo "---- verify the address of the receiver"
tsp --database marlon verify --alias marc "$DID_MARC"

echo "---- establish an outer relation: send and receive an initial hello"
sleep 2 && tsp --database marlon request -s marlon -r marc &
read -d '\t' vid thread_id <<< $(tsp --yes --database marc receive --one marc)
tsp --database marc set-alias marlon "$vid"

echo "---- confirm the outer relation: send and process the reply"
sleep 1 && tsp --database marc accept -s marc -r marlon --thread-id "$thread_id"

echo "---- send and process a direct message"
sleep 2 && echo -n "Oh hello Marc" | tsp --database marlon send -s marlon -r marc &
tsp --database marc receive --one marc

echo "---- establish a nested relationship: send and receive nested hello"
(
    read -d '\t' nested_marc thread_id <<< $(tsp --database marlon receive --one marlon)
    sleep 1 && tsp --database marlon accept -s marlon -r "$nested_marc" --nested --thread-id "$thread_id"
) &
sleep 2 && read -d '' nested_marc nested_marlon <<< $(tsp --database marc request -s marc -r marlon --nested)

echo "---- send and process a nested message"
sleep 2 && echo "Oh hello Nested Marc" | tsp --database marlon send -s "$nested_marlon" -r "$nested_marc" &
tsp --database marc receive --one marc

echo "---- cleanup databases"
rm -f marc.sqlite marlon.sqlite

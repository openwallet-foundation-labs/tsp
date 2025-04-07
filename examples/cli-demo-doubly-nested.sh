#!/bin/bash

# install using
cargo install --path .

randuser() {
    head -c4 /dev/urandom | shasum | head -c8
}

echo "---- cleanup the database"
rm -f marlon.sqlite marc.sqlite

echo "---- create identities"
tsp --database marlon create --alias marlon `randuser`
DID_MARLON=$(tsp --database marlon print marlon)

tsp --database marc create --alias marc `randuser`
DID_MARC=$(tsp --database marc print marc)

echo "---- make the initial connection"
tsp --database marlon verify --alias marc "$DID_MARC"

echo "---- establish an outer relation"
sleep 0.2 && tsp --database marlon request -s marlon -r marc &
read -d '\t' marlon thread_id <<< $(tsp --yes --database marc receive --one marc)
sleep 1 && tsp --database marc accept -s marc -r "$marlon" --thread-id "$thread_id"

echo "---- establish a nested relationship"
(
    read -d '\t' nested_marlon thread_id <<< $(tsp --database marc receive --one marc)
    sleep 1 && tsp --database marc accept --nested -s marc -r "$nested_marlon" --thread-id "$thread_id"
) &
sleep 2 && read -d '' nested_marlon nested_marc <<< $(tsp --database marlon request --nested -s marlon -r marc)

echo "---- establish a twice-nested relationship"
(
    read -d '\t' nested_nested_marlon thread_id <<< $(tsp --database marc receive --one marc)
    sleep 1 && tsp --database marc accept --nested -s "$nested_marc" -r "$nested_nested_marlon" --thread-id "$thread_id"
) &
sleep 2 && read -d '' nested_nested_marlon nested_nested_marc <<< $(tsp --database marlon request --nested -s "$nested_marlon" -r "$nested_marc" -p "$marlon")

echo "---- send and process a twice-nested message"
echo Sender: "$nested_nested_marlon"
sleep 0.2 && echo "Oh hello Nested Marc" | tsp --database marlon send -s "$nested_nested_marlon" -r "$nested_nested_marc" &
tsp --database marc receive --one marc

echo "---- cleanup databases"
rm -f marc.sqlite marlon.sqlite

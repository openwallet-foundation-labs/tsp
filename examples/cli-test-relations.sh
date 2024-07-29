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

echo "---- establish an outer relation: send and receive an initial hello"
sleep 2 && tsp --database marlon request -s marlon -r marc &

received=$(tsp --yes --database marc receive --one marc)
vid=$(echo "$received" | cut -f1)
thread_id=$(echo "$received" | cut -f2)

tsp --database marc set-alias marlon "$vid"

echo "---- confirm the outer relation: send and process the reply"
sleep 2 && tsp --database marc accept -s marc -r marlon --thread-id "$thread_id" &
tsp --database marlon receive --one marlon

echo "---- send and process a direct message"
sleep 2 && echo -n "Oh hello Marc" | tsp --database marlon send -s marlon -r marc &

[ "$(tsp --database marc receive --one marc)" == "Oh hello Marc" ] || exit 5

echo "---- establish a nested relationship: send and receive nested hello"
sleep 2 && tsp --database marc request -s marc -r marlon --nested > /tmp/vid &

received=$(tsp --database marlon receive --one marlon)
nested_marc=$(echo "$received" | cut -f1)
thread_id=$(echo "$received" | cut -f2)

[ "$nested_marc" == `cat /tmp/vid` ] || exit 5

echo "---- confirm a nested relationship: send and receive nested reply"

sleep 2 && tsp --database marlon accept -s marlon -r "$nested_marc" --nested --thread-id "$thread_id" &
nested_marlon=$(tsp --database marc receive --one marc)

echo "---- send and process a nested message"
sleep 2 && echo "Oh hello Nested Marc" | tsp --database marlon send -s "$nested_marlon" -r "$nested_marc" &
[ "$(tsp --database marc receive --one marc)" == "Oh hello Nested Marc" ] || exit 5

echo "---- cleanup databases"
rm -f marc.sqlite marlon.sqlite /tmp/vid

#!/bin/bash
HPKE="./build-hpke"
NACL="./build-nacl"

HPKE_TPS="$HPKE/bin/tsp"
NACL_TPS="$NACL/bin/tsp"

# install two different versions of the TSP command line example tool
cargo install --path . --bin tsp --root "$HPKE"
cargo install --path . --bin tsp --features nacl --root "$NACL"

randuser() {
    head -c4 /dev/urandom | shasum | head -c8
}

echo "---- cleanup the database"
rm -f marlon.sqlite marc.sqlite

echo "---- create a new sender identity"
$HPKE_TPS --database marlon create --alias marlon `randuser`

echo "---- create a new receiver identity"
$NACL_TPS --database marc create --alias marc `randuser`

DID_MARC=$($NACL_TPS --database marc print marc)
DID_MARLON=$($HPKE_TPS --database marlon print marlon)

echo "---- verify the address of the receiver"
$HPKE_TPS --database marlon verify --alias marc "$DID_MARC"

echo "---- verify the address of the sender"
$NACL_TPS --database marc verify --alias marlon "$DID_MARLON"

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Oh hi Marc" | $HPKE_TPS --database marlon send -s marlon -r marc &

echo "---- receive the message"
$NACL_TPS --database marc receive --one marc

echo "---- wait 1 seconds and then send a message back"
sleep 1 && echo "Oh hello Marlon" | $NACL_TPS --database marc send -s marc -r marlon &

echo "---- receive the message"
$HPKE_TPS --database marlon receive --one marlon

echo "---- cleanup databases"
rm -f marc.sqlite marlon.sqlite

echo "---- cleanup install"
rm -rf "$HPKE"
rm -rf "$NACL"

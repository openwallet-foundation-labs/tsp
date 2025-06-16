#!/bin/bash

# install using
cargo install --path .

randuser() {
    head -c4 /dev/urandom | shasum | head -c8
}

cointoss() {
    (( $RANDOM % 2 ))
}

echo "---- cleanup the wallet"
rm -f a.sqlite b.sqlite p.sqlite q.sqlite

echo
echo "==== create sender, receiver, and intermediaries"

if cointoss; then
    echo "------ drop off vid (q2) will be a public vid"
    Q2=q2
else
    echo "------ drop off vid will be a nested vid (out-of-band)"
fi

for entity in a p q $Q2 b; do
    if cointoss; then
	echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:web"
	tsp --wallet "${entity%%[0-9]*}" create --type web --alias $entity `randuser`
    else
	if cointoss; then
	    echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:peer with https:// transport"
	    tsp --wallet "${entity%%[0-9]*}" create --type peer $entity
	else
	    echo "------ $entity (identifier for ${entity%%[0-9]*}) uses did:peer with local transport"
	    port=$((${port:-1024} + RANDOM % 1000))
	    tsp --wallet "${entity%%[0-9]*}" create --type peer --tcp localhost:$port $entity
	fi
    fi
done
DID_A=$(tsp --wallet a print a)
DID_P=$(tsp --wallet p print p)
DID_Q=$(tsp --wallet q print q)
[ "$Q2" ] && DID_Q2=$(tsp --wallet q print q2)
DID_B=$(tsp --wallet b print b)

wait
sleep 5
echo
echo "==== let the nodes introduce each other"

echo "---- verify the address of the receiver"
tsp --wallet a verify --alias b "$DID_B"

echo "---- establish outer relation a<->p"
tsp --wallet a verify --alias p "$DID_P"

sleep 2 && tsp --wallet a request --wait -s a -r p &
read -d '\t' vid thread_id <<< $(tsp --yes --wallet p receive --one p)
tsp --wallet p set-alias a "$vid"
sleep 2 && tsp --wallet p accept -s p -r a --thread-id "$thread_id"

echo "---- establish outer relation p<->q"
tsp --wallet q verify --alias p "$DID_P"

sleep 2 && tsp --wallet q request --wait -s q -r p &
read -d '\t' vid thread_id <<< $(tsp --yes --wallet p receive --one p)
tsp --wallet p set-alias q "$vid"
sleep 2 && tsp --wallet p accept -s p -r q --thread-id "$thread_id"

if [ "$Q2" ]; then
    echo "---- establish outer relation q2<->b"
    tsp --wallet b verify --alias q2 "$DID_Q2"

    sleep 2 && tsp --wallet b request --wait -s b -r q2 &
    read -d '\t' vid thread_id <<< $(tsp --yes --wallet q receive --one q2)
    tsp --wallet q set-alias b "$vid"
    sleep 2 && tsp --wallet q accept -s q2 -r b --thread-id "$thread_id"

    tsp --wallet q request -s q2 -r b
else
    echo "---- establish outer relation q<->b"
    tsp --wallet b verify --alias q "$DID_Q"

    sleep 2 && tsp --wallet b request --wait -s b -r q &
    read -d '\t' vid thread_id <<< $(tsp --yes --wallet q receive --one q)
    tsp --wallet q set-alias b "$vid"
    sleep 2 && tsp --wallet q accept -s q -r b --thread-id "$thread_id"

    echo "---- establish nested relation q<->b"
    (
        read -d '\t' nested_b thread_id <<< $(tsp --wallet q receive --one q)
        sleep 1 && tsp --wallet q accept --nested -s q -r "$nested_b" --thread-id "$thread_id"
    ) &
    sleep 2 && read -d '' DID_B2 DID_Q2 <<< $(tsp --wallet b request --wait --nested -s b -r q)
fi

echo "---- setup the route"
tsp --wallet a set-route b "p,$DID_Q,$DID_Q2"

wait
sleep 5
echo
echo "==== send a routed message"

sleep 2 && echo -n "Indirect Message from A to B was received!" | tsp --wallet a send -s a -r b &
tsp --yes --wallet p receive --one p &
tsp --yes --wallet q receive --one q &
tsp --yes --wallet b receive --one b

echo "---- cleanup wallets"
rm -f a.sqlite b.sqlite p.sqlite q.sqlite

#!/bin/bash

# install using
#cargo install --path .

echo "---- cleanup the database"
rm -f marlon.sqlite marc.sqlite p.sqlite q.sqlite

echo "---- create a new sender identity"
tsp --database marlon create --alias marlon marlon

echo "---- create a new receiver identity"
tsp --database marc create --alias marc marc

echo "---- verify the address of the receiver"
tsp --database marlon verify --alias marc did:web:tsp-test.org:user:marc

echo "---- create intermediaries"
tsp --database p create --alias p p
tsp --database q create --alias q q
tsp --database q create --alias q2 q2

echo "---- establish outer relation a<->p"
tsp --database marlon verify --alias p did:web:tsp-test.org:user:p

sleep 2 && tsp --database marlon request -s marlon -r p &
received=$(tsp --yes --database p receive --one p)
vid=$(echo "$received" | cut -f1)
thread_id=$(echo "$received" | cut -f2)

tsp --database p set-alias marlon "$vid"
sleep 2 && tsp --database p accept -s p -r marlon --thread-id "$thread_id" &
tsp --database marlon receive --one marlon

echo "---- establish outer relation p<->q"
tsp --database q verify --alias p did:web:tsp-test.org:user:p

sleep 2 && tsp --database q request -s q -r p &
received=$(tsp --yes --database p receive --one p)
vid=$(echo "$received" | cut -f1)
thread_id=$(echo "$received" | cut -f2)
tsp --database p set-alias q "$vid"

sleep 2 && tsp --database p accept -s p -r q --thread-id "$thread_id" &
tsp --database q receive --one q

echo "---- establish outer relation q2<->b"
tsp --database marc verify --alias q2 did:web:tsp-test.org:user:q2

sleep 2 && tsp --database marc request -s marc -r q2 &
received=$(tsp --yes --database q receive --one q2)
vid=$(echo "$received" | cut -f1)
thread_id=$(echo "$received" | cut -f2)
tsp --database q set-alias marc "$vid"

sleep 2 && tsp --database q accept -s q2 -r marc --thread-id "$thread_id" &
tsp --database marc receive --one marc

echo "---- setup the route"
tsp --database marlon set-route marc did:web:tsp-test.org:user:p,did:web:tsp-test.org:user:q,did:web:tsp-test.org:user:q2
tsp --database marlon set-relation marc marlon
tsp --database marlon set-relation p marlon

tsp --database p set-relation did:web:tsp-test.org:user:q p
tsp --database q set-relation did:web:tsp-test.org:user:q2 did:web:tsp-test.org:user:marc

tsp --database marc verify did:web:tsp-test.org:user:marlon

echo "---- send a routed message"

sleep 2 && echo -n "Indirect Message from Marlon to Marc was received!" | tsp --database marlon send -s marlon -r marc &
tsp --yes --database p receive --one p &
tsp --yes --database q receive --one q &
tsp --database marc receive --one marc

echo "---- cleanup databases"
rm -f marlon.sqlite marc.sqlite p.sqlite q.sqlite

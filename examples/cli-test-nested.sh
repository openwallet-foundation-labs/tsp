#!/bin/bash

# install using
cargo install --path .

echo "---- cleanup wallets"
rm -f a.sqlite b.sqlite

echo "---- load the sender identity"
tsp --wallet a import-piv --alias a test/a/piv.json
tsp --wallet a create-peer a-inner
tsp --wallet a set-parent a-inner a

echo "---- load the receiver identity"
tsp --wallet b import-piv --alias b test/b/piv.json
tsp --wallet b create-peer b-inner

echo "---- verify sender vids"
tsp --wallet a print a | xargs tsp --wallet b verify --alias a
tsp --wallet a print a-inner | xargs tsp --wallet b verify --alias a-inner

echo "---- verify receiver vids"
tsp --wallet b print b | xargs tsp --wallet a verify --alias b
tsp --wallet b print b-inner | xargs tsp --wallet a verify --alias b-inner
tsp --wallet a set-parent b-inner b

# without the following, the nested message will still be received, but
# will not be recognized as confidential since b can't tell that "a-inner" and "a"
# are related
tsp --wallet b set-parent a-inner a

echo "---- configure relations"
tsp --wallet a set-relation b-inner a-inner

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Hi b" | tsp --wallet a send -s a-inner -r b-inner &

echo "---- receive the message"
tsp --wallet b receive --one b

echo "---- cleanup wallets"
rm -f a.sqlite b.sqlite

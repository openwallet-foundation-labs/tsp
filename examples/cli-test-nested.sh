#!/bin/bash

# install using
cargo install --path .

echo "---- cleanup databases"
rm -f a.sqlite b.sqlite

echo "---- load the sender identity"
tsp --database a create-from-file --alias a test/a.json
tsp --database a create-peer a-inner
tsp --database a set-parent a-inner a

echo "---- load the receiver identity"
tsp --database b create-from-file --alias b test/b.json
tsp --database b create-peer b-inner

echo "---- verify sender vids"
tsp --database a print a | xargs tsp --database b verify --alias a
tsp --database a print a-inner | xargs tsp --database b verify --alias a-inner

echo "---- verify receiver vids"
tsp --database b print b | xargs tsp --database a verify --alias b
tsp --database b print b-inner | xargs tsp --database a verify --alias b-inner
tsp --database a set-parent b-inner b

# without the following, the nested message will still be received, but
# will not be recognized as confidential since b can't tell that "a-inner" and "a"
# are related
tsp --database b set-parent a-inner a

echo "---- configure relations"
tsp --database a set-relation b-inner a-inner

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Hi b" | tsp --database a send -s a-inner -r b-inner &

echo "---- receive the message"
tsp --database b receive --one b

echo "---- cleanup databases"
rm -f a.sqlite b.sqlite

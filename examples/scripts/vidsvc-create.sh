#!/bin/sh
# Create a did:webvh identity on vidsvc.com.
#
#   vidsvc-create.sh NAME
#
# NAME is the one thing to choose: it names the wallet file (NAME.wallet in the current
# directory) and is the identity's alias inside it. The wallet passphrase and the invite code
# are asked for, not typed on the command line. The server is vidsvc.com, the watcher
# vidsvc.ch, the TSP endpoint the testbed intermediary p.teaspoon.world.
set -eu
NAME=${1:?usage: vidsvc-create.sh NAME}
TSP=${TSP:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/tsp}

printf 'Passphrase for the wallet "%s": ' "$NAME"
stty -echo; read -r PASS; stty echo; printf '\n'
printf 'Confirm passphrase: '
stty -echo; read -r PASS2; stty echo; printf '\n'
[ "$PASS" = "$PASS2" ] || { echo "passphrases differ" >&2; exit 1; }
[ -n "$PASS" ] || { echo "empty passphrase" >&2; exit 1; }

printf 'Invite code: '
read -r CODE
[ -n "$CODE" ] || { echo "no code" >&2; exit 1; }

exec "$TSP" --wallet "$NAME" --password "$PASS" --did-server vidsvc.com \
    create --type webvh "$NAME" --alias "$NAME" --invite "$CODE" --watcher https://vidsvc.ch

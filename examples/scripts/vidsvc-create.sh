#!/bin/sh
# Create a did:webvh identity on vidsvc.com.
#
#   vidsvc-create.sh NAME
#
# NAME is the one thing to choose: it names the wallet file (NAME.sqlite in the current
# directory) and is the identity's alias inside it. PREFIX=/t/ in the environment creates a
# test identity under the test prefix, with a test-witness code. The CLI prompts for the wallet passphrase,
# hidden; the invite code is asked for here. The server is vidsvc.com, the watcher vidsvc.ch,
# the TSP endpoint the testbed intermediary p.teaspoon.world.
set -eu
NAME=${1:?usage: vidsvc-create.sh NAME}
TSP=${TSP:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/tsp}
if [ -e "$NAME.sqlite" ]; then
    echo "$NAME.sqlite exists here; choose another name or another directory" >&2
    exit 1
fi
printf 'Invite code: '
read -r CODE
[ -n "$CODE" ] || { echo "no code" >&2; exit 1; }
exec "$TSP" --wallet "$NAME" --did-server vidsvc.com \
    create --type webvh "$NAME" --alias "$NAME" --invite "$CODE" --watcher https://vidsvc.ch --prefix "${PREFIX:-/a/}"

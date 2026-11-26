#!/bin/bash
# Behaviour test: t_cancel_branch() followed by drop in the reply route of a
# provisional reply sends the CANCEL at once. Runs the OpenSIPS image with
# opensips.cfg against the UAC and UAS in check.py (host network, 127.0.0.1).
#
#   test/cancel-dropped-provisional/run.sh [image]   (default: the image of ../../VERSION)
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
name=opensips-cancel-dropped-provisional-test

docker rm -f "$name" >/dev/null 2>&1 || true
# check.py binds its ports first.
python3 -I "$dir/check.py" &
checker=$!
sleep 0.5
docker run -d --rm --name "$name" --network host --entrypoint opensips \
    -v "$dir/opensips.cfg:/etc/opensips/opensips.cfg:ro" "$image" \
    -F -f /etc/opensips/opensips.cfg >/dev/null
rc=0
wait "$checker" || rc=$?
if [ "$rc" != 0 ]; then
    docker logs "$name" 2>&1 | grep -iE "error|rtpengine" | tail -20
fi
docker rm -f "$name" >/dev/null 2>&1 || true
exit "$rc"

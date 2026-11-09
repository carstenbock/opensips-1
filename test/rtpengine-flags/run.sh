#!/bin/bash
# Behaviour test: the flags given to rtpengine_offer() in a script variable
# reach RTPEngine intact. Runs the OpenSIPS image with opensips.cfg against the
# fake RTPEngine in check.py (both on the host network, 127.0.0.1).
#
#   test/rtpengine-flags/run.sh [image]   (default: the image of ../../VERSION)
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
name=opensips-rtpengine-flags-test

docker rm -f "$name" >/dev/null 2>&1 || true
# check.py binds the NG port first, so the module's start-up ping is answered.
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

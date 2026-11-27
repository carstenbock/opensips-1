#!/bin/bash
# Behaviour test for ending a dialog more than once (KI-322): two releases of
# the same confirmed call while its BYEs are still unanswered must send one
# BYE per side, not one per release. Runs the OpenSIPS image with opensips.cfg
# (the one of test/dialog-end-by-val) against the UAC and UAS in check.py
# (host network, 127.0.0.1).
#
#   test/dialog-end-once/run.sh [image]   (default: the image of ../../VERSION)
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
name=opensips-dialog-end-once-test

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --rm --name "$name" --network host --entrypoint opensips \
    -v "$dir/opensips.cfg:/etc/opensips/opensips.cfg:ro" "$image" \
    -F -f /etc/opensips/opensips.cfg >/dev/null
rc=0
python3 -I "$dir/check.py" || rc=$?
if [ "$rc" != 0 ]; then
    docker logs "$name" 2>&1 | grep -iE "error|warn" | tail -20
fi
docker rm -f "$name" >/dev/null 2>&1 || true
exit "$rc"

#!/bin/bash
# Behaviour test for dlg_end_dlgs_by_val() and its optional extra headers:
# the BYEs of a confirmed call and the CANCEL of a ringing call carry the
# given Reason header; without the parameter they carry none (as before), and
# headers without a final CRLF are refused. Runs the OpenSIPS image with
# opensips.cfg against the UAC and UAS in check.py (host network, 127.0.0.1).
#
#   test/dialog-end-by-val/run.sh [image]   (default: the image of ../../VERSION)
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
name=opensips-dialog-end-by-val-test

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

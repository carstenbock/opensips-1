#!/bin/bash
# Regression test for swap_msg_branches(): runs the OpenSIPS image under
# valgrind with opensips.cfg and the client in check.py (host network,
# 127.0.0.1). Fails if the swapped branches are wrong or valgrind reports an
# error in dset.c (OpenSIPS 0.1.47 and older read an uninitialised backup
# branch when the Request-URI is the destination and freed its attrs pointer).
#
#   test/swap-msg-branches/run.sh [image]   (default: the image of ../../VERSION)
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
vg_image="opensips-swap-test-valgrind:$(echo "$image" | tr '/:' '__')"
name=opensips-swap-msg-branches-test
logs=$(mktemp -d)
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$logs"' EXIT

printf 'FROM %s\nUSER root\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq valgrind >/dev/null && rm -rf /var/lib/apt/lists/*\n' "$image" \
    | docker build -q -t "$vg_image" - >/dev/null

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --network host --entrypoint valgrind \
    -v "$dir/opensips.cfg:/etc/opensips/opensips.cfg:ro" -v "$logs:/vg" "$vg_image" \
    --trace-children=yes --log-file=/vg/vg.%p.log \
    opensips -F -m 64 -M 8 -f /etc/opensips/opensips.cfg >/dev/null

rc=0
python3 -I "$dir/check.py" || rc=$?
if grep -l "dset\.c" "$logs"/vg.*.log >/dev/null 2>&1; then
    echo "FAIL valgrind reports errors in dset.c:"
    grep -h -B1 -A6 -m3 -E "uninitialised|Invalid" $(grep -l "dset\.c" "$logs"/vg.*.log) | head -30
    rc=1
else
    echo "ok   valgrind: no errors in dset.c"
fi
exit "$rc"

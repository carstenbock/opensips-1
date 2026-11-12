#!/bin/bash
# Behaviour test for KI-152: a re-registration that replaces a contact sends
# one reg-event NOTIFY per watcher (old contact terminated, new one active),
# and a 477 to a NOTIFY ends the subscription. Runs the OpenSIPS image with
# opensips.cfg against the UE and watcher in check.py (host network,
# 127.0.0.1). OpenSIPS 0.1.48 and older send two NOTIFYs and keep the
# subscription after a 477.
#
#   test/reginfo-replace-notify/run.sh [image]   (default: the image of ../../VERSION)
#
# MODULES=<dir> mounts the presence.so / pua_reginfo.so found in <dir> over
# the image's, to test locally built modules.
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
name=opensips-reginfo-replace-notify-test
moddir=/usr/lib/x86_64-linux-gnu/opensips/modules
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

mounts=()
for m in presence pua_reginfo; do
    if [ -n "${MODULES:-}" ] && [ -f "$MODULES/$m.so" ]; then
        mounts+=(-v "$MODULES/$m.so:$moddir/$m.so:ro")
    fi
done

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --network host --entrypoint sh \
    -v "$dir/opensips.cfg:/etc/opensips/opensips.cfg:ro" "${mounts[@]}" "$image" \
    -c 'cp -r /usr/share/opensips/dbtext/opensips /tmp/db && exec opensips -F -f /etc/opensips/opensips.cfg' >/dev/null
rc=0
OPENSIPS_CONTAINER=$name python3 -I -u "$dir/check.py" || rc=$?
if [ "$rc" != 0 ]; then
    docker logs "$name" 2>&1 | grep -iE "error|warn|crit" | tail -20
fi
exit "$rc"

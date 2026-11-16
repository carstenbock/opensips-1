#!/bin/bash
# Behaviour test for KI-190: the registrar builds the public and temporary
# GRUU in the domain held by gruu_domain_avp, and in gruu_domain when the AVP
# is unset. Runs the OpenSIPS image with opensips.cfg against the UE in
# check.py (host network, 127.0.0.1). OpenSIPS 0.1.50 and older do not know
# gruu_domain_avp and refuse the config.
#
#   test/gruu-domain-avp/run.sh [image]   (default: the image of ../../VERSION)
#
# MODULES=<dir> mounts the registrar.so found in <dir> over the image's, to
# test a locally built module.
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
name=opensips-gruu-domain-avp-test
moddir=/usr/lib/x86_64-linux-gnu/opensips/modules
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

mounts=()
if [ -n "${MODULES:-}" ] && [ -f "$MODULES/registrar.so" ]; then
    mounts+=(-v "$MODULES/registrar.so:$moddir/registrar.so:ro")
fi

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --network host --entrypoint opensips \
    -v "$dir/opensips.cfg:/etc/opensips/opensips.cfg:ro" "${mounts[@]}" "$image" \
    -F -f /etc/opensips/opensips.cfg >/dev/null
rc=0
python3 -I -u "$dir/check.py" || rc=$?
if [ "$rc" != 0 ]; then
    docker logs "$name" 2>&1 | grep -iE "error|warn|crit" | tail -20
fi
exit "$rc"

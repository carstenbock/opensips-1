#!/bin/bash
# Behaviour test for proto_ipsec without a set of SAs (KI-69): a request
# towards a UE must not leave the protected server port in clear text (tm
# answers 477, TS 33.203 7.1), while a UE's request relayed to the core
# through that socket is still sent. The gateway runs in its own network
# namespace (NET_ADMIN only there); check.py uses the host side of the
# Docker network.
#
#   test/ipsec-no-sa/run.sh [image]   (default: the image of ../../VERSION)
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
net=opensips-ipsec-test-net
name=opensips-ipsec-no-sa-test
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create --subnet 172.30.98.0/24 --gateway 172.30.98.1 "$net" >/dev/null
docker run -d --name "$name" --network "$net" --ip 172.30.98.10 --cap-add NET_ADMIN \
    --entrypoint opensips -v "$dir/opensips.cfg:/etc/opensips/opensips.cfg:ro" "$image" \
    -F -f /etc/opensips/opensips.cfg >/dev/null
rc=0
python3 -I "$dir/check.py" || rc=$?
docker logs "$name" 2>&1 | grep -E "proto_ipsec_send" | tail -4
exit "$rc"

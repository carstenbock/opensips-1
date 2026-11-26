#!/bin/bash
# Behaviour test for proto_ipsec (helm KI-248): a REGISTER whose UE address
# and protected ports are bound to the set of security associations of
# another user takes them over, as a REGISTER of the same user does; the old
# set's SAs leave the kernel. Before, the new owner of the address got no
# Security-Server until the old binding expired. The gateway runs in its own
# network namespace (NET_ADMIN only there); check.py uses the host side of
# the Docker network and reads the SAs with "ip xfrm state" in the container,
# so the image needs the ip tool (the debug image, the default, has it).
#
#   test/ipsec-port-takeover/run.sh [image]   (default: the image of ../../VERSION)
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
net=opensips-ipsec-takeover-net
name=opensips-ipsec-port-takeover-test
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create --subnet 172.30.95.0/24 --gateway 172.30.95.1 "$net" >/dev/null
docker run -d --name "$name" --network "$net" --ip 172.30.95.10 --cap-add NET_ADMIN \
    --entrypoint opensips -v "$dir/opensips.cfg:/etc/opensips/opensips.cfg:ro" "$image" \
    -F -f /etc/opensips/opensips.cfg >/dev/null
rc=0
python3 -I "$dir/check.py" "$name" || rc=$?
docker logs "$name" 2>&1 | grep -E "bound to another set|of another user" | tail -4 || true
exit "$rc"

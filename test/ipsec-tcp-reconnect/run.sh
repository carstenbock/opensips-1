#!/bin/bash
# Behaviour test for KI-150: TCP from the IPsec gateway to a UE through its
# SAs. The protected client port is fixed (TS 33.203 7.1), so after the
# gateway closed an idle connection its TIME_WAIT blocks a new connect to the
# same UE port for 60 s if the UE does not use TCP timestamps (connect():
# EADDRNOTAVAIL). check.py runs the UE and the core in a second container
# (hmac-md5-96 + null encryption SAs set up with ip xfrm from the 401's Security-Server):
#  1. a request reaches the UE over a new TCP connection,
#  2. a second request reuses that connection,
#  3. after the gateway closed it, a request must still reach the UE: the
#     failed connect is reported to tm, the script retries over UDP and tm
#     retransmits (the UE drops the first copy). OpenSIPS 0.1.49 and older
#     send one UDP copy behind tm's back, never retransmitted: 408.
#
#   test/ipsec-tcp-reconnect/run.sh [image]   (default: the image of ../../VERSION)
#
# MODULES=<dir> mounts the proto_ipsec.so found in <dir> over the image's.
# UE_TIMESTAMPS=1 lets the UE use TCP timestamps (the kernel may then reuse
# the TIME_WAIT pair and step 3 goes over TCP).
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
net=opensips-ipsec-tcp-net
gw=opensips-ipsec-tcp-gw
moddir=/usr/lib/x86_64-linux-gnu/opensips/modules
cleanup() {
    docker rm -f "$gw" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create --subnet 172.30.96.0/24 "$net" >/dev/null

mounts=()
if [ -n "${MODULES:-}" ] && [ -f "$MODULES/proto_ipsec.so" ]; then
    mounts+=(-v "$MODULES/proto_ipsec.so:$moddir/proto_ipsec.so:ro")
fi
docker run -d --name "$gw" --network "$net" --ip 172.30.96.10 --cap-add NET_ADMIN \
    --entrypoint opensips "${mounts[@]}" -v "$dir/opensips.cfg:/etc/opensips/opensips.cfg:ro" \
    "$image" -F -f /etc/opensips/opensips.cfg >/dev/null
rc=0
docker run --rm --network "$net" --ip 172.30.96.20 --cap-add NET_ADMIN \
    --sysctl net.ipv4.tcp_timestamps="${UE_TIMESTAMPS:-0}" --entrypoint python3 \
    -v "$dir/check.py:/check.py:ro" "$image" -I -u /check.py || rc=$?
echo "     gateway log:"
docker logs "$gw" 2>&1 | grep -E "Cannot assign|tcp_async_connect|proto_ipsec_send|falling back" \
    | sed 's/^/       /' | tail -6
# step 3 tests nothing unless the connect really collided
if [ "${UE_TIMESTAMPS:-0}" = 0 ] && ! docker logs "$gw" 2>&1 | grep -q "Cannot assign requested address"; then
    echo "FAIL the TIME_WAIT collision (EADDRNOTAVAIL) was not reproduced"
    rc=1
fi
[ "$rc" = 0 ] && echo PASS
exit "$rc"

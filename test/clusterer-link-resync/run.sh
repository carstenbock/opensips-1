#!/bin/bash
# Behaviour test for KI-14: two usrloc full-sharing nodes. Node 2's interface
# goes down until both nodes see the link Down; meanwhile each node registers
# contacts that cannot be replicated. When the interface is up again, the
# clusterer must resync the usrloc capability on both sides by itself (no MI
# ul_cluster_sync), so both nodes end with the same contacts. OpenSIPS 0.1.49
# and older keep the gap until the registrations expire.
#
#   test/clusterer-link-resync/run.sh [image]   (default: the image of ../../VERSION)
#
# MODULES=<dir> mounts the clusterer.so found in <dir> over the image's, to
# test a locally built module.
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
net=opensips-cl-resync-net
work=$(mktemp -d)
moddir=/usr/lib/x86_64-linux-gnu/opensips/modules
cleanup_docker() {
    docker rm -f cl-resync-1 cl-resync-2 >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
}
trap 'cleanup_docker; rm -rf "$work"' EXIT
cleanup_docker
docker network create --subnet 172.30.97.0/24 "$net" >/dev/null

mounts=()
if [ -n "${MODULES:-}" ] && [ -f "$MODULES/clusterer.so" ]; then
    mounts+=(-v "$MODULES/clusterer.so:$moddir/clusterer.so:ro")
fi

# node <id> <ip> <peer id> <peer ip>
node() {
    sed -e "s/MY_ID/$1/; s/MY_IP/$2/g; s/PEER_ID/$3/; s/PEER_IP/$4/" \
        "$dir/node.cfg" > "$work/node$1.cfg"
    docker run -d --name "cl-resync-$1" --network "$net" --ip "$2" \
        --cap-add NET_ADMIN --entrypoint opensips "${mounts[@]}" \
        -v "$work/node$1.cfg:/etc/opensips/opensips.cfg:ro" "$image" \
        -F -f /etc/opensips/opensips.cfg >/dev/null
}

mi() { docker exec "cl-resync-$1" opensips-cli -x mi "${@:2}" 2>/dev/null; }

# link state node <n> has for its peer
link_state() {
    mi "$1" clusterer_list | python3 -c 'import json,sys
d=json.load(sys.stdin)
print(d["Clusters"][0]["Nodes"][0]["link_state"])' 2>/dev/null || echo "?"
}

wait_state() {  # wait_state <node> <Up|Down> <seconds>
    local i
    for i in $(seq 1 "$3"); do
        [ "$(link_state "$1")" = "$2" ] && return 0
        sleep 1
    done
    return 1
}

contacts() {
    mi "$1" ul_dump | python3 -c 'import json,sys
d=json.load(sys.stdin)
print(sum(len(a.get("Contacts", [])) for dom in d["Domains"] for a in dom.get("AORs", [])))' \
        2>/dev/null || echo "?"
}

add() {  # add <node> <prefix> <count>
    local i
    for i in $(seq 1 "$3"); do
        mi "$1" ul_add location "$2$i" "sip:$2$i@10.0.0.$i:5060" 600 1 0 0 0 >/dev/null
    done
}

rc=0
fail() { echo "FAIL $*"; rc=1; }

node 1 172.30.97.11 2 172.30.97.12
node 2 172.30.97.12 1 172.30.97.11
wait_state 1 Up 30 && wait_state 2 Up 10 || fail "link never came Up"
add 1 before 5
sleep 1
echo "     before the outage: node 1 $(contacts 1), node 2 $(contacts 2) contacts"

docker exec cl-resync-2 ip link set eth0 down
wait_state 1 Down 20 || fail "node 1 does not see the link Down ($(link_state 1))"
wait_state 2 Down 20 || fail "node 2 does not see the link Down ($(link_state 2))"
add 1 outage-a 7
add 2 outage-b 3
echo "     during the outage: node 1 $(contacts 1), node 2 $(contacts 2) contacts"
docker exec cl-resync-2 ip link set eth0 up

wait_state 1 Up 30 && wait_state 2 Up 10 || fail "link not Up again"
want=15
for i in $(seq 1 20); do
    c1=$(contacts 1); c2=$(contacts 2)
    [ "$c1" = "$want" ] && [ "$c2" = "$want" ] && break
    sleep 1
done
if [ "$c1" = "$want" ] && [ "$c2" = "$want" ]; then
    echo "ok   both nodes hold all $want contacts after the outage, without an MI sync"
else
    fail "contacts after the outage: node 1 $c1, node 2 $c2 (want $want each)"
fi
# One resync per node: the first link-up after the start must not trigger
# one (a node that starts takes its data through its own startup sync).
for n in 1 2; do
    count=$(docker logs "cl-resync-$n" 2>&1 | grep -c "resyncing capability" || true)
    [ "$count" = 1 ] || fail "node $n logged $count link resyncs, want 1"
done
[ "$rc" = 0 ] && echo PASS
exit "$rc"

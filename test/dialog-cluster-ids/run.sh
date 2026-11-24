#!/bin/bash
# Behaviour test for helm KI-237: two dialog replication nodes, one on-net
# call whose two legs (same Call-ID and tags) pass different nodes, as the
# originating and the terminating P-CSCF pod. The two dialogs must get
# different ids, and a BYE through each node must reach the callee. OpenSIPS
# 0.1.52 and older give both legs the same id once the nodes' counters are in
# step, and a BYE is answered 481.
#
#   test/dialog-cluster-ids/run.sh [image]   (default: the image of ../../VERSION)
#
# MODULES=<dir> mounts the dialog.so found in <dir> over the image's, to test
# a locally built module. KEEP=1 leaves the containers running for debugging.
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")-debug}
net=opensips-dlg-ids-net
gw=172.30.98.1
work=$(mktemp -d)
moddir=/usr/lib/x86_64-linux-gnu/opensips/modules
cleanup_docker() {
    docker rm -f dlg-ids-1 dlg-ids-2 >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
}
trap '[ -n "${KEEP:-}" ] || cleanup_docker; rm -rf "$work"' EXIT
cleanup_docker
docker network create --subnet 172.30.98.0/24 --gateway "$gw" "$net" >/dev/null

mounts=()
if [ -n "${MODULES:-}" ] && [ -f "$MODULES/dialog.so" ]; then
    mounts+=(-v "$MODULES/dialog.so:$moddir/dialog.so:ro")
fi

# node <id> <ip> <peer id> <peer ip>
node() {
    sed -e "s/MY_ID/$1/; s/MY_IP/$2/g; s/PEER_ID/$3/; s/PEER_IP/$4/; s/UAS/$gw:5090/" \
        "$dir/node.cfg" > "$work/node$1.cfg"
    docker run -d --name "dlg-ids-$1" --network "$net" --ip "$2" \
        --entrypoint opensips "${mounts[@]}" \
        -v "$work/node$1.cfg:/etc/opensips/opensips.cfg:ro" "$image" \
        -F -f /etc/opensips/opensips.cfg >/dev/null
}

link_up() {  # link_up <node>: its peer's link state is Up
    docker exec "dlg-ids-$1" opensips-cli -x mi clusterer_list 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin)
sys.exit(0 if d["Clusters"][0]["Nodes"][0]["link_state"] == "Up" else 1)' 2>/dev/null
}

node 1 172.30.98.11 2 172.30.98.12
node 2 172.30.98.12 1 172.30.98.11
for i in $(seq 1 30); do
    link_up 1 && link_up 2 && break
    sleep 1
done
link_up 1 && link_up 2 || { echo "FAIL cluster link never came Up"; exit 1; }

rc=0
python3 "$dir/check.py" "$gw" 172.30.98.11 172.30.98.12 || rc=1
if [ "$rc" != 0 ]; then
    for n in 1 2; do
        echo "---- node $n"
        docker logs "dlg-ids-$n" 2>&1 | grep -E 'dialog |no dialog|ERROR' | tail -8
    done
fi
exit "$rc"

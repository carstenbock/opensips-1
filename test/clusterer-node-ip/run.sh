#!/bin/bash
# Behaviour test for clusterer peers whose IP changed (a restarted pod): two
# nodes on a private Docker network, each knowing the other only by a host
# name from /etc/hosts. Fails unless both cases bring the link Up:
#  learn:   node 1 resolved node 2's name to an old IP; node 2 now pings it
#           from a new IP. Node 1 must take the new IP from the ping (OpenSIPS
#           0.1.48 and older drop the pings as "unknown source").
#  resolve: node 2 cannot reach node 1 by itself (its name for node 1 points
#           to an unused IP) and node 1's name for node 2 is fixed in
#           /etc/hosts only after the link went Down. Node 1 must resolve the
#           name again, and node 2 must learn node 1's IP from that ping.
#
#   test/clusterer-node-ip/run.sh [image]   (default: the image of ../../VERSION)
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
net=opensips-cl-test-net
work=$(mktemp -d)
cleanup() {
    docker rm -f cl-test-1 cl-test-2 >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
cleanup_net() { docker rm -f cl-test-1 cl-test-2 >/dev/null 2>&1 || true; }

docker network rm "$net" >/dev/null 2>&1 || true
docker network create --subnet 172.30.99.0/24 "$net" >/dev/null

# node <id> <ip> <peer id> <peer host> <peer host IP>
node() {
    sed -e "s/MY_ID/$1/; s/MY_IP/$2/g; s/PEER_ID/$3/; s/PEER_HOST/$4/" \
        "$dir/node.cfg" > "$work/node$1.cfg"
    docker run -d --name "cl-test-$1" --network "$net" --ip "$2" \
        --add-host "$4:$5" --entrypoint opensips \
        -v "$work/node$1.cfg:/etc/opensips/opensips.cfg:ro" "$image" \
        -F -f /etc/opensips/opensips.cfg >/dev/null
}

# link state node 1 has for node 2
link_state() {
    docker exec cl-test-1 opensips-cli -x mi clusterer_list 2>/dev/null \
        | python3 -c 'import json,sys
d=json.load(sys.stdin)
print(d["Clusters"][0]["Nodes"][0]["link_state"])' 2>/dev/null || echo "?"
}

wait_up() {
    local i
    for i in $(seq 1 "$1"); do
        [ "$(link_state)" = "Up" ] && return 0
        sleep 1
    done
    return 1
}

rc=0

# --- learn: node 1 still has node 2's old IP (.12), node 2 is at .13
node 1 172.30.99.11 2 nodeb 172.30.99.12
node 2 172.30.99.13 1 nodea 172.30.99.11
if wait_up 20; then
    echo "ok   learn: link Up after node 2 came back with a new IP"
    docker logs cl-test-1 2>&1 | grep -m1 "moved from" || true
else
    echo "FAIL learn: link of node 1 to node 2 is $(link_state)"
    docker logs cl-test-1 2>&1 | grep -iE "unknown source|moved|error" | tail -5
    rc=1
fi
cleanup_net

# --- resolve: node 2's name for node 1 points nowhere, node 1's name for
# node 2 points to the old IP until the link is Down
node 1 172.30.99.11 2 nodeb 172.30.99.12
node 2 172.30.99.13 1 nodea 172.30.99.250
for i in $(seq 1 20); do
    [ "$(link_state)" = "Down" ] && break
    sleep 1
done
echo "     resolve: link of node 1 to node 2 is $(link_state) before the name is fixed"
# /etc/hosts is a bind mount: rewrite it in place
docker exec cl-test-1 sh -c 'sed "s/172.30.99.12/172.30.99.13/" /etc/hosts > /tmp/h && cat /tmp/h > /etc/hosts'
if wait_up 20; then
    echo "ok   resolve: link Up after node 1 resolved node 2's name again"
    docker logs cl-test-1 2>&1 | grep -m1 "URL resolved again" || true
    docker logs cl-test-2 2>&1 | grep -m2 -E "learned from its ping|closing pending connect" || true
else
    echo "FAIL resolve: link of node 1 to node 2 is $(link_state)"
    docker logs cl-test-1 2>&1 | grep -iE "resolve|moved|error" | tail -5
    docker logs cl-test-2 2>&1 | grep -iE "unknown source|moved|error" | tail -5
    rc=1
fi
[ "$rc" = 0 ] && echo PASS
exit "$rc"

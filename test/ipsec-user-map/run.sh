#!/bin/bash
# Unit test for the user map of proto_ipsec (helm KI-23 item 5). Needs gcc
# and the Linux XFRM headers only; ipsec_user.c is built on stand-ins for
# the OpenSIPS core (stub/stub.h).
#
#   test/ipsec-user-map/run.sh [users behind one address]   (default 25000)
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
bin=$(mktemp)
trap 'rm -f "$bin"' EXIT
# -w: the core headers warn without the build's own flags
gcc -O2 -w -DMOD_NAME='"proto_ipsec"' -DUSE_PTHREAD_MUTEX -DF_MALLOC \
    -I "$dir/stub" -I "$dir" -o "$bin" "$dir/test.c"
"$bin" "$@"

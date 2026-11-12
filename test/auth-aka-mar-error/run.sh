#!/bin/bash
# Behaviour test for a failed Cx MAR in auth_aka/aka_av_diameter (KI-21): a
# fake HSS (fake_hss.py) answers DIAMETER_ERROR_USER_UNKNOWN, UNABLE_TO_COMPLY
# or nothing. With av_failure_reply 0 the script must see $rc -7/-8 and the
# Diameter result in $aka_mar_rc/$aka_mar_exp_rc and answer itself (403 for
# an unknown user); with the default (1) the module answers 500/504 as before.
# Runs on the host network (127.0.0.1, ports 3868, 3870, 5178, 5179).
#
#   test/auth-aka-mar-error/run.sh [image]   (default: the image of ../../VERSION)
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$dir/../../../.." && pwd)
image=${1:-harbor.volte.io/cnaas/opensips:$(cat "$dir/../../VERSION")}
name=opensips-auth-aka-mar-test
work=$(mktemp -d)
hss=
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    [ -n "$hss" ] && kill "$hss" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

# the S-CSCF chart's Cx dictionary, without the template comments
python3 -I - "$repo/scscf-chart/templates/_configs/_scscf.dictionary.tpl" \
    "$work/scscf.dictionary" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
open(sys.argv[2], "w").write(re.sub(r"\{\{-? */\*.*?\*/ *-?\}\}\n?", "", src, flags=re.S))
PY
cp "$dir/freeDiameter.conf" "$work/"

python3 -I "$dir/fake_hss.py" > "$work/hss.log" 2>&1 &
hss=$!
rc=0
for mode in 0 1; do
    sed "s/AV_FAILURE_REPLY/$mode/" "$dir/opensips.cfg" > "$work/opensips.cfg"
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" --network host --entrypoint opensips \
        -v "$work:/etc/opensips:ro" "$image" -F -f /etc/opensips/opensips.cfg >/dev/null
    python3 -I "$dir/check.py" "$mode" || {
        rc=1
        docker logs "$name" 2>&1 | grep -iE "error|diameter" | tail -10
    }
done
docker rm -f "$name" >/dev/null 2>&1 || true
[ "$rc" = 0 ] && echo PASS
exit "$rc"

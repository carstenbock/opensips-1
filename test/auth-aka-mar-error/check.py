#!/usr/bin/env python3
"""UE side of test/auth-aka-mar-error/run.sh. argv[1] is the auth_aka
av_failure_reply mode under test, argv[2] the fake HSS log.

Mode 0 lets the S-CSCF script answer a failed MAR itself, so it can answer
DIAMETER_ERROR_USER_UNKNOWN with 403 (TS 24.229 5.4.1.2, TS 29.228 6.3) and
add its own headers (P-Charging-Vector, KI-21); mode 1 must keep the module's
own 500/504 exactly as before.
"""
import re
import socket
import sys
import time

PROXY = ("127.0.0.1", 5179)
WANT = {
    "0": {"unknown": (403, "rc=-7 exp=5001"), "other": (500, "rc=-7 mar=5012"),
          "silent": (504, "rc=-8")},
    "1": {"unknown": (500, None), "other": (500, None), "silent": (500, None)},
}


def register(s, user, n):
    msg = ("REGISTER sip:test SIP/2.0\r\n"
           "Via: SIP/2.0/UDP 127.0.0.1:5178;branch=z9hG4bK-aka-%s-%d\r\n"
           "From: <sip:%s@test>;tag=%d\r\nTo: <sip:%s@test>\r\n"
           "Call-ID: aka-%s-%d\r\nCSeq: 1 REGISTER\r\nMax-Forwards: 70\r\n"
           "Contact: <sip:%s@127.0.0.1:5178>\r\nExpires: 600\r\n"
           'Authorization: Digest username="%s@test", realm="test", '
           'uri="sip:test", nonce="", response=""\r\n'
           "Content-Length: 0\r\n\r\n"
           % (user, n, user, n, user, user, n, user, user)).encode()
    s.sendto(msg, PROXY)
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            data = s.recv(65535).decode()
        except socket.timeout:
            continue
        line = data.split("\r\n", 1)[0]
        code = int(line.split(" ", 2)[1])
        if code >= 200:
            return code, line.split(" ", 2)[2]
    return None, None


def main():
    mode = sys.argv[1]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 5178))
    s.settimeout(0.2)
    n = 0
    # Wait until the Diameter connection to the fake HSS is up: a warm-up MAR
    # must have reached the fake HSS (its log, argv[2]). Any final reply is
    # not enough: before the peer is open freeDiameter answers the MAR itself
    # with 3002 (DIAMETER_UNABLE_TO_DELIVER), and the first case raced the
    # connection (KI-169).
    hss_log = sys.argv[2]
    deadline = time.time() + 40
    while time.time() < deadline:
        n += 1
        register(s, "other-warmup%d" % n, n)
        with open(hss_log, errors="replace") as f:
            if re.search(r"MAR for other-warmup%d\b(?!\d)" % n, f.read()):
                break
        time.sleep(1)
    else:
        print("FAIL mode %s: no warm-up MAR reached the fake HSS within 40 s" % mode)
        sys.exit(1)
    ok = True
    for user, (want_code, want_text) in WANT[mode].items():
        n += 1
        code, reason = register(s, "%s%d" % (user, n), n)
        if code != want_code or (want_text and want_text not in reason) or \
                (want_text is None and reason and "rc=" in reason):
            print("FAIL mode %s %s: got %s %s, want %s %s"
                  % (mode, user, code, reason, want_code, want_text or "(module reply)"))
            ok = False
        else:
            print("ok   mode %s %s: %s %s" % (mode, user, code, reason))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

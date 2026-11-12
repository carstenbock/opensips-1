#!/usr/bin/env python3
"""Core and UE endpoints for test/ipsec-no-sa/run.sh (host side of the test
network, 172.30.98.1).

to-ue:   the core sends a MESSAGE that the gateway must relay to a UE through
         the protected server port. The UE has no SAs, so TS 33.203 7.1 forbids
         sending it in clear text: the UE must receive nothing and the core
         must get 477. OpenSIPS 0.1.48 and older sent it unprotected.
to-core: a UE's MESSAGE that the gateway relays to the core through the same
         socket (no SA either). This is not UE-bound traffic, so the change
         must leave it alone: the core gets it and the UE gets the 200.
"""
import re
import socket
import sys
import time

GW_PLAIN = ("172.30.98.10", 5060)
GW_PROTECTED = ("172.30.98.10", 5100)


def sock(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("172.30.98.1", port))
    s.settimeout(0.1)
    return s


CORE, UE = sock(5070), sock(5080)


def request(direction, src_port, n):
    return ("MESSAGE sip:x@172.30.98.10 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 172.30.98.1:%d;branch=z9hG4bK-%s-%d\r\n"
            "From: <sip:a@test>;tag=%s\r\nTo: <sip:b@test>\r\n"
            "Call-ID: ipsec-no-sa-%s-%d\r\nCSeq: 1 MESSAGE\r\nMax-Forwards: 70\r\n"
            "X-Dir: %s\r\nContent-Length: 0\r\n\r\n"
            % (src_port, direction, n, direction, direction, n, direction)).encode()


def answer(msg, peer, s):
    hdrs = [l for l in msg.split("\r\n")
            if re.match(r"^(Via|From|To|Call-ID|CSeq):", l)]
    s.sendto(("SIP/2.0 200 OK\r\n" + "\r\n".join(hdrs) +
              "\r\nContent-Length: 0\r\n\r\n").encode(), peer)


def run(direction, sender, src_port, dst, receiver, seconds=6):
    """returns (final reply code seen by the sender, request seen by receiver)"""
    deadline, sent_at, n = time.time() + 30, 0.0, 0
    code, got = None, None
    end = None
    while time.time() < deadline:
        if code is None and got is None and time.time() - sent_at > 1.0:
            n += 1  # resent (new transaction) until the gateway is up
            sender.sendto(request(direction, src_port, n), dst)
            sent_at = time.time()
        try:
            data, peer = receiver.recvfrom(65535)
            msg = data.decode()
            if msg.startswith("MESSAGE"):
                got = (msg, peer)
                answer(msg, peer, receiver)
                end = end or time.time() + 2
        except socket.timeout:
            pass
        try:
            data, _ = sender.recvfrom(65535)
            c = int(data.decode().split(" ", 2)[1])
            if c >= 200:
                code = c
                end = end or time.time() + 1
        except socket.timeout:
            pass
        if end and time.time() > end:
            break
    return code, got


def main():
    ok = True
    code, got = run("to-ue", CORE, 5070, GW_PLAIN, UE)
    if got:
        print("FAIL to-ue: the UE received the request in clear text from %s:%d"
              % got[1])
        ok = False
    elif code != 477:
        print("FAIL to-ue: the core got %s, want 477" % code)
        ok = False
    else:
        print("ok   to-ue: nothing sent to the UE without SAs, the core got 477")

    code, got = run("to-core", UE, 5080, GW_PROTECTED, CORE)
    if not got or code != 200:
        print("FAIL to-core: core received %s, the UE got %s (want the request and 200)"
              % ("the request" if got else "nothing", code))
        ok = False
    else:
        print("ok   to-core: relayed to the core, the UE got 200")
    if not ok:
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()

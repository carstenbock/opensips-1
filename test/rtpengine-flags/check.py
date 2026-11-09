#!/usr/bin/env python3
"""Fake RTPEngine NG server plus SIP client for test/rtpengine-flags/run.sh.

Sends INVITEs to OpenSIPS, which offers each one to this fake RTPEngine.
Fails unless every offer carries exactly the flags of opensips.cfg. OpenSIPS
0.1.45 freed the flag string before sending the NG request, so RTPEngine got
empty flags and a garbled address family (KI-86 MT test, 2026-11-09).
"""
import socket
import sys
import time

NG_ADDR = ("127.0.0.1", 22299)
SIP_ADDR = ("127.0.0.1", 5099)
EXPECTED = {
    "address family": b"IP6",
    "direction": [b"internal", b"internal"],
    "replace": [b"origin"],
    "flags": [b"codec-strip-all", b"codec-except-AMR", b"codec-except-AMR-WB",
              b"codec-except-EVS", b"codec-except-telephone-event"],
    "label": b"x" * 1400,
}
CALLS = 20


def bdecode(data, i=0):
    c = data[i:i + 1]
    if c == b"i":
        end = data.index(b"e", i)
        return int(data[i + 1:end]), end + 1
    if c in (b"l", b"d"):
        i += 1
        items = []
        while data[i:i + 1] != b"e":
            item, i = bdecode(data, i)
            items.append(item)
        if c == b"l":
            return items, i + 1
        return {items[k].decode(errors="replace"): items[k + 1] for k in range(0, len(items), 2)}, i + 1
    colon = data.index(b":", i)
    n = int(data[i:colon])
    return data[colon + 1:colon + 1 + n], colon + 1 + n


def bencode(x):
    if isinstance(x, int):
        return b"i%de" % x
    if isinstance(x, str):
        x = x.encode()
    if isinstance(x, bytes):
        return b"%d:%s" % (len(x), x)
    if isinstance(x, list):
        return b"l" + b"".join(bencode(i) for i in x) + b"e"
    return b"d" + b"".join(bencode(k) + bencode(v) for k, v in sorted(x.items())) + b"e"


SDP = ("v=0\r\no=- 1 1 IN IP4 10.0.0.3\r\ns=-\r\nc=IN IP4 10.0.0.3\r\nt=0 0\r\n"
       "m=audio 30000 RTP/AVP 96 8 101\r\na=rtpmap:96 AMR-WB/16000\r\n"
       "a=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/16000\r\n")


def invite(n):
    return ("INVITE sip:ue@[cafe::1]:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:5098;branch=z9hG4bK-%d\r\n"
            "From: <sip:a@test>;tag=from%d\r\nTo: <sip:ue@test>\r\n"
            "Call-ID: flags-test-%d\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\n"
            "Contact: <sip:a@127.0.0.1:5098>\r\nContent-Type: application/sdp\r\n"
            "Content-Length: %d\r\n\r\n%s" % (n, n, n, len(SDP), SDP)).encode()


def main():
    ng = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ng.bind(NG_ADDR)
    ng.settimeout(0.2)
    sip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sip.bind(("127.0.0.1", 5098))
    sip.settimeout(0.2)

    offers, replies, deadline, last_sent = [], [], time.time() + 30, 0.0
    while time.time() < deadline and len(replies) < CALLS:
        # One INVITE at a time, resent every second until it is answered
        # (OpenSIPS may still be starting).
        if time.time() - last_sent > 1.0:
            sip.sendto(invite(len(replies)), SIP_ADDR)
            last_sent = time.time()
        try:
            data, peer = ng.recvfrom(65535)
            cookie, _, body = data.partition(b" ")
            msg, _ = bdecode(body)
            if msg.get("command") == b"offer":
                offers.append(msg)
                reply = {"result": "ok", "sdp": msg["sdp"]}
            else:
                reply = {"result": "pong"}
            ng.sendto(cookie + b" " + bencode(reply), peer)
        except socket.timeout:
            pass
        try:
            data, _ = sip.recvfrom(65535)
            replies.append(data.split(b"\r\n", 1)[0])
            last_sent = 0.0
        except socket.timeout:
            pass

    bad = 0
    for n, msg in enumerate(offers):
        got = {k: msg.get(k) for k in EXPECTED}
        if got != EXPECTED:
            bad += 1
            print("offer %d: wrong flags: %r" % (n, got))
    print("offers %d, SIP replies %d (%s), wrong %d"
          % (len(offers), len(replies), sorted(set(r.decode() for r in replies)), bad))
    if len(offers) < CALLS or bad:
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()

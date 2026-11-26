#!/usr/bin/env python3
"""UAC and UAS for test/cancel-dropped-provisional/run.sh.

The UAS answers the INVITE with one 183 and does not retransmit it. The
proxy's reply route cancels the branch and drops the 183. The CANCEL must
reach the UAS at once and the 183 must not reach the UAC.

Before 0.1.66 t_cancel_branch() only marked the branch for the first
provisional reply (nothing had been received on it yet) and the CANCEL was
sent when that reply was processed, which a dropped reply never is: the UAS
kept its INVITE until its own timers ran out (helm KI-312).
"""
import re
import socket
import sys
import time

PROXY = ("127.0.0.1", 5179)


def sock(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.1)
    return s


def main():
    uac, uas = sock(5177), sock(5178)
    invite = ("INVITE sip:ue@127.0.0.1:5178 SIP/2.0\r\n"
              "Via: SIP/2.0/UDP 127.0.0.1:5177;branch=z9hG4bK-cdp-1\r\n"
              "From: <sip:a@test>;tag=caller1\r\nTo: <sip:ue@test>\r\n"
              "Call-ID: cancel-dropped-provisional-1\r\nCSeq: 7 INVITE\r\nMax-Forwards: 70\r\n"
              "Contact: <sip:a@127.0.0.1:5177>\r\nContent-Length: 0\r\n\r\n")
    deadline, sent_at, answered = time.time() + 30, 0.0, None
    cancel_after, got_183, final = None, False, None
    while time.time() < deadline and (cancel_after is None or final is None):
        if answered is None and time.time() - sent_at > 1.0:
            uac.sendto(invite.encode(), PROXY)  # resent until the proxy is up
            sent_at = time.time()
        try:
            data, peer = uas.recvfrom(65535)
            msg = data.decode()
            hdr = lambda n: "\r\n".join(re.findall(r"^%s: [^\r\n]*" % n, msg, re.M))
            if msg.startswith("INVITE") and answered is None:
                answered = time.time()
                invite_at_uas = msg
                reply = ("SIP/2.0 183 Session Progress\r\n" + hdr("Via") + "\r\n" + hdr("From") + "\r\n"
                         + hdr("To") + ";tag=callee1\r\n" + hdr("Call-ID") + "\r\n" + hdr("CSeq") + "\r\n"
                         "Contact: <sip:ue@127.0.0.1:5178>\r\nContent-Length: 0\r\n\r\n")
                uas.sendto(reply.encode(), peer)  # once; no retransmission
                deadline = time.time() + 3
            elif msg.startswith("CANCEL") and cancel_after is None:
                cancel_after = time.time() - answered
                ok = ("SIP/2.0 200 OK\r\n" + hdr("Via") + "\r\n" + hdr("From") + "\r\n" + hdr("To") + "\r\n"
                      + hdr("Call-ID") + "\r\n" + hdr("CSeq") + "\r\nContent-Length: 0\r\n\r\n")
                uas.sendto(ok.encode(), peer)
                h2 = lambda n: "\r\n".join(re.findall(r"^%s: [^\r\n]*" % n, invite_at_uas, re.M))
                term = ("SIP/2.0 487 Request Terminated\r\n" + h2("Via") + "\r\n" + h2("From") + "\r\n"
                        + h2("To") + ";tag=callee1\r\n" + h2("Call-ID") + "\r\n" + h2("CSeq") + "\r\n"
                        "Content-Length: 0\r\n\r\n")
                uas.sendto(term.encode(), peer)
        except socket.timeout:
            pass
        try:
            data, _ = uac.recvfrom(65535)
            first = data.decode().split("\r\n")[0]
            if first.startswith("SIP/2.0 183"):
                got_183 = True
            elif re.match(r"SIP/2.0 [2-6]", first):
                final = first
        except socket.timeout:
            pass

    print("CANCEL at the UAS after:", None if cancel_after is None else "%.2f s" % cancel_after)
    print("183 reached the UAC:", got_183, "| final answer at the UAC:", final)
    if cancel_after is None or cancel_after > 1.0 or got_183 or not (final or "").startswith("SIP/2.0 487"):
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()

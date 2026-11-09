#!/usr/bin/env python3
"""UAC, UAS and two "gateway" listeners for test/dialog-early-route/run.sh.

The INVITE carries two identical S-CSCF Record-Route entries. The UAS answers
with a reliable 183 that adds two entries of an IPsec gateway above the proxy
(UE-facing on port 5195, network-facing on 5196) and, like the iPhone in the
KI-86 MT test of 2026-11-09, leaves out one of the identical S-CSCF entries.
The proxy's PRACK toward the callee must go to the network-facing entry
(5196). OpenSIPS 0.1.46 counted the INVITE's entries and sent it to 5195.
"""
import re
import socket
import sys
import time

PROXY = ("127.0.0.1", 5199)


def sock(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.1)
    return s


def main():
    uac, uas, gw_ue, gw_net = sock(5197), sock(5198), sock(5195), sock(5196)
    invite = ("INVITE sip:ue@127.0.0.1:5198 SIP/2.0\r\n"
              "Via: SIP/2.0/UDP 127.0.0.1:5197;branch=z9hG4bK-rr-1\r\n"
              "Record-Route: <sip:scscf.test;lr>, <sip:10.9.9.9:7060;lr>, <sip:scscf.test;lr>\r\n"
              "From: <sip:a@test>;tag=caller1\r\nTo: <sip:ue@test>\r\n"
              "Call-ID: early-route-test-1\r\nCSeq: 7 INVITE\r\nMax-Forwards: 70\r\n"
              "Contact: <sip:a@127.0.0.1:5197>\r\nSupported: 100rel\r\nContent-Length: 0\r\n\r\n")
    deadline, sent_at, answered, result = time.time() + 30, 0.0, False, None
    retransmit = None
    while time.time() < deadline and result is None:
        if not answered and time.time() - sent_at > 1.0:
            uac.sendto(invite.encode(), PROXY)  # resent until the proxy is up
            sent_at = time.time()
        try:
            data, peer = uas.recvfrom(65535)
            msg = data.decode()
            if msg.startswith("INVITE") and not answered:
                answered = True
                vias = re.findall(r"^Via: [^\r\n]*", msg, re.M)
                rrs = ",".join(re.findall(r"^Record-Route: ([^\r\n]*)", msg, re.M))
                entries = [e.strip() for e in rrs.split(",")]
                # The UE leaves out the second of the two identical entries.
                dup = [i for i, e in enumerate(entries) if e == "<sip:scscf.test;lr>"]
                if len(dup) == 2:
                    del entries[dup[1]]
                entries = ["<sip:127.0.0.1:5195;lr>", "<sip:127.0.0.1:5196;lr>"] + entries
                hdr = lambda n: re.search(r"^%s: [^\r\n]*" % n, msg, re.M).group(0)
                reply = ("SIP/2.0 183 Session Progress\r\n" + "\r\n".join(vias) + "\r\n"
                         "Record-Route: " + ", ".join(entries) + "\r\n"
                         + hdr("From") + "\r\n" + hdr("To") + ";tag=callee1\r\n"
                         + hdr("Call-ID") + "\r\n" + hdr("CSeq") + "\r\n"
                         "Contact: <sip:ue@127.0.0.1:5198>\r\nRequire: 100rel\r\nRSeq: 1\r\n"
                         "Content-Length: 0\r\n\r\n")
                uas.sendto(reply.encode(), peer)
                # The proxy's script sees the first 183 before the dialog
                # module stores the callee leg; the UE retransmits it (RFC 3262).
                retransmit = (reply.encode(), peer, time.time() + 0.5)
        except socket.timeout:
            pass
        if retransmit and time.time() > retransmit[2]:
            uas.sendto(retransmit[0], retransmit[1])
            retransmit = (retransmit[0], retransmit[1], time.time() + 0.5)
        for name, s in (("UE-facing 5195 (wrong)", gw_ue), ("network-facing 5196", gw_net)):
            try:
                data, _ = s.recvfrom(65535)
                if data.startswith(b"PRACK"):
                    result = name
                    print(data.decode().split("\r\n\r\n")[0])
            except socket.timeout:
                pass
        try:
            uac.recvfrom(65535)  # 100/183 for the UAC; not checked
        except socket.timeout:
            pass

    print("PRACK went to:", result)
    if result != "network-facing 5196":
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()

"""UA side of test/dialog-cluster-ids/run.sh.

    check.py <my ip> <node 1 ip> <node 2 ip>

Plays caller (UDP 5070) and callee (UDP 5090). A warm-up call through
each node puts both nodes' dialog-id counters of the hash entry in step
(the entry depends on the Call-ID only). Then the two legs of one on-net call,
with the same Call-ID and tags, go through node 1 (leg A) and node 2
(leg B), as an originating and a terminating P-CSCF pod see them. Each
leg's dialog id is read from the Record-Route of its 200 OK. A BYE through
each node must be relayed to the callee (200 OK), not answered 481.
Prints one line per check, then PASS or FAIL.
"""
import re
import socket
import sys
import threading
import time

ME, N1, N2 = sys.argv[1:4]
CALLID = "ki237-same-callid@test"
UAS_TAG = "uas-tag-1"

uas = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
uas.bind((ME, 5090))
uac = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
uac.bind((ME, 5070))
uac.settimeout(5)


def hdrs(msg, name):
    return re.findall(r"(?im)^" + name + r":\s*(.*?)\r$", msg)


def serve():
    while True:
        data, addr = uas.recvfrom(65535)
        msg = data.decode()
        first = msg.split("\r\n", 1)[0]
        method = first.split(" ", 1)[0]
        if method == "ACK" or first.startswith("SIP/2.0"):
            continue
        lines = ["SIP/2.0 200 OK"]
        lines += ["Via: " + v for v in hdrs(msg, "Via")]
        lines += ["Record-Route: " + r for r in hdrs(msg, "Record-Route")]
        lines.append("From: " + hdrs(msg, "From")[0])
        to = hdrs(msg, "To")[0]
        if ";tag=" not in to:
            to += ";tag=" + UAS_TAG
        lines.append("To: " + to)
        lines.append("Call-ID: " + hdrs(msg, "Call-ID")[0])
        lines.append("CSeq: " + hdrs(msg, "CSeq")[0])
        lines.append(f"Contact: <sip:callee@{ME}:5090>")
        lines.append("Content-Length: 0")
        uas.sendto(("\r\n".join(lines) + "\r\n\r\n").encode(), addr)


threading.Thread(target=serve, daemon=True).start()


def request(node, method, ftag, cseq, route=None, ruri=None, to_tag=None):
    ruri = ruri or "sip:callee@example.test"
    lines = [f"{method} {ruri} SIP/2.0",
             f"Via: SIP/2.0/UDP {ME}:5070;branch=z9hG4bK{method}{ftag}{cseq}{time.time_ns()}",
             "Max-Forwards: 70",
             f"From: <sip:caller@example.test>;tag={ftag}",
             "To: <sip:callee@example.test>" + (f";tag={to_tag}" if to_tag else ""),
             f"Call-ID: {CALLID}",
             f"CSeq: {cseq} {method}",
             f"Contact: <sip:caller@{ME}:5070>"]
    if route:
        lines.append("Route: " + route)
    lines.append("Content-Length: 0")
    uac.sendto(("\r\n".join(lines) + "\r\n\r\n").encode(), (node, 5060))
    if method == "ACK":
        return None
    while True:
        msg = uac.recv(65535).decode()
        code = int(msg.split(" ", 2)[1])
        if code >= 200:
            return msg


def call(node, ftag):
    """INVITE and ACK through node; returns (route set, did)."""
    ok = request(node, "INVITE", ftag, 1)
    rr = hdrs(ok, "Record-Route")
    route = ", ".join(rr)
    did = re.search(r"did=([0-9a-f.]+)", route).group(1)
    contact = re.search(r"<([^>]+)>", hdrs(ok, "Contact")[0]).group(1)
    request(node, "ACK", ftag, 1, route=route, ruri=contact, to_tag=UAS_TAG)
    return route, contact, did


def bye(node, ftag, route, contact):
    msg = request(node, "BYE", ftag, 2, route=route, ruri=contact, to_tag=UAS_TAG)
    return msg.split("\r\n", 1)[0]


rc = 0
# A node follows a replicated id only if it is above its own (random)
# counter: a warm-up on each node leaves both counters at node 2's id + 1.
for name, node, tag in (("node 1", N1, "warmup1"), ("node 2", N2, "warmup2")):
    route, contact, did = call(node, tag)
    print(f"     warm-up dialog on {name}: {did}, BYE: {bye(node, tag, route, contact)}")
    time.sleep(1)

ra, ca, did_a = call(N1, "caller-tag")
rb, cb, did_b = call(N2, "caller-tag")
time.sleep(1)
if did_a != did_b:
    print(f"ok   the two legs got different dialog ids: node 1 {did_a}, node 2 {did_b}")
else:
    print(f"FAIL both legs got dialog id {did_a}")
    rc = 1

for name, node, route, contact in (("node 1", N1, ra, ca), ("node 2", N2, rb, cb)):
    status = bye(node, "caller-tag", route, contact)
    if status.startswith("SIP/2.0 200"):
        print(f"ok   BYE through {name}: {status}")
    else:
        print(f"FAIL BYE through {name}: {status}")
        rc = 1

print("PASS" if rc == 0 else "FAIL")
sys.exit(rc)

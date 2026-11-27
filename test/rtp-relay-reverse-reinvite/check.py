#!/usr/bin/env python3
"""Fake RTPEngine NG server, SIP caller and SIP callee for
test/rtp-relay-reverse-reinvite/run.sh.

A call is set up through the B2B of opensips.cfg; then the CALLEE sends a
re-INVITE (a phone that puts a call from the PSTN on hold). rtp_relay has to
hand that offer to RTPEngine with the tags of the first offer swapped, because
it now comes from the other side. With the tags of the first direction
RTPEngine applies the callee's SDP to the caller's leg: the caller is offered
the wrong codecs (488 from a carrier) and the audio is gone afterwards
(KI-331, 2026-11-27).
"""
import re
import socket
import sys
import time

NG_ADDR = ("127.0.0.1", 22299)
SIP_ADDR = ("127.0.0.1", 5099)
CALLER = ("127.0.0.1", 5098)
CALLEE = ("127.0.0.1", 5097)
CALLID = "reverse-reinvite-test"


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


def sdp(owner, direction="sendrecv"):
    # the owner name tells in the NG log whose SDP an offer or answer carries
    return ("v=0\r\no=%s 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n"
            "m=audio 30000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=%s\r\n" % (owner, direction))


def ng_entry(cmd, msg):
    """(command, from-tag, to-tag, SDP owner, direction, label) of an NG request"""
    owner = re.search(rb"o=(\w+)", msg.get("sdp", b""))
    return (cmd, msg.get("from-tag", b"").decode(), msg.get("to-tag", b"").decode(),
            owner.group(1).decode() if owner else "?",
            "/".join(d.decode() for d in msg.get("direction", [])),
            msg.get("label", b"").decode())


def hdr(msg, name):
    m = re.search(r"^%s:[ \t]*(.*)$" % name, msg, re.M | re.I)
    return m.group(1).strip() if m else ""


def hdrs(msg, name):
    return [h.strip() for h in re.findall(r"^%s:[ \t]*(.*)$" % name, msg, re.M | re.I)]


def reply(req, code, reason, tag, contact, body=""):
    to = hdr(req, "To")
    if "tag=" not in to:
        to += ";tag=" + tag
    lines = ["SIP/2.0 %d %s" % (code, reason)]
    lines += ["Via: " + v for v in hdrs(req, "Via")]
    lines += ["Record-Route: " + r for r in hdrs(req, "Record-Route")]
    lines += ["From: " + hdr(req, "From"), "To: " + to, "Call-ID: " + hdr(req, "Call-ID"),
              "CSeq: " + hdr(req, "CSeq"), "Contact: <sip:%s:%d>" % contact]
    if body:
        lines.append("Content-Type: application/sdp")
    lines.append("Content-Length: %d" % len(body))
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def request(method, ruri, frm, to, callid, cseq, contact, branch, body=""):
    lines = ["%s %s SIP/2.0" % (method, ruri),
             "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK-%s" % (contact[0], contact[1], branch),
             "From: " + frm, "To: " + to, "Call-ID: " + callid, "CSeq: %d %s" % (cseq, method),
             "Max-Forwards: 70", "Contact: <sip:%s:%d>" % contact]
    if body:
        lines.append("Content-Type: application/sdp")
    lines.append("Content-Length: %d" % len(body))
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def uri_of(contact_hdr):
    m = re.search(r"<([^>]+)>", contact_hdr)
    return m.group(1) if m else contact_hdr.split(";")[0].strip()


def main():
    ng = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ng.bind(NG_ADDR)
    caller = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    caller.bind(CALLER)
    callee = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    callee.bind(CALLEE)
    for s in (ng, caller, callee):
        s.settimeout(0.05)

    ngs = []          # (command, from-tag, to-tag, SDP owner)
    state = "start"
    callee_invite = None   # the INVITE the callee got
    last_sent = 0.0
    done = False
    deadline = time.time() + 40
    invite = request("INVITE", "sip:callee@test", "<sip:caller@test>;tag=callertag", "<sip:callee@test>",
                     CALLID, 1, CALLER, "inv1", sdp("caller"))

    while time.time() < deadline and not done:
        if state == "start" and time.time() - last_sent > 1.0:
            caller.sendto(invite, SIP_ADDR)   # resent until OpenSIPS is up
            last_sent = time.time()
        try:
            data, peer = ng.recvfrom(65535)
            cookie, _, body = data.partition(b" ")
            msg, _ = bdecode(body)
            cmd = msg.get("command", b"").decode()
            if cmd in ("offer", "answer"):
                ngs.append(ng_entry(cmd, msg))
                rep = {"result": "ok", "sdp": msg["sdp"]}
            elif cmd == "ping":
                rep = {"result": "pong"}
            else:
                rep = {"result": "ok"}
            ng.sendto(cookie + b" " + bencode(rep), peer)
        except socket.timeout:
            pass

        try:
            data, peer = callee.recvfrom(65535)
            m = data.decode(errors="replace")
            first = m.split("\r\n", 1)[0]
            if first.startswith("INVITE ") and "tag=" not in hdr(m, "To"):
                callee_invite = m
                callee.sendto(reply(m, 200, "OK", "calleetag", CALLEE, sdp("callee")), peer)
            elif first.startswith("ACK ") and state in ("start", "ringing"):
                # call is up: the callee puts it on hold
                state = "reinvite"
                ci = callee_invite
                callee.sendto(request("INVITE", uri_of(hdr(ci, "Contact")),
                                      hdr(ci, "To") + ";tag=calleetag", hdr(ci, "From"),
                                      hdr(ci, "Call-ID"), 1, CALLEE, "reinv1",
                                      sdp("callee", "sendonly")), SIP_ADDR)
            elif first.startswith("SIP/2.0 200") and "INVITE" in hdr(m, "CSeq") and state == "reinvite":
                ci = callee_invite
                callee.sendto(request("ACK", uri_of(hdr(ci, "Contact")),
                                      hdr(ci, "To") + ";tag=calleetag", hdr(ci, "From"),
                                      hdr(ci, "Call-ID"), 1, CALLEE, "reack1"), SIP_ADDR)
                done = True
            elif first.startswith("SIP/2.0 4") or first.startswith("SIP/2.0 5"):
                print("callee got", first)
                done = True
        except socket.timeout:
            pass

        try:
            data, peer = caller.recvfrom(65535)
            m = data.decode(errors="replace")
            first = m.split("\r\n", 1)[0]
            if first.startswith("SIP/2.0 200") and state == "start":
                state = "ringing"
                caller.sendto(request("ACK", uri_of(hdr(m, "Contact")), hdr(m, "From"), hdr(m, "To"),
                                      CALLID, 1, CALLER, "ack1"), SIP_ADDR)
            elif first.startswith("INVITE ") and "tag=" in hdr(m, "To"):
                caller.sendto(reply(m, 200, "OK", "callertag", CALLER, sdp("caller", "recvonly")), peer)
            elif first.startswith("SIP/2.0 4") or first.startswith("SIP/2.0 5") or first.startswith("SIP/2.0 6"):
                print("caller got", first)
                done = True
        except socket.timeout:
            pass

    # let the last answer reach the fake RTPEngine
    end = time.time() + 1.0
    while time.time() < end:
        try:
            data, peer = ng.recvfrom(65535)
            cookie, _, body = data.partition(b" ")
            msg, _ = bdecode(body)
            cmd = msg.get("command", b"").decode()
            if cmd in ("offer", "answer"):
                ngs.append(ng_entry(cmd, msg))
            ng.sendto(cookie + b" " + bencode({"result": "ok", "sdp": msg.get("sdp", b"")}), peer)
        except socket.timeout:
            pass

    for n in ngs:
        print("NG %-6s from-tag=%-10s to-tag=%-10s SDP of %-6s direction=%-17s label=%s" % n)
    offers = [n for n in ngs if n[0] == "offer"]
    if len(offers) < 2:
        print("FAIL: expected the first offer and the re-INVITE's offer, got %d offers (state %s)"
              % (len(offers), state))
        sys.exit(1)
    first, second = offers[0], offers[-1]
    ok = True
    if first[3] != "caller" or second[3] != "callee":
        print("FAIL: unexpected SDP owners in the offers")
        ok = False
    # The re-INVITE comes from the side that answered the first offer: its
    # from-tag has to be the first offer's to-side, not the first from-tag.
    if second[1] == first[1]:
        print("FAIL: the callee's re-INVITE was offered with the caller's tag (%s): "
              "RTPEngine takes it for an offer of the caller" % first[1])
        ok = False
    answers = [n for n in ngs if n[0] == "answer"]
    if answers and second[1] != answers[0][2]:
        print("FAIL: the re-INVITE's from-tag %r is not the to-tag %r of the first answer"
              % (second[1], answers[0][2]))
        ok = False
    # Each side's offers carry the flags set for that side ($rtp_relay for the
    # caller, $rtp_relay_peer for the callee): interfaces and codec lists
    # differ per direction, the SBC depends on it.
    if (first[4], first[5]) != ("external/internal", "from-caller"):
        print("FAIL: the first offer does not carry the caller's flags: %r %r" % (first[4], first[5]))
        ok = False
    if (second[4], second[5]) != ("internal/external", "from-callee"):
        print("FAIL: the callee's re-INVITE does not carry the callee's flags: %r %r"
              % (second[4], second[5]))
        ok = False
    if not ok:
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()

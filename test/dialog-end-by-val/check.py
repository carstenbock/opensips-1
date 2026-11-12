#!/usr/bin/env python3
"""UAC, UAS and trigger client for test/dialog-end-by-val/run.sh.

Each case sets up one call through the proxy (dialog value served_aor = the
case's AoR), then sends the proxy a MESSAGE that ends the AoR's dialogs with
dlg_end_dlgs_by_val(). The P-CSCF uses the extra headers to tell both ends
why it released the call (TS 24.229 7.2A.18, RELEASE_CAUSE); a missing Reason
would make a bearer loss look like a normal hang-up. Without the parameter the
requests must stay as before (no Reason), so existing scripts are unaffected.
"""
import re
import socket
import sys
import time

PROXY = ("127.0.0.1", 5189)
REASON = 'Reason: RELEASE_CAUSE;cause=3;text="Media bearer loss"'


def sock(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.05)
    return s


UAC, UAS, CTL = sock(5187), sock(5188), sock(5186)


def recv(s):
    try:
        data, peer = s.recvfrom(65535)
        return data.decode(), peer
    except socket.timeout:
        return None, None


def hdr(msg, name):
    m = re.search(r"^%s: ([^\r\n]*)" % name, msg, re.M | re.I)
    return m.group(1) if m else None


def reply(msg, code, text, extra=""):
    vias = "\r\n".join(re.findall(r"^Via: [^\r\n]*", msg, re.M))
    rrs = "".join(l + "\r\n" for l in re.findall(r"^Record-Route: [^\r\n]*", msg, re.M))
    extra = rrs + extra
    to = hdr(msg, "To")
    if ";tag=" not in to:
        to += ";tag=uas-" + hdr(msg, "Call-ID")
    return ("SIP/2.0 %d %s\r\n%s\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\n"
            "CSeq: %s\r\n%sContent-Length: 0\r\n\r\n" % (
                code, text, vias, hdr(msg, "From"), to, hdr(msg, "Call-ID"),
                hdr(msg, "CSeq"), extra)).encode()


def setup_call(aor, confirm):
    """INVITE through the proxy; the UAS rings, and answers if confirm."""
    callid = "end-by-val-" + aor
    invite = ("INVITE sip:ue@127.0.0.1:5188 SIP/2.0\r\n"
              "Via: SIP/2.0/UDP 127.0.0.1:5187;branch=z9hG4bK-%s\r\n"
              "From: <sip:a@test>;tag=uac-%s\r\nTo: <sip:ue@test>\r\n"
              "Call-ID: %s\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\n"
              "Contact: <sip:a@127.0.0.1:5187>\r\nX-AoR: %s\r\n"
              "Content-Length: 0\r\n\r\n" % (callid, aor, callid, aor))
    deadline, sent_at, got_invite = time.time() + 30, 0.0, False
    while time.time() < deadline:
        if not got_invite and time.time() - sent_at > 1.0:
            UAC.sendto(invite.encode(), PROXY)  # resent until the proxy is up
            sent_at = time.time()
        msg, peer = recv(UAS)
        if msg and msg.startswith("INVITE") and not got_invite:
            got_invite = True
            UAS.sendto(reply(msg, 180, "Ringing",
                             "Contact: <sip:ue@127.0.0.1:5188>\r\n"), peer)
            if not confirm:
                time.sleep(0.3)
                return True
            UAS.sendto(reply(msg, 200, "OK",
                             "Contact: <sip:ue@127.0.0.1:5188>\r\n"), peer)
        msg, _ = recv(UAC)
        if msg and msg.startswith("SIP/2.0 200"):
            rr = hdr(msg, "Record-Route")
            ack = ("ACK sip:ue@127.0.0.1:5188 SIP/2.0\r\n"
                   "Via: SIP/2.0/UDP 127.0.0.1:5187;branch=z9hG4bK-ack-%s\r\n"
                   "Route: %s\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\n"
                   "CSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
                   % (callid, rr, hdr(msg, "From"), hdr(msg, "To"), callid))
            UAC.sendto(ack.encode(), PROXY)
            time.sleep(0.3)
            return True
    return False


def end_dialogs(aor, reason):
    msg = ("MESSAGE sip:proxy@127.0.0.1:5189 SIP/2.0\r\n"
           "Via: SIP/2.0/UDP 127.0.0.1:5186;branch=z9hG4bK-end-%s-%s\r\n"
           "From: <sip:ctl@test>;tag=ctl\r\nTo: <sip:proxy@test>\r\n"
           "Call-ID: end-%s-%s\r\nCSeq: 1 MESSAGE\r\nMax-Forwards: 70\r\n"
           "X-End: %s\r\nX-Reason: %s\r\nContent-Length: 0\r\n\r\n"
           % (aor, reason, aor, reason, aor, reason))
    CTL.sendto(msg.encode(), PROXY)
    deadline = time.time() + 5
    while time.time() < deadline:
        rpl, _ = recv(CTL)
        if rpl:
            return int(rpl.split(" ", 2)[1])
    return None


def collect(seconds=2.0):
    """BYE/CANCEL requests received by the UAC and the UAS, answered 200."""
    got = []
    deadline = time.time() + seconds
    while time.time() < deadline:
        for side, s in (("uac", UAC), ("uas", UAS)):
            msg, peer = recv(s)
            if msg and (msg.startswith("BYE") or msg.startswith("CANCEL")):
                got.append((side, msg.split(" ", 1)[0], hdr(msg, "Reason")))
                s.sendto(reply(msg, 200, "OK"), peer)
            elif msg and msg.startswith("INVITE"):
                pass
    return sorted(set(got))


def main():
    reason_value = REASON.split(": ", 1)[1]
    cases = [
        # (name, aor, confirm, X-Reason, expected MESSAGE reply, expected requests)
        ("confirmed call, Reason given", "c1", True, "yes", 200,
         [("uac", "BYE", reason_value), ("uas", "BYE", reason_value)]),
        ("ringing call, Reason given", "e1", False, "yes", 200,
         [("uas", "CANCEL", reason_value)]),
        ("confirmed call, no extra headers (unchanged)", "c2", True, "no", 200,
         [("uac", "BYE", None), ("uas", "BYE", None)]),
        ("headers without CRLF are refused", "c3", True, "bad", 500, []),
    ]
    ok = True
    for name, aor, confirm, reason, want_code, want in cases:
        if not setup_call(aor, confirm):
            print("FAIL %s: call setup failed" % name)
            ok = False
            continue
        code = end_dialogs(aor, reason)
        got = collect()
        if code != want_code or got != sorted(want):
            print("FAIL %s: reply %s, requests %s; want %s, %s"
                  % (name, code, got, want_code, sorted(want)))
            ok = False
        else:
            print("ok   %s" % name)
    if not ok:
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()

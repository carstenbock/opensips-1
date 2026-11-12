#!/usr/bin/env python3
"""Client for test/reginfo-replace-notify/run.sh (KI-152).

A UE registers, a watcher subscribes to its reg event, then the UE registers
again with a new contact, as a phone does with a new IPsec SA set. The watcher
must get exactly one NOTIFY with the old contact terminated and the new one
active: a second NOTIFY in the same millisecond is what reached the old
flow of a phone and ended in 477/408. Then a NOTIFY is answered 477; the
subscription must be gone, so the next re-registration notifies nobody.
"""
import os
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PROXY = ("127.0.0.1", 5460)
UE = ("127.0.0.1", 5461)
WATCHER = ("127.0.0.1", 5462)
AOR = "sip:alice@test"
NS = "{urn:ietf:params:xml:ns:reginfo}"
CONTAINER = os.environ.get("OPENSIPS_CONTAINER", "opensips-reginfo-replace-notify-test")

ue = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ue.bind(UE)
ue.settimeout(1.0)
watcher = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
watcher.bind(WATCHER)
watcher.settimeout(0.2)
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def headers(msg):
    head = msg.split("\r\n\r\n", 1)[0].split("\r\n")
    return head[0], [(l.split(":", 1)[0].strip(), l.split(":", 1)[1].strip())
                     for l in head[1:] if ":" in l]


def hdr(msg, name):
    for k, v in headers(msg)[1]:
        if k.lower() == name.lower():
            return v
    return None


def reply(sock, req, code, reason, extra=""):
    _, hs = headers(req)
    keep = [f"{k}: {v}" for k, v in hs
            if k.lower() in ("via", "from", "call-id", "cseq")]
    to = hdr(req, "To")
    if ";tag=" not in to:
        to += ";tag=w1"
    msg = "\r\n".join([f"SIP/2.0 {code} {reason}"] + keep + [f"To: {to}"]
                      + ([extra] if extra else []) + ["Content-Length: 0", "", ""])
    sock.sendto(msg.encode(), PROXY)


def register(port, callid, cseq, expires=600):
    msg = (f"REGISTER sip:test SIP/2.0\r\n"
           f"Via: SIP/2.0/UDP {UE[0]}:{UE[1]};branch=z9hG4bK-{callid}-{cseq}\r\n"
           f"From: <{AOR}>;tag=ue-{callid}\r\nTo: <{AOR}>\r\n"
           f"Call-ID: {callid}\r\nCSeq: {cseq} REGISTER\r\nMax-Forwards: 70\r\n"
           f"Contact: <sip:alice@127.0.0.1:{port}>;expires={expires}\r\n"
           "Content-Length: 0\r\n\r\n")
    deadline = time.time() + 30  # first run: wait for OpenSIPS to start
    while time.time() < deadline:
        ue.sendto(msg.encode(), PROXY)
        try:
            data = ue.recv(65535).decode()
        except socket.timeout:
            continue
        return data.split("\r\n", 1)[0]
    return None


def collect_notifies(seconds, code=200, reason="OK"):
    """NOTIFYs received by the watcher within seconds, each answered with code.
    A retransmission (same CSeq) is answered again but counted once."""
    seen = {}
    end = time.time() + seconds
    while time.time() < end:
        try:
            data = watcher.recv(65535).decode()
        except socket.timeout:
            continue
        if data.startswith("NOTIFY "):
            seen.setdefault(hdr(data, "CSeq"), data)
            reply(watcher, data, code, reason)
    return list(seen.values())


def contacts(notify):
    """{contact uri: (state, event)} and the list of contact ids."""
    body = notify.split("\r\n\r\n", 1)[1]
    root = ET.fromstring(body)
    out, ids = {}, []
    for reg in root.iter(NS + "registration"):
        for c in reg.iter(NS + "contact"):
            out[c.find(NS + "uri").text] = (c.get("state"), c.get("event"))
            ids.append(c.get("id"))
    return out, ids


def subscriptions():
    r = subprocess.run(["docker", "exec", CONTAINER, "opensips-cli", "-x", "mi",
                        "subs_phtable_list"], capture_output=True, text=True)
    return r.stdout + r.stderr


def main():
    check(register(6001, "reg-a", 1) == "SIP/2.0 200 OK", "first registration")
    # The notifier process writes the presentity after the 200 OK; a SUBSCRIBE
    # before that gets a second NOTIFY when it lands.
    time.sleep(0.5)

    sub = (f"SUBSCRIBE {AOR} SIP/2.0\r\n"
           f"Via: SIP/2.0/UDP {WATCHER[0]}:{WATCHER[1]};branch=z9hG4bK-sub-1\r\n"
           f"From: <sip:watcher@test>;tag=w-from\r\nTo: <{AOR}>\r\n"
           "Call-ID: sub-1\r\nCSeq: 1 SUBSCRIBE\r\nMax-Forwards: 70\r\n"
           f"Contact: <sip:watcher@{WATCHER[0]}:{WATCHER[1]}>\r\n"
           "Event: reg\r\nAccept: application/reginfo+xml\r\nExpires: 600\r\n"
           "Content-Length: 0\r\n\r\n")
    watcher.sendto(sub.encode(), PROXY)
    got200, initial = False, []
    end = time.time() + 3
    while time.time() < end:
        try:
            data = watcher.recv(65535).decode()
        except socket.timeout:
            continue
        if data.startswith("SIP/2.0 200") and "SUBSCRIBE" in (hdr(data, "CSeq") or ""):
            got200 = True
        elif data.startswith("NOTIFY "):
            if hdr(data, "CSeq") not in initial:
                initial.append(hdr(data, "CSeq"))
            reply(watcher, data, 200, "OK")
    check(got200 and len(initial) == 1, f"subscription accepted, initial NOTIFY "
          f"(CSeqs {initial})")

    # Re-registration with a new contact (new SA set, new Call-ID):
    # max-contacts=1 + force-registration replaces the old binding.
    check(register(6002, "reg-b", 1) == "SIP/2.0 200 OK", "re-registration, new contact")
    notifies = collect_notifies(2.0)
    check(len(notifies) == 1, f"one NOTIFY for a replaced contact (got {len(notifies)}, "
          f"CSeqs {[hdr(n, 'CSeq') for n in notifies]})")
    if notifies:
        cs, ids = contacts(notifies[-1])
        check(cs.get("sip:alice@127.0.0.1:6001") == ("terminated", "unregistered"),
              f"old contact terminated in the NOTIFY ({cs.get('sip:alice@127.0.0.1:6001')})")
        check(cs.get("sip:alice@127.0.0.1:6002", ("",))[0] == "active",
              f"new contact active in the same NOTIFY ({cs.get('sip:alice@127.0.0.1:6002')})")
        check(len(ids) == len(set(ids)), f"contact ids unique ({ids})")

    # Refresh of the same binding: one NOTIFY, no terminated contact left over.
    check(register(6002, "reg-b", 2) == "SIP/2.0 200 OK", "refresh, same contact")
    notifies = collect_notifies(2.0)
    check(len(notifies) == 1, f"one NOTIFY for a refresh (got {len(notifies)})")
    if notifies:
        cs, _ = contacts(notifies[-1])
        check(list(cs) == ["sip:alice@127.0.0.1:6002"]
              and cs["sip:alice@127.0.0.1:6002"][0] == "active",
              f"refresh lists only the active contact ({cs})")

    # The watcher's flow is gone: its NOTIFYs end in 477 (as from an IPsec GW
    # without an SA). The subscription must be removed.
    before = subscriptions()
    check("sub-1" in before, "subscription listed before the 477")
    check(register(6003, "reg-c", 1) == "SIP/2.0 200 OK", "re-registration, NOTIFY gets 477")
    n477 = collect_notifies(2.0, 477, "Send Failed")
    check(len(n477) >= 1, f"NOTIFY answered with 477 ({len(n477)})")
    after = subscriptions()
    check("sub-1" not in after, "subscription removed after the 477"
          + ("" if "sub-1" not in after else f": {after.strip()[:300]}"))
    check(register(6004, "reg-d", 1) == "SIP/2.0 200 OK", "re-registration after the 477")
    late = collect_notifies(2.0)
    check(len(late) == 0, f"no NOTIFY on the removed subscription (got {len(late)})")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

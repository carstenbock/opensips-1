#!/usr/bin/env python3
"""UEs and core for test/ipsec-port-takeover/run.sh (host side of the test
network, 172.30.95.1).

A UE that leaves without de-registering keeps its binding and its set of
security associations on the gateway, for hours or days. The access network
gives its address to the next UE, and a UE that picks the same protected
ports (SIPp always does) was refused: up to 0.1.67 the gateway answered
"UE ports ... are bound to another set of security associations" and the new
owner of the address got no Security-Server until the old binding expired
(helm KI-248, KI-309).

  1. alice registers with ports 6200/6201: Security-Server, 4 SAs
  2. bob, from the same address with the same ports: must get
     Security-Server as well, and alice's SAs must be gone
  3. carol, same address, other ports: Security-Server, bob's set stays
  4. alice comes back with bob's ports: Security-Server, bob's SAs gone
"""
import re
import socket
import subprocess
import sys
import time

GW, ME = "172.30.95.10", "172.30.95.1"
NAME = sys.argv[1]
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ME, port))
    s.settimeout(0.2)
    return s


ue, core = udp(5060), udp(5070)
seq = [0]


def hdr(msg, name):
    m = re.search(r"^%s:\s*(.*)$" % name, msg, re.I | re.M)
    return m.group(1).strip() if m else None


def register(user, port_c, port_s, wait=6):
    """one unprotected REGISTER; returns (status, Security-Server params)"""
    seq[0] += 1
    n = seq[0]
    req = ("REGISTER sip:test SIP/2.0\r\n"
           "Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK-takeover-%d;rport\r\n"
           "From: <sip:%s@test>;tag=r%d\r\nTo: <sip:%s@test>\r\n"
           "Call-ID: ipsec-takeover-%d\r\nCSeq: 1 REGISTER\r\nMax-Forwards: 70\r\n"
           "Contact: <sip:%s@%s:%d>\r\nExpires: 600\r\n"
           "Authorization: Digest username=\"%s@test\",realm=\"test\",uri=\"sip:test\","
           "nonce=\"\",response=\"\"\r\n"
           "Security-Client: ipsec-3gpp;alg=hmac-md5-96;ealg=null;spi-c=%d;spi-s=%d;"
           "port-c=%d;port-s=%d;prot=esp;mod=trans\r\n"
           "Require: sec-agree\r\nProxy-Require: sec-agree\r\nSupported: sec-agree\r\n"
           "Content-Length: 0\r\n\r\n"
           % (ME, n, user, n, user, n, user, ME, port_s, user,
              0x3000 + 2 * n, 0x3001 + 2 * n, port_c, port_s))
    ue.sendto(req.encode(), (GW, 5060))
    end = time.time() + wait
    while time.time() < end:
        try:
            data, peer = core.recvfrom(65535)
            msg = data.decode()
            if msg.startswith("REGISTER"):
                keep = [l for l in msg.split("\r\n")
                        if re.match(r"^(Via|From|Call-ID|CSeq):", l, re.I)]
                core.sendto(("SIP/2.0 401 Unauthorized\r\n" + "\r\n".join(keep)
                             + "\r\nTo: " + hdr(msg, "To") + ";tag=t%d\r\n" % n
                             + 'WWW-Authenticate: Digest realm="test", nonce="bm9uY2U=", '
                             'algorithm=AKAv1-MD5, qop="auth", '
                             'ik="00112233445566778899aabbccddeeff", '
                             'ck="ffeeddccbbaa99887766554433221100"\r\n'
                             "Content-Length: 0\r\n\r\n").encode(), peer)
        except socket.timeout:
            pass
        try:
            data = ue.recv(65535).decode()
            status = int(data.split(" ")[1])
            if status >= 200 and hdr(data, "Call-ID") == "ipsec-takeover-%d" % n:
                ss = hdr(data, "Security-Server")
                p = dict(kv.split("=", 1) for kv in (ss or "").split(";")[1:] if "=" in kv)
                return status, p
        except socket.timeout:
            pass
    return None, {}


def spis():
    """the SPIs of the ESP states in the gateway's network namespace"""
    out = subprocess.run(["docker", "exec", NAME, "ip", "xfrm", "state"],
                         capture_output=True, text=True, check=True).stdout
    return {int(x, 16) for x in re.findall(r"proto esp spi (0x[0-9a-f]+)", out)}


def own(p):
    return {int(p["spi-c"]), int(p["spi-s"])} if "spi-c" in p else set()


# the gateway may still be starting
deadline = time.time() + 30
status, alice = register("alice", 6200, 6201, wait=2)
while status is None and time.time() < deadline:
    status, alice = register("alice", 6200, 6201, wait=2)
check(status == 401 and own(alice), "alice gets Security-Server (%s)" % status)
check(len(spis()) == 4 and own(alice) <= spis(), "4 SAs, alice's among them")

status, bob = register("bob", 6200, 6201)
check(status == 401 and own(bob),
      "bob, same address and ports, gets Security-Server (%s)" % status)
now = spis()
check(len(now) == 4 and own(bob) <= now and not own(alice) & now,
      "4 SAs: bob's, none of alice's (%d in the kernel)" % len(now))

status, carol = register("carol", 6300, 6301)
check(status == 401 and own(carol), "carol, other ports, gets Security-Server (%s)" % status)
now = spis()
check(len(now) == 8 and own(bob) <= now and own(carol) <= now,
      "8 SAs: bob's set is untouched by carol's (%d in the kernel)" % len(now))

status, alice2 = register("alice", 6200, 6201)
check(status == 401 and own(alice2), "alice takes bob's ports back (%s)" % status)
now = spis()
check(len(now) == 8 and own(alice2) <= now and own(carol) <= now and not own(bob) & now,
      "8 SAs: alice's and carol's, none of bob's (%d in the kernel)" % len(now))

if failures:
    sys.exit(1)
print("PASS")

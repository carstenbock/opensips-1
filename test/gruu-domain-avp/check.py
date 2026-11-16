#!/usr/bin/env python3
"""Client for test/gruu-domain-avp/run.sh (KI-190).

A public GRUU is a public user identity of the UE plus "gr" (RFC 5627 3.1,
TS 24.229 5.4.7A). On a platform with several home PLMNs the S-CSCF stores
AoRs without a domain, so the registrar has to be told the domain of the
identity it saves: gruu_domain_avp. A UE of an additional home PLMN must get
GRUUs in its own domain, not in the platform domain (gruu_domain). Without
the AVP the platform domain stays the GRUU host, as before 0.1.51.
"""
import re
import socket
import sys
import time

PROXY = ("127.0.0.1", 5470)
UE = ("127.0.0.1", 5471)
PLATFORM = "platform.test"
HOME = "ims.mnc025.mcc262.3gppnetwork.org"

ue = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ue.bind(UE)
ue.settimeout(1.0)
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def register(user, domain, home=None):
    callid = f"{user}-{time.time()}"
    msg = (f"REGISTER sip:{domain} SIP/2.0\r\n"
           f"Via: SIP/2.0/UDP {UE[0]}:{UE[1]};branch=z9hG4bK-{callid}\r\n"
           f"From: <sip:{user}@{domain}>;tag=ue\r\nTo: <sip:{user}@{domain}>\r\n"
           f"Call-ID: {callid}\r\nCSeq: 1 REGISTER\r\nMax-Forwards: 70\r\n"
           "Supported: gruu\r\n"
           + (f"X-Home-Domain: {home}\r\n" if home else "")
           + f'Contact: <sip:{user}@127.0.0.1:{UE[1]}>;expires=600;'
           f'+sip.instance="<urn:uuid:00000000-0000-0000-0000-{abs(hash(user)) % 10**12:012d}>"\r\n'
           "Content-Length: 0\r\n\r\n")
    deadline = time.time() + 30  # first run: wait for OpenSIPS to start
    while time.time() < deadline:
        ue.sendto(msg.encode(), PROXY)
        try:
            return ue.recv(65535).decode()
        except socket.timeout:
            continue
    sys.exit("no reply from OpenSIPS")


def gruu_hosts(reply):
    pub = re.search(r'pub-gruu="sips?:[^@"]*@([^;">]+)', reply)
    tmp = re.search(r'temp-gruu="sips?:[^@"]*@([^;">]+)', reply)
    return (pub.group(1) if pub else None, tmp.group(1) if tmp else None)


# A subscriber of an additional home PLMN: the AVP names its domain.
r = register("262259999000001", HOME, home=HOME)
check(r.startswith("SIP/2.0 200"), "additional-PLMN REGISTER answered 200")
pub, tmp = gruu_hosts(r)
check(pub == HOME, f"pub-gruu host is the subscriber's home domain ({pub})")
check(tmp == HOME, f"temp-gruu host is the subscriber's home domain ({tmp})")

# No AVP: gruu_domain, the behaviour every other OpenSIPS chart keeps.
r = register("262249999000001", PLATFORM)
check(r.startswith("SIP/2.0 200"), "platform-PLMN REGISTER answered 200")
pub, tmp = gruu_hosts(r)
check(pub == PLATFORM, f"pub-gruu host falls back to gruu_domain ({pub})")
check(tmp == PLATFORM, f"temp-gruu host falls back to gruu_domain ({tmp})")

sys.exit(1 if failures else 0)

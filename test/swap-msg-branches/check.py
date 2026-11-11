#!/usr/bin/env python3
"""Client for test/swap-msg-branches/run.sh: sends one OPTIONS per swap case
and compares the branches the proxy reports after swap_msg_branches()."""
import socket
import sys
import time

PROXY = ("127.0.0.1", 5299)
CASES = {
    # Request-URI <-> extra branch 1: URI and attr move together
    "ruri-swap": ["sip:b2@127.0.0.1:5303 attr-b2",
                  "sip:b1@127.0.0.1:5302 attr-b1",
                  "sip:ruri@127.0.0.1:5301 attr-ruri"],
    # extra branch 0 <-> extra branch 1
    "branch-swap": ["sip:ruri@127.0.0.1:5301 attr-ruri",
                    "sip:b2@127.0.0.1:5303 attr-b2",
                    "sip:b1@127.0.0.1:5302 attr-b1"],
}


def ask(s, user, n):
    msg = (f"OPTIONS sip:{user}@127.0.0.1 SIP/2.0\r\n"
           f"Via: SIP/2.0/UDP 127.0.0.1:5298;branch=z9hG4bK-swap-{n}\r\n"
           f"From: <sip:t@test>;tag={n}\r\nTo: <sip:{user}@test>\r\n"
           f"Call-ID: swap-test-{n}\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n"
           "Content-Length: 0\r\n\r\n")
    deadline = time.time() + 60  # valgrind start-up is slow
    while time.time() < deadline:
        s.sendto(msg.encode(), PROXY)
        try:
            data = s.recv(65535).decode()
        except socket.timeout:
            continue
        lines = [l for l in data.split("\r\n") if l.startswith("X-Branch-")]
        return [l.split(": ", 1)[1] for l in sorted(lines)]
    return None


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 5298))
    s.settimeout(1.0)
    ok = True
    for n, (user, want) in enumerate(CASES.items()):
        got = ask(s, user, n)
        if got != want:
            print(f"FAIL {user}: got {got}, want {want}")
            ok = False
        else:
            print(f"ok   {user}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

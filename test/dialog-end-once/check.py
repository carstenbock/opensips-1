#!/usr/bin/env python3
"""UAC, UAS and trigger client for test/dialog-end-once/run.sh.

A confirmed dialog stays confirmed until its BYEs are answered or time out,
which takes seconds when the UE is gone. In that time the P-CSCF can get a
second reason to release the same call: the PCRF aborts the Rx session of the
registration and of the call when the bearer is lost, the registration goes,
an operator ends the call over MI. Each release used to send its own BYEs
(same CSeq, new branch), so both ends saw the call ended twice and an
unreachable UE got every BYE retransmitted twice (KI-322). The BYEs of a
dialog must be sent once, whatever asks for the release a second time.
"""
import importlib.util
import os
import re
import sys
import time

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "endval", os.path.join(here, "..", "dialog-end-by-val", "check.py"))
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)


def branches(seconds):
    """Via branches of the BYEs each side receives; nobody answers."""
    seen = {"uac": set(), "uas": set()}
    last = {}
    deadline = time.time() + seconds
    while time.time() < deadline:
        for side, s in (("uac", ev.UAC), ("uas", ev.UAS)):
            msg, peer = ev.recv(s)
            if msg and msg.startswith("BYE"):
                seen[side].add(re.search(r"branch=([^;\r\n]+)", msg).group(1))
                last[side] = (msg, peer)
    return seen, last


def main():
    if not ev.setup_call("once", True):
        print("FAIL call setup failed")
        sys.exit(1)
    # Two releases 0 ms apart, as an Rx ASR and the loss of the registration
    # give them; the UEs answer neither BYE for 1.5 s (retransmissions arrive).
    first = ev.end_dialogs("once", "no")
    second = ev.end_dialogs("once", "yes")
    seen, last = branches(1.5)
    for side, s in (("uac", ev.UAC), ("uas", ev.UAS)):
        if side in last:
            s.sendto(ev.reply(last[side][0], 200, "OK"), last[side][1])
    counts = {side: len(b) for side, b in seen.items()}
    if first != 200 or second != 200 or counts != {"uac": 1, "uas": 1}:
        print("FAIL replies %s/%s, BYE transactions per side %s; want 200/200 "
              "and one per side" % (first, second, counts))
        sys.exit(1)
    print("ok   two releases of one call: one BYE transaction per side")
    print("PASS")


if __name__ == "__main__":
    main()

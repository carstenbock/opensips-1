#!/usr/bin/env python3
"""UE and core for test/ipsec-tcp-reconnect/run.sh (KI-150), run in a
container at 172.30.96.20 with NET_ADMIN.

The UE registers (unprotected REGISTER, Security-Client with hmac-md5-96 and null encryption),
the core answers 401 with AKA ik/ck, the gateway creates the SAs and the UE
mirrors them with ip xfrm. Then the core sends MESSAGEs that the gateway
relays to the UE's protected server port over TCP from its protected client
port (TS 33.203 7.1):
  1. first MESSAGE: new TCP connection, 200 back to the core
  2. second MESSAGE: same connection (reused, no new connect)
  3. the gateway closes the idle connection (tcp_connection_lifetime) and
     holds its TIME_WAIT. Third MESSAGE: the connect collides; the request
     must still reach the UE and the core must get the 200. The UE drops the
     first UDP copy, so this needs tm's UDP retransmission (RFC 3261
     17.1.1.2): a copy sent behind tm's back is never repeated.
"""
import re
import socket
import subprocess
import sys
import time

GW, ME = "172.30.96.10", "172.30.96.20"
UE_PORT_C, UE_PORT_S = 6200, 6201
UE_SPI_C, UE_SPI_S = 0x2001, 0x2002
IK, CK = "00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100"
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def udp(port, timeout=0.2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ME, port))
    s.settimeout(timeout)
    return s


ue_plain, core, ue_udp = udp(5060), udp(5070), udp(UE_PORT_S)
ue_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ue_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ue_tcp.bind((ME, UE_PORT_S))
ue_tcp.listen(4)
ue_tcp.settimeout(0.2)


def hdr(msg, name):
    m = re.search(r"^%s:\s*(.*)$" % name, msg, re.I | re.M)
    return m.group(1).strip() if m else None


def reply(msg, code, reason, extra=""):
    keep = [l for l in msg.split("\r\n")
            if re.match(r"^(Via|From|Call-ID|CSeq):", l, re.I)]
    to = hdr(msg, "To")
    if ";tag=" not in to:
        to += ";tag=t1"
    return ("SIP/2.0 %d %s\r\n" % (code, reason) + "\r\n".join(keep)
            + "\r\nTo: " + to + "\r\n" + extra + "Content-Length: 0\r\n\r\n").encode()


def register():
    req = ("REGISTER sip:test SIP/2.0\r\n"
           "Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK-reg-%d;rport\r\n"
           "From: <sip:alice@test>;tag=r1\r\nTo: <sip:alice@test>\r\n"
           "Call-ID: ipsec-tcp-reg\r\nCSeq: %d REGISTER\r\nMax-Forwards: 70\r\n"
           "Contact: <sip:alice@%s:%d>\r\nExpires: 600\r\n"
           "Security-Client: ipsec-3gpp;alg=hmac-md5-96;ealg=null;spi-c=%d;spi-s=%d;"
           "port-c=%d;port-s=%d;prot=esp;mod=trans\r\n"
           "Require: sec-agree\r\nProxy-Require: sec-agree\r\nSupported: sec-agree\r\n"
           "Content-Length: 0\r\n\r\n")
    deadline, n = time.time() + 30, 0
    while time.time() < deadline:  # resent until the gateway is up
        n += 1
        ue_plain.sendto((req % (ME, n, n, ME, UE_PORT_S, UE_SPI_C, UE_SPI_S,
                                UE_PORT_C, UE_PORT_S)).encode(), (GW, 5060))
        end = time.time() + 1
        while time.time() < end:
            try:
                data, peer = core.recvfrom(65535)
                msg = data.decode()
                if msg.startswith("REGISTER"):
                    core.sendto(reply(msg, 401, "Unauthorized",
                                      'WWW-Authenticate: Digest realm="test", '
                                      'nonce="bm9uY2U=", algorithm=AKAv1-MD5, qop="auth", '
                                      'ik="%s", ck="%s"\r\n' % (IK, CK)), peer)
            except socket.timeout:
                pass
            try:
                data = ue_plain.recv(65535).decode()
                if data.startswith("SIP/2.0 401"):
                    return hdr(data, "Security-Server")
            except socket.timeout:
                pass
    return None


def xfrm(*args):
    subprocess.run(["ip", "xfrm"] + list(args), check=True)


def setup_sas(sec_server):
    p = dict(kv.split("=", 1) for kv in sec_server.split(";")[1:] if "=" in kv)
    gw_spi_c, gw_port_c = int(p["spi-c"]), int(p["port-c"])
    # hmac-md5-96 keyed with IK (TS 33.203 Annex I), no encryption
    null = ["auth-trunc", "hmac(md5)", "0x" + IK, "96", "enc", "cipher_null", ""]
    # gateway protected client port -> UE protected server port
    xfrm("state", "add", "src", GW, "dst", ME, "proto", "esp", "spi", str(UE_SPI_S),
         "mode", "transport", *null)
    # UE protected server port -> gateway protected client port (replies)
    xfrm("state", "add", "src", ME, "dst", GW, "proto", "esp", "spi", str(gw_spi_c),
         "mode", "transport", *null)
    for proto in ("tcp", "udp"):
        xfrm("policy", "add", "src", ME + "/32", "dst", GW + "/32", "proto", proto,
             "sport", str(UE_PORT_S), "dport", str(gw_port_c), "dir", "out",
             "tmpl", "src", ME, "dst", GW, "proto", "esp", "spi", str(gw_spi_c),
             "mode", "transport")
    return gw_port_c


def message(n):
    return ("MESSAGE sip:alice@test SIP/2.0\r\n"
            "Via: SIP/2.0/UDP %s:5070;branch=z9hG4bK-msg-%d\r\n"
            "From: <sip:core@test>;tag=c%d\r\nTo: <sip:alice@test>\r\n"
            "Call-ID: ipsec-tcp-msg-%d\r\nCSeq: 1 MESSAGE\r\nMax-Forwards: 70\r\n"
            "Content-Length: 0\r\n\r\n" % (ME, n, n, n)).encode()


def read_sip(conn, buf):
    """one SIP message from a TCP connection: (message, rest) or (None, b'')
    on EOF"""
    while b"\r\n\r\n" not in buf:
        try:
            data = conn.recv(65535)
        except socket.timeout:
            continue
        if not data:
            return None, b""
        buf += data
    head, rest = buf.split(b"\r\n\r\n", 1)
    clen = int(hdr(head.decode(), "Content-Length") or 0)
    return head.decode() + "\r\n\r\n", rest[clen:]


class UE:
    def __init__(self):
        self.conn, self.peer, self.buf, self.accepts = None, None, b"", 0
        self.udp_seen = 0

    def poll(self, drop_first_udp):
        """serves one pending request, if any; returns how it came in"""
        try:
            c, peer = ue_tcp.accept()
            c.settimeout(0.2)
            self.conn, self.peer, self.buf = c, peer, b""
            self.accepts += 1
        except socket.timeout:
            pass
        if self.conn:
            self.conn.settimeout(0.05)
            try:
                data = self.conn.recv(65535)
                if not data:
                    self.conn.close()
                    self.conn = None
                    return "eof"
                self.buf += data
            except socket.timeout:
                pass
            if b"\r\n\r\n" in self.buf:
                msg, self.buf = read_sip(self.conn, self.buf)
                if msg and msg.startswith("MESSAGE"):
                    self.conn.sendall(reply(msg, 200, "OK"))
                    return "tcp"
        try:
            data, peer = ue_udp.recvfrom(65535)
            msg = data.decode()
            if msg.startswith("MESSAGE"):
                self.udp_seen += 1
                if drop_first_udp and self.udp_seen == 1:
                    return "udp-dropped"
                ue_udp.sendto(reply(msg, 200, "OK"), peer)
                return "udp"
        except socket.timeout:
            pass
        return None


def send(ue, n, drop_first_udp=False, seconds=6):
    """core sends MESSAGE n; returns (final code, transports the UE saw)"""
    core.sendto(message(n), (GW, 5060))
    seen, code, end = [], None, time.time() + seconds
    while time.time() < end and code is None:
        how = ue.poll(drop_first_udp)
        if how and how != "eof":
            seen.append(how)
        try:
            data = core.recv(65535).decode()
            c = int(data.split(" ", 2)[1])
            if c >= 200 and "ipsec-tcp-msg-%d" % n in data:
                code = c
        except socket.timeout:
            pass
    return code, seen


def main():
    sec = register()
    check(sec is not None, "401 with Security-Server (%s)" % sec)
    if not sec:
        return 1
    gw_port_c = setup_sas(sec)
    ue = UE()

    code, seen = send(ue, 1)
    check(code == 200 and seen == ["tcp"] and ue.accepts == 1
          and ue.peer and ue.peer[1] == gw_port_c,
          "1st MESSAGE over a new TCP connection from the protected client "
          "port %s (code %s, %s)" % (ue.peer, code, seen))

    code, seen = send(ue, 2)
    check(code == 200 and seen == ["tcp"] and ue.accepts == 1,
          "2nd MESSAGE reuses the connection (code %s, %s, %d connects)"
          % (code, seen, ue.accepts))

    # the gateway closes the idle connection: its side keeps the TIME_WAIT
    end = time.time() + 10
    while ue.conn and time.time() < end:
        ue.poll(False)
    check(ue.conn is None, "gateway closed the idle connection")

    code, seen = send(ue, 3, drop_first_udp=True)
    check(code == 200, "3rd MESSAGE after the close reaches the UE, core got %s "
          "(UE saw %s)" % (code, seen))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

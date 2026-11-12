#!/usr/bin/env python3
"""Minimal Diameter Cx peer for test/auth-aka-mar-error/run.sh (TCP
127.0.0.1:3868, Origin-Host hss.test, realm test). Answers CER and DWR, and
answers a MAR by the User-Name it carries:
  unknown...  Experimental-Result DIAMETER_ERROR_USER_UNKNOWN (5001, TS 29.229)
  silent...   no answer at all (auth_aka's async_timeout runs out)
  anything else  Result-Code DIAMETER_UNABLE_TO_COMPLY (5012)
"""
import socket
import struct
import sys
import threading

HOST, REALM, VENDOR_3GPP, CX = b"hss.test", b"test", 10415, 16777216


def avp(code, data, vendor=0, mandatory=True):
    flags = (0x80 if vendor else 0) | (0x40 if mandatory else 0)
    hdr_len = 12 if vendor else 8
    length = hdr_len + len(data)
    out = struct.pack("!IB", code, flags) + length.to_bytes(3, "big")
    if vendor:
        out += struct.pack("!I", vendor)
    return out + data + b"\0" * ((4 - len(data) % 4) % 4)


def u32(code, val, vendor=0):
    return avp(code, struct.pack("!I", val), vendor)


def grouped(code, *avps, vendor=0):
    return avp(code, b"".join(avps), vendor)


def parse_avps(data):
    out, i = [], 0
    while i + 8 <= len(data):
        code, flags = struct.unpack("!IB", data[i:i + 5])
        length = int.from_bytes(data[i + 5:i + 8], "big")
        hl = 12 if flags & 0x80 else 8
        out.append((code, data[i + hl:i + length]))
        i += (length + 3) & ~3
    return out


def answer(req_hdr, avps):
    _, _, flags, code, app, hbh, e2e = req_hdr
    body = b"".join(avps)
    length = 20 + len(body)
    return (bytes([1]) + length.to_bytes(3, "big") + bytes([flags & 0x7f])  # answer: R bit cleared
            + code.to_bytes(3, "big") + struct.pack("!III", app, hbh, e2e) + body)


def origin():
    return [avp(264, HOST), avp(296, REALM)]


def handle(conn):
    buf = b""
    while True:
        data = conn.recv(65535)
        if not data:
            return
        buf += data
        while len(buf) >= 20:
            length = int.from_bytes(buf[1:4], "big")
            if len(buf) < length:
                break
            msg, buf = buf[:length], buf[length:]
            flags = msg[4]
            code = int.from_bytes(msg[5:8], "big")
            app, hbh, e2e = struct.unpack("!III", msg[8:20])
            hdr = (1, length, flags, code, app, hbh, e2e)
            avps = dict(parse_avps(msg[20:]))
            if not flags & 0x80:
                continue  # an answer (e.g. DWA): nothing to do
            if code == 257:  # CER
                rpl = [u32(268, 2001)] + origin() + [
                    avp(257, b"\x00\x01" + socket.inet_aton("127.0.0.1")),
                    u32(266, 0), avp(269, b"fake-hss", mandatory=False),
                    grouped(260, u32(266, VENDOR_3GPP), u32(258, CX))]
            elif code == 280:  # DWR
                rpl = [u32(268, 2001)] + origin()
            elif code == 303:  # MAR
                user = avps.get(1, b"")
                print("fake HSS: MAR for", user.decode(errors="replace"), flush=True)
                if user.startswith(b"silent"):
                    continue
                rpl = [avp(263, avps.get(263, b"")),
                       grouped(260, u32(266, VENDOR_3GPP), u32(258, CX)),
                       u32(277, 1)] + origin()
                if user.startswith(b"unknown"):
                    rpl.append(grouped(297, u32(266, VENDOR_3GPP), u32(298, 5001)))
                else:
                    rpl.append(u32(268, 5012))
            else:
                print("fake HSS: unexpected command", code, flush=True)
                continue
            conn.sendall(answer(hdr, rpl))


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 3868))
    srv.listen(4)
    print("fake HSS: listening", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Unofficial client for the OptiCut S90 HMI's TCP list protocol (port 51000).

The specification is SPEC.md; this file is its executable form and the tests
in tests/ check the two against each other. Python 3.8+, standard library only.

    opticut51000.py <host> upload <file.xml>   send one list to the saw
    opticut51000.py <host> list                the saw's list directory: id, store, name
    opticut51000.py <host> fetch <name|id>     print a list as the saw holds it now

`list` and `fetch` only work while no older client (for example the vendor's
PC software) is connected: the HMI answers one connection at a time (SPEC §3.3).
There is deliberately no delete command.

Unofficial; not affiliated with Weinig or Dimter. Use at your own risk.
"""
import argparse
import re
import socket
import struct
import sys
import time

PORT = 51000
HEADER = struct.Struct("<iii")  # cmd, length, x  (little-endian int32, SPEC §2)
CMD_KEEPALIVE, CMD_UPLOAD, CMD_UPLOAD_END, CMD_LISTOP = 45, 150, 151, 6
DIR_SIZE, REC = 122200, 240  # directory buffer and record size, SPEC §3.4
OP_FETCH = ord("e")  # cmd 6 sub-operation, SPEC §5


def frame(cmd, body=b""):
    """One message: 12-byte header + body. The third header field is unused; send 0."""
    return HEADER.pack(cmd, len(body), 0) + body


def parse(stream):
    """Split a byte stream into [(cmd, x, body)]; stops at a partial message."""
    out, i = [], 0
    while i + HEADER.size <= len(stream):
        cmd, n, x = HEADER.unpack_from(stream, i)
        if n < 0 or i + HEADER.size + n > len(stream):
            break
        out.append((cmd, x, stream[i + HEADER.size:i + HEADER.size + n]))
        i += HEADER.size + n
    return out


def upload_bytes(xml):
    """The exact bytes of one list upload: (keepalive, 150 + 151)."""
    if isinstance(xml, str):
        xml = xml.encode("utf-8")
    if not re.search(rb"<Product>.*<Name>[^<]+</Name>.*</Product>", xml, re.S):
        raise ValueError("not a <Product> list document with a <Name>")
    return frame(CMD_KEEPALIVE), frame(CMD_UPLOAD, xml) + frame(CMD_UPLOAD_END)


def directory_entries(body):
    """Parse a cmd 6 directory body into [(id, store, name)] (SPEC §3.4)."""
    out = []
    for k in range(len(body) // REC):
        rec = body[k * REC:(k + 1) * REC]
        raw = rec[32:72].split(b"\0")[0]  # 40-byte name field, NUL-terminated
        try:
            name = raw.decode("ascii")
        except UnicodeDecodeError:
            break  # uninitialised memory after the last record
        if not name or not name.isprintable():
            break
        store, ident = struct.unpack_from("<ii", rec, 72)
        out.append((ident, store, name))
    return out


def fetch_body(list_id):
    """cmd 6 'e' body: fetch one list by id (SPEC §5.1). Read-only."""
    body = bytearray(176)
    body[0] = OP_FETCH
    struct.pack_into("<ii", body, 8, 1, list_id)
    return bytes(body)


def _session(host, port, send=b"", wait=3.0, until=None):
    """Connect, send a keepalive, optionally send `send` after 0.5 s, and
    collect messages for up to `wait` seconds (or until `until(messages)`)."""
    buf = b""
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(0.2)
        s.sendall(frame(CMD_KEEPALIVE))
        start = time.time()
        sent = not send
        while time.time() - start < wait:
            if not sent and time.time() - start > 0.5:
                s.sendall(send)
                sent = True
            try:
                d = s.recv(65536)
                if not d:
                    break
                buf += d
            except socket.timeout:
                pass
            if until and until(parse(buf)):
                break
    return parse(buf)


def directory(host, port=PORT, wait=3.0):
    """The saw's list directory as [(id, store, name)], or None when the HMI
    is serving another client."""
    def got_dir(msgs):
        return any(c == CMD_LISTOP and len(b) == DIR_SIZE for c, _, b in msgs)
    for cmd, _, body in _session(host, port, wait=wait, until=got_dir):
        if cmd == CMD_LISTOP and len(body) == DIR_SIZE:
            return directory_entries(body)
    return None


def fetch(list_id, host, port=PORT, wait=5.0):
    """The list document as the saw holds it now (Cut counts included), or None."""
    msgs = _session(host, port, send=frame(CMD_LISTOP, fetch_body(list_id)), wait=wait,
                    until=lambda m: any(c == CMD_UPLOAD_END for c, _, _ in m))
    xml = [b for c, _, b in msgs if c == CMD_UPLOAD]
    return xml[0] if xml else None


def upload(xml, host, port=PORT, pause=0.5, hold=20.0):
    """Send one list. The HMI sends no acknowledgement: success here means
    'delivered', not 'saved' (SPEC §4). The socket stays open for `hold` seconds,
    which is the sequence the vendor software uses."""
    hello, payload = upload_bytes(xml)
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(hello)
        time.sleep(pause)
        s.sendall(payload)
        time.sleep(hold)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host", help="HMI host name or IP address (required)")
    ap.add_argument("--port", type=int, default=PORT)
    sub = ap.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("upload", help="send one list document to the saw")
    u.add_argument("file")
    u.add_argument("--hold", type=float, default=20.0,
                   help="seconds to keep the socket open after sending (default 20)")
    sub.add_parser("list", help="print the saw's list directory")
    f = sub.add_parser("fetch", help="print one list as the saw holds it now")
    f.add_argument("which", help="list name or id")
    a = ap.parse_args(argv)

    if a.cmd == "upload":
        with open(a.file, "rb") as fh:
            xml = fh.read()
        name = re.search(rb"<Name>([^<]+)</Name>", xml)
        upload(xml, a.host, a.port, hold=a.hold)
        print(f"uploaded {name.group(1).decode() if name else a.file} "
              f"({len(xml)} bytes) to {a.host}:{a.port}")
        return 0

    d = directory(a.host, a.port)
    if d is None:
        sys.exit("no directory: the HMI is serving another client (close the PC software)")
    if a.cmd == "list":
        for ident, store, name in d:
            print(f"{ident:4d}  {'oxml' if store == 2 else 'pxml' if store == 1 else store}  {name}")
        return 0
    ids = [i for i, _, n in d if n == a.which or str(i) == a.which]
    if not ids:
        sys.exit(f"{a.which}: not on the saw")
    xml = fetch(ids[0], a.host, a.port)
    if xml is None:
        sys.exit("no reply to the fetch")
    sys.stdout.write(xml.decode("utf-8", "replace") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

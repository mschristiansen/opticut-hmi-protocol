"""A localhost stand-in for the saw's HMI, just enough of SPEC.md to test a client.

    hmi = FakeHMI()          # listens on 127.0.0.1, random port
    hmi.port, hmi.lists      # connect here; lists = {name: (id, store, xml_bytes)}
    hmi.close()

Behaviour (SPEC §3):
  * it answers ONE connection at a time: the oldest live one (§3.3);
  * on that connection's first keepalive it pushes the directory (cmd 6, 122200 bytes);
  * cmd 150 + 151 from ANY connection adds a list (store from <Type>: 1 for MODE_SCHNITTFOLGE, else 2; next free id);
  * cmd 6 'e' from the served connection replies 150 (document) + 151 (1432-byte sidecar);
  * every other command is ignored; cmd 6 'i' is recorded in `ignored` and NOT executed.
"""
import re
import socket
import struct
import threading

HEADER = struct.Struct("<iii")
DIR_SIZE, REC = 122200, 240


def synthetic_directory(entries):
    """Build a directory buffer from [(id, store, name)].

    Records are 240 bytes: name at +32 (40 bytes, NUL-terminated), store at +72,
    id at +76. Everything after the last record is filler that is NOT a valid
    name, like the uninitialised memory the real buffer carries.
    """
    buf = bytearray(b"\xcd" * DIR_SIZE)
    for k, (ident, store, name) in enumerate(entries):
        rec = bytearray(REC)
        rec[32:32 + len(name)] = name.encode("ascii")
        struct.pack_into("<ii", rec, 72, store, ident)
        buf[k * REC:(k + 1) * REC] = rec
    # the record after the last one has an empty name: ends the useful part
    end = len(entries) * REC
    buf[end:end + REC] = bytes(REC)
    return bytes(buf)


def synthetic_list(name, lengths=((2400, 4), (1200, 8))):
    """A minimal valid list document, enough for the fake to serve back."""
    parts = "".join(
        f'<Part ID="{i}" TYPE="FIX"><MinLen>{l:.3f}</MinLen><MaxLen>{l:.3f}</MaxLen>'
        f"<Required>{n}</Required><Cut>0</Cut><Grade>1</Grade><Mode>16</Mode></Part>"
        for i, (l, n) in enumerate(lengths, 1))
    return (f'<?xml version="1.0" encoding="UTF-8"?><Product><Name>{name}</Name>'
            f"<Type>MODE_OPTIMIERUNG</Type><PartList>{parts}</PartList></Product>\n").encode()


def frame(cmd, body=b""):
    return HEADER.pack(cmd, len(body), 0) + body


class FakeHMI:
    def __init__(self, seed=(("DEMO1", 2), ("DEMO2", 2), ("PATTERN", 1))):
        self.lists = {}
        self.ignored = []          # (cmd, body) the fake received but does not implement
        self.next_id = 1
        for name, store in seed:
            self._add(name, store, synthetic_list(name))
        self._lock = threading.Lock()
        self._conns = []           # live connections, oldest first
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._closed = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _add(self, name, store, xml):
        # Re-uploading a name keeps its id: replace-by-name is an ASSUMPTION (SPEC §4, [I]),
        # not something that was measured.
        ident = self.lists[name][0] if name in self.lists else self.next_id
        if name not in self.lists:
            self.next_id += 1
        self.lists[name] = (ident, store, xml)

    def directory(self):
        return synthetic_directory(
            sorted(((i, st, n) for n, (i, st, _) in self.lists.items())))

    def _accept(self):
        while not self._closed:
            try:
                c, _ = self._srv.accept()
            except OSError:
                return
            with self._lock:
                self._conns.append(c)
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _is_oldest(self, c):
        with self._lock:
            return bool(self._conns) and self._conns[0] is c

    def _serve(self, c):
        buf, pending_upload, greeted = b"", None, False
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                buf += d
                while len(buf) >= HEADER.size:
                    cmd, n, _x = HEADER.unpack_from(buf)
                    if n < 0 or len(buf) < HEADER.size + n:
                        break
                    body = buf[HEADER.size:HEADER.size + n]
                    buf = buf[HEADER.size + n:]
                    if cmd == 45 and not greeted and self._is_oldest(c):
                        greeted = True
                        c.sendall(frame(6, self.directory()))
                    elif cmd == 150:
                        pending_upload = body
                    elif cmd == 151 and pending_upload is not None:
                        m = re.search(rb"<Name>([^<]+)</Name>", pending_upload)
                        if m:
                            store = 1 if b"MODE_SCHNITTFOLGE" in pending_upload else 2
                            with self._lock:
                                self._add(m.group(1).decode(), store, pending_upload)
                        pending_upload = None
                    elif cmd == 6 and len(body) == 176 and body[:1] == b"e":
                        if self._is_oldest(c):
                            list_id = struct.unpack_from("<i", body, 12)[0]
                            for ident, _st, xml in list(self.lists.values()):
                                if ident == list_id:
                                    c.sendall(frame(150, xml) + frame(151, bytes(1432)))
                    elif cmd != 45:
                        self.ignored.append((cmd, body))
        except OSError:
            pass
        finally:
            with self._lock:
                if c in self._conns:
                    self._conns.remove(c)
            c.close()

    def close(self):
        self._closed = True
        self._srv.close()
        with self._lock:
            for c in list(self._conns):
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

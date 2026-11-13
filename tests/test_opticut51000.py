"""Checks opticut51000.py against SPEC.md, and runs it against a fake HMI.

    python -m unittest            (from the repository root)
"""
import contextlib
import io
import os
import socket
import struct
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import opticut51000 as oc  # noqa: E402
from fake_hmi import FakeHMI, synthetic_directory, synthetic_list  # noqa: E402

HELLO = os.path.join(ROOT, "examples", "hello.xml")
LOCAL = "127.0.0.1"


def hello_bytes():
    with open(HELLO, "rb") as fh:
        return fh.read()


class Framing(unittest.TestCase):
    def test_keepalive_bytes(self):
        self.assertEqual(oc.frame(45), bytes.fromhex("2d000000" "00000000" "00000000"))

    def test_x_is_ignored_on_receive(self):
        stream = bytes.fromhex("2d000000" "00000000" "8e4f4800")  # x = garbage
        self.assertEqual(oc.parse(stream), [(45, 0x00484F8E, b"")])

    def test_header_fields(self):
        h = oc.frame(150, b"abc")[:12]
        self.assertEqual(oc.HEADER.unpack(h), (150, 3, 0))

    def test_partial_message_is_not_returned(self):
        self.assertEqual(oc.parse(oc.frame(150, b"<?xml")[:-1]), [])

    def test_two_messages_back_to_back(self):
        got = oc.parse(oc.frame(150, b"xy") + oc.frame(151))
        self.assertEqual([(c, b) for c, _, b in got], [(150, b"xy"), (151, b"")])


class UploadBytes(unittest.TestCase):
    def test_hello_file_is_valid(self):
        xml = hello_bytes()
        hello, payload = oc.upload_bytes(xml)
        self.assertEqual(oc.parse(hello), [(45, 0, b"")])
        msgs = oc.parse(payload)
        self.assertEqual([(c, x, len(b)) for c, x, b in msgs],
                         [(150, 0, len(oc.compact(xml))), (151, 0, 0)])
        self.assertEqual(msgs[0][2], oc.compact(xml))

    def test_non_list_is_refused(self):
        with self.assertRaises(ValueError):
            oc.upload_bytes("<html>not a list</html>")


class Directory(unittest.TestCase):
    def test_parse_synthetic_directory(self):
        d = synthetic_directory([(1, 2, "A"), (7, 1, "SEQ"), (9, 2, "B" * 39)])
        self.assertEqual(len(d), oc.DIR_SIZE)
        self.assertEqual(oc.directory_entries(d),
                         [(1, 2, "A"), (7, 1, "SEQ"), (9, 2, "B" * 39)])

    def test_filler_after_last_record_is_not_a_list(self):
        d = synthetic_directory([(1, 2, "A")])
        self.assertEqual([n for _, _, n in oc.directory_entries(d)], ["A"])

    def test_record_layout(self):
        d = synthetic_directory([(5, 2, "X")])
        self.assertEqual(d[32:33], b"X")
        self.assertEqual(struct.unpack_from("<ii", d, 72), (2, 5))

    def test_fetch_body(self):
        b = oc.fetch_body(5)
        self.assertEqual((len(b), b[:1], struct.unpack_from("<ii", b, 8)), (176, b"e", (1, 5)))
        self.assertEqual(b[1:8] + b[16:], bytes(7 + 160))


class AgainstFakeHMI(unittest.TestCase):
    def setUp(self):
        self.hmi = FakeHMI()
        self.addCleanup(self.hmi.close)

    def test_hello_world_upload(self):
        oc.upload(hello_bytes(), LOCAL, self.hmi.port, pause=0.05, hold=0.2)
        self.assertIn("HELLO", self.hmi.lists)
        self.assertEqual(self.hmi.lists["HELLO"][2], oc.compact(hello_bytes()))
        self.assertNotIn(b"\n", self.hmi.lists["HELLO"][2])

    def test_directory(self):
        d = oc.directory(LOCAL, self.hmi.port)
        self.assertEqual(d, [(1, 2, "DEMO1"), (2, 2, "DEMO2"), (3, 1, "PATTERN")])

    def test_uploaded_list_shows_up_in_directory(self):
        oc.upload(hello_bytes(), LOCAL, self.hmi.port, pause=0.05, hold=0.2)
        names = [n for _, _, n in oc.directory(LOCAL, self.hmi.port)]
        self.assertIn("HELLO", names)

    def test_cut_sequence_goes_to_store_1(self):
        xml = synthetic_list("SEQ1").replace(b"MODE_OPTIMIERUNG", b"MODE_SCHNITTFOLGE")
        oc.upload(xml, LOCAL, self.hmi.port, pause=0.05, hold=0.2)
        self.assertIn((4, 1, "SEQ1"), oc.directory(LOCAL, self.hmi.port))

    def test_fetch(self):
        self.assertEqual(oc.fetch(2, LOCAL, self.hmi.port), synthetic_list("DEMO2"))

    def test_fetch_unknown_id_gets_no_reply(self):
        self.assertIsNone(oc.fetch(99, LOCAL, self.hmi.port, wait=0.8))

    def test_directory_is_none_while_another_client_is_served(self):
        older = socket.create_connection((LOCAL, self.hmi.port))
        self.addCleanup(older.close)
        older.sendall(oc.frame(45))
        time.sleep(0.3)  # the fake now serves `older`
        self.assertIsNone(oc.directory(LOCAL, self.hmi.port, wait=0.8))

    def test_upload_works_while_another_client_is_served(self):
        older = socket.create_connection((LOCAL, self.hmi.port))
        self.addCleanup(older.close)
        older.sendall(oc.frame(45))
        time.sleep(0.3)
        oc.upload(hello_bytes(), LOCAL, self.hmi.port, pause=0.05, hold=0.2)
        self.assertIn("HELLO", self.hmi.lists)

    def test_client_never_sends_delete_or_toggle(self):
        oc.directory(LOCAL, self.hmi.port)
        oc.fetch(1, LOCAL, self.hmi.port)
        oc.upload(hello_bytes(), LOCAL, self.hmi.port, pause=0.05, hold=0.2)
        self.assertEqual(self.hmi.ignored, [])
        self.assertFalse(hasattr(oc, "delete"))


class Cli(unittest.TestCase):
    def test_host_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            oc.main([])

    def test_list_and_fetch_via_cli(self):
        hmi = FakeHMI()
        self.addCleanup(hmi.close)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            oc.main([LOCAL, "--port", str(hmi.port), "list"])
            oc.main([LOCAL, "--port", str(hmi.port), "fetch", "DEMO1"])
        text = out.getvalue()
        self.assertIn("DEMO2", text)
        self.assertIn("<Name>DEMO1</Name>", text)

    def test_upload_via_cli(self):
        hmi = FakeHMI()
        self.addCleanup(hmi.close)
        with contextlib.redirect_stdout(io.StringIO()):
            oc.main([LOCAL, "--port", str(hmi.port), "upload", HELLO, "--hold", "0.2"])
        self.assertIn("HELLO", hmi.lists)


if __name__ == "__main__":
    unittest.main()

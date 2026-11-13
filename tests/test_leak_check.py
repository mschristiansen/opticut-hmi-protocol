"""The leak check must catch what it exists to catch. Terms here are made up."""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import leak_check  # noqa: E402

TERMS = {"zanzibar", "qux"}


def w(*parts):
    return "".join(parts)


class LeakCheck(unittest.TestCase):
    def scan(self, text, terms=TERMS):
        return leak_check.scan_text("t", text, terms)

    def test_clean_text(self):
        self.assertEqual(self.scan("HELLO at 192.0.2.10 and 127.0.0.1, noreply@example.com"), [])

    def test_long_term_matches_anywhere_and_in_any_case(self):
        self.assertTrue(self.scan("a ZanzibarSavvy b"))
        self.assertTrue(self.scan("zanzibar_123"))

    def test_short_term_matches_whole_words_only(self):
        self.assertTrue(self.scan("who is Qux here"))
        self.assertEqual(self.scan("quxx is fine"), [])

    def test_matching_word_is_not_echoed(self):
        self.assertNotIn("zanzibar", " ".join(self.scan("zanzibar")).casefold())

    def test_private_ip(self):
        self.assertTrue(self.scan(w("host 192", ".168", ".1.5")))
        self.assertTrue(self.scan(w("host 10", ".1.2.3")))

    def test_email(self):
        self.assertTrue(self.scan(w("someone@corp", ".invalid")))
        self.assertEqual(self.scan("437005+someone@users.noreply.github.com"), [])

    def test_tracker_id(self):
        self.assertTrue(self.scan(w("AB", "C-", "123")))

    def test_author_words_only_in_author_files(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("LICENSE", "README.md"):
                with open(os.path.join(d, name), "w") as fh:
                    fh.write(w("Copyright Mik", "kel Christiansen\n"))
            found = leak_check.scan_files(d, {w("mik", "kel")})
            self.assertEqual([f.split(":")[0] for f in found], ["README.md"])

    def test_require_terms(self):
        old = os.environ.pop("LEAK_EXTRA_TERMS", None)
        try:
            self.assertEqual(leak_check.main(["--require-terms"]), 1)
        finally:
            if old is not None:
                os.environ["LEAK_EXTRA_TERMS"] = old

    def test_git_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            def g(*a):
                subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)
            g("init", "-q")
            with open(os.path.join(d, "f.txt"), "w") as fh:
                fh.write("hello\n")
            g("add", "f.txt")
            g("-c", "user.name=Some Body", "-c", w("user.email=x@corp", ".invalid"),
              "commit", "-qm", "init")
            found = leak_check.scan_git(d, set())
            self.assertTrue([f for f in found if "e-mail" in f])
            self.assertTrue([f for f in found if "name" in f])


if __name__ == "__main__":
    unittest.main()

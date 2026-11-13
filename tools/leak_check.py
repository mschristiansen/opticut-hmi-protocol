#!/usr/bin/env python3
"""Leak check: fails if the repository contains traces that must not be public.

    LEAK_EXTRA_TERMS="word1,word2" python tools/leak_check.py [--require-terms]

The list of forbidden words is NOT stored in this repository (a list of hashes can be
cracked, a list of words is the leak). It is read from the LEAK_EXTRA_TERMS environment
variable, comma-separated; CI takes it from a repository secret. `--require-terms` makes
a missing or empty variable an error, so CI cannot pass by accident.

Checks
  * forbidden words, case-folded: terms of 4+ characters match anywhere in a line
    (so run-together words are caught), shorter terms match whole words only;
  * generic patterns: IPv4 addresses outside loopback and the RFC 5737 documentation
    ranges, e-mail addresses other than GitHub/Anthropic no-reply and example.*,
    and tracker ids (letters, a dash, digits);
  * git metadata of every commit and ref: author/committer name and e-mail, message,
    branch and tag names. Only the author's own identity below may appear.

Exit status 0 = clean, 1 = findings (file:line and rule; a matching word is never echoed).
"""
import hashlib
import os
import re
import subprocess
import sys

# The author's public identity (name in the licence, commit address as a hash).
AUTHOR_NAMES = {"Mikkel Christiansen", "GitHub", "Claude Sonnet 5.5"}
AUTHOR_EMAIL_SHA256 = {"fc47420af5b6a220e84412187bed064b162ba36c4711f10f03ba2b4a7417dcf1"}
# Files that may name the author.
AUTHOR_WORDS = {"mikkel", "christiansen"}
AUTHOR_FILES = {"LICENSE", "leak_check.py"}

WORD = re.compile(r"[^\W_]+", re.UNICODE)
IPV4 = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w.]*\d)")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
TICKET = re.compile(r"\b[A-Z]{2,5}-\d{2,6}\b")
TICKET_OK = {"SHA", "UTF", "RFC", "ISO"}
EMAIL_OK = re.compile(r"(@users\.noreply\.github\.com|^noreply@(github|anthropic)\.com"
                      r"|@example\.(com|org|net))$", re.I)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ip_ok(a, b, c, d):
    a, b, c, d = int(a), int(b), int(c), int(d)
    if max(a, b, c, d) > 255:
        return True  # not an address (version number etc.)
    return (a == 127 or (a, b, c) in {(192, 0, 2), (198, 51, 100), (203, 0, 113)}
            or (a, b, c, d) == (0, 0, 0, 0))


def scan_text(label, text, terms, skip_words=frozenset()):
    """Findings for one text blob. `terms` is a set of case-folded forbidden words."""
    found = []
    long_terms = [t for t in terms if len(t) >= 4]
    short_terms = {t for t in terms if len(t) < 4}
    for n, line in enumerate(text.splitlines(), 1):
        folded = line.casefold()
        for w in WORD.findall(folded):
            if w in skip_words:
                continue
            if w in short_terms:
                found.append(f"{label}:{n}: forbidden word (short term)")
        for t in long_terms:
            start = 0
            while True:
                i = folded.find(t, start)
                if i < 0:
                    break
                start = i + len(t)
                if t in skip_words:
                    continue
                found.append(f"{label}:{n}: forbidden term at column {i + 1}")
        for m in IPV4.finditer(line):
            if not ip_ok(*m.groups()):
                found.append(f"{label}:{n}: IPv4 address outside documentation ranges")
        for m in EMAIL.finditer(line):
            if not EMAIL_OK.search(m.group(0)):
                found.append(f"{label}:{n}: e-mail address {m.group(0)}")
        for m in TICKET.finditer(line):
            if m.group(0).split("-")[0] not in TICKET_OK:
                found.append(f"{label}:{n}: tracker id {m.group(0)}")
    return found


def git(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True,
                          check=True).stdout


def tracked_files(root):
    try:
        names = git(root, "ls-files", "-z").split("\0")
    except (subprocess.CalledProcessError, FileNotFoundError):
        names = [os.path.relpath(os.path.join(d, f), root)
                 for d, dirs, fs in os.walk(root) for f in fs if ".git" not in d.split(os.sep)]
    return [n for n in names if n]


def scan_files(root, terms):
    found = []
    for name in tracked_files(root):
        try:
            with open(os.path.join(root, name), "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        if b"\0" in raw:
            found.append(f"{name}: binary file in the repository")
            continue
        skip = AUTHOR_WORDS if os.path.basename(name) in AUTHOR_FILES else frozenset()
        found += scan_text(name, raw.decode("utf-8", "replace"), terms, skip)
        found += scan_text(name + " [path]", name.replace("/", " "), terms)
    return found


def scan_git(root, terms):
    found = []
    try:
        log = git(root, "log", "--all", "--format=%an%x09%ae%x09%cn%x09%ce%x09%B%x1e")
        refs = git(root, "for-each-ref", "--format=%(refname)")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ["git metadata could not be read"]
    for k, rec in enumerate(r for r in log.split("\x1e") if r.strip()):
        an, ae, cn, ce, body = (rec.strip("\n").split("\t", 4) + [""] * 5)[:5]
        for who, mail in ((an, ae), (cn, ce)):
            if who not in AUTHOR_NAMES:
                found.append(f"commit #{k}: author/committer name not allowed")
            if not EMAIL_OK.search(mail) and sha(mail.casefold()) not in AUTHOR_EMAIL_SHA256:
                found.append(f"commit #{k}: author/committer e-mail not allowed")
        found += scan_text(f"commit #{k} message", body, terms)
    found += scan_text("refs", refs, terms)
    return found


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    terms = {t.strip().casefold() for t in os.environ.get("LEAK_EXTRA_TERMS", "").split(",") if t.strip()}
    if "--require-terms" in argv and not terms:
        print("LEAK_EXTRA_TERMS is empty: refusing to pass without a term list")
        return 1
    findings = scan_files(root, terms)
    if os.path.isdir(os.path.join(root, ".git")):
        findings += scan_git(root, terms)
    for f in findings:
        print("LEAK", f)
    print(f"leak check: {len(findings)} finding(s)" + ("" if terms else " (no term list given)"))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())

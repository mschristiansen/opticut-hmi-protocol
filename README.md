# opticut-hmi-protocol

An **unofficial** description and a small Python client of the TCP list protocol spoken by
the HMI of the Dimter OptiCut S90 cross-cut saw (Weinig OptiCom family) on port 51000:
send a cut list to the saw, read its list directory, fetch a list with its live counts.

> **Disclaimer.** Unofficial and independent. Not affiliated with, endorsed by, or supported
> by Weinig or Dimter. All trademarks and product names belong to their owners. The
> protocol was reverse-engineered from packet captures, live tests and static disassembly of
> the vendor's PC software; it may be wrong or differ between versions. The saw has no
> authentication and does not validate what it receives. **Use at your own risk**, and not
> on a machine in production without the operator's agreement.

- [`SPEC.md`](SPEC.md) — the protocol: framing, commands, the list document, the directory,
  cmd 6 operations (fetch / delete / toggle, from the disassembly), the statistics sidecar.
  Every claim is tagged measured / disassembly / inferred.
- [`opticut51000.py`](opticut51000.py) — one file, standard library only, Python 3.8+.
  `upload`, `list`, `fetch`. It has no delete command on purpose.
- [`examples/hello.xml`](examples/hello.xml) — a synthetic two-length list.
- [`tests/`](tests) — unit tests and a localhost fake HMI; no saw needed.

## Hello world

```sh
python3 opticut51000.py <hmi-host> upload examples/hello.xml   # list HELLO appears on the saw
python3 opticut51000.py <hmi-host> list                        # id, store, name
python3 opticut51000.py <hmi-host> fetch HELLO                 # the list as the saw holds it
python3 -m unittest                                            # no saw needed
```

`<hmi-host>` is the saw's HMI address (required). `list` and `fetch` work only while no
older client — for instance the vendor's PC software — is connected: the HMI answers one
connection at a time (SPEC §3.3). `upload` always works.

## Development

`python -m unittest` runs the tests; `LEAK_EXTRA_TERMS="word1,word2" python tools/leak_check.py` checks that none of
the given words, no private IP or stray e-mail address, and no foreign git identity has crept into
the files or the git history. The word list is deliberately not in the repository; CI reads it
from a secret.

Licence: MIT.

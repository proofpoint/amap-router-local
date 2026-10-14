"""Production flows for the clock's child-process witness
(`test_clock_child.py`). Not a test module (its name keeps it out of
discovery): the witness runs it in a child interpreter, after
`clock.install(Stepper(...), strict=True)` in that same interpreter, and with
no source at all for the companion run.

Each flow drives real production paths and records, after every operation,
every timestamp-shaped string that operation newly wrote into a JSON or JSONL
file under the flow's temp tree, keyed by file and member path. Members that
carry a time passed in as DATA, or one derived from the clock by arithmetic
(`DERIVED`), are not clock reads and are skipped. The parent judges the
records; the flows only drive and observe.

Write ORDER is observed too: `install_write_trace()` wraps `os.fsync`, which
every durable write in the package calls on the file it has just written
(before a rename into place, or after an append). At each fsync of a regular
file under the flow's tree the file is read back through `/proc/self/fd`, and
the timestamps that write ADDED (not in that path's previous content) are
appended to `TRACE` in call order. Each operation records its slice, so the
parent can check that no write stamps a time earlier than the write before it.

The flows:
- `mail_once`: an outbound mail request through `router once` (the CLI's
  `main`, in this interpreter), then a service poll that writes
  `status.json`, then `router status`;
- `peer_send`: a peer task through the drain, the sender's exposure assessed
  from a foreign notice whose mtime is set with `os.utime` from the INSTALLED
  clock (the documented way a test controls a file time);
- `ingress`: an inbound notice placed by one ingress pump (`Pump.now`);
- `peer_verbs`: `peer-store init`, `peer-store declare-restored` and
  `router peer-bound` through the CLI.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
from datetime import timedelta
from pathlib import Path
from unittest import mock

from router import clock, outbound
from router.tests.helpers import RouterTestCase, notices_dir, read_json, write_request
from router.tests.peer_helpers import addr, list_peer_notices, make_peer_config, peer_notices_dir
from router.tests.test_ingress_pump import E1, _Pump, entry
from router.tests.test_peerbind import _Base as _PeerBase

TS = re.compile(r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")

#: Members whose time is data or derived from the clock, never a read:
#: windows computed as now minus a window, expiries, floors, bounds given by
#: an operator, and times copied from a statement.
DERIVED = frozenset({"window_start", "expires_at", "floor", "B", "at", "deferred_until",
                     "sender_since", "last_external_delivery_ts"})

OUT = os.environ.get("CLOCK_W2_OUT")
RECORDS: list = []
#: (path, added timestamps) per fsync of a regular file, in call order.
TRACE: list = []
_SEEN_BY_PATH: dict = {}
_ROOTS: list = []


def _values_in(text: str, suffix: str) -> set:
    out: set = set()
    docs = text.splitlines() if suffix == ".jsonl" else [text]
    for line in docs:
        try:
            _walk(json.loads(line), (), out, "")
        except ValueError:
            continue
    return {v for _r, _k, v in out}


def install_write_trace() -> None:
    import stat as stat_mod
    real = os.fsync

    def fsync(fd):
        real(fd)
        try:
            st = os.fstat(fd)
            path = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            return
        if not stat_mod.S_ISREG(st.st_mode) or not any(path.startswith(r) for r in _ROOTS):
            return
        try:
            with open(f"/proc/self/fd/{fd}", "rb") as f:
                text = f.read().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return
        suffix = ".jsonl" if ".jsonl" in path else ".json"
        now = _values_in(text, suffix)
        added = sorted(now - _SEEN_BY_PATH.get(path, set()))
        _SEEN_BY_PATH[path] = now
        if added:
            TRACE.append([path, added])

    os.fsync = fsync


def _walk(value, path, out, rel):
    if isinstance(value, dict):
        for k, v in value.items():
            if k in DERIVED:
                continue
            _walk(v, path + (str(k),), out, rel)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _walk(v, path + (str(i),), out, rel)
    elif isinstance(value, str) and TS.match(value):
        out.add((rel, "/".join(path), value))


def snapshot(root: Path) -> set:
    out: set = set()
    for p in sorted(Path(root).rglob("*")):
        if not p.is_file() or p.suffix not in (".json", ".jsonl"):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = str(p.relative_to(root))
        docs = text.splitlines() if p.suffix == ".jsonl" else [text]
        for line in docs:
            try:
                _walk(json.loads(line), (), out, rel)
            except ValueError:
                continue
    return out


class _Observe:
    """`op(label, fn)`: run `fn`, then record what it newly wrote."""

    def begin(self, flow, root):
        self.flow, self.root, self.seen, self.n = flow, Path(root), snapshot(root), 0
        _ROOTS[:] = [os.path.realpath(root)]

    def op(self, label, fn):
        start = len(TRACE)
        out = fn()
        trace = [added for _p, added in TRACE[start:]]
        now = snapshot(self.root)
        new = sorted(now - self.seen)
        self.seen = now
        RECORDS.append({"flow": self.flow, "op": self.n, "label": label,
                        "values": [list(v) for v in new], "trace": trace})
        self.n += 1
        return out


def _cli(cfg, *argv):
    from router import __main__ as cli
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(cli, "load", lambda path: cfg), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(["--config", "unused", *argv])
    return code, out.getvalue(), err.getvalue()


class MailOnce(_Observe, RouterTestCase):

    def test_mail_once_then_status(self):
        cfg = self.make_config({"a": ["b"], "b": ["a"]})
        self.begin("mail_once", self.tmp)
        write_request(cfg, "a", "00000001", to=["b@example.invalid"], subject="hello",
                      body_text="hi")
        self.seen = snapshot(self.tmp)
        code, _o, err = self.op("once", lambda: _cli(cfg, "once"))
        self.assertEqual(code, 0, err)
        from router import service, status
        tracker = self.op("tracker", lambda: status.StatusTracker(interval_s=5))
        self.op("poll_once", lambda: service.poll_once(cfg, tracker))
        self.assertTrue((cfg.state_dir / "status.json").exists())
        code, _o, err = self.op("status", lambda: _cli(cfg, "status"))
        self.assertEqual(code, 0, err)


class PeerSend(_Observe, RouterTestCase):

    def test_peer_send_with_exposure_from_a_set_mtime(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        self.begin("peer_send", self.tmp)
        foreign = notices_dir(cfg, "a") / ("notice-" + "e" * 32 + ".json")
        foreign.write_text("{}")
        # A file time is data: set from the INSTALLED clock (after first
        # sight, which clamps the window's start, and before the drain's now).
        written = clock.now()
        os.utime(foreign, (written.timestamp(), written.timestamp()))
        write_request(cfg, "a", "00000001", to=[addr("b")], subject="task", body_text="go")
        self.seen = snapshot(self.tmp)
        self.op("drain", lambda: outbound.drain_instance(cfg, "a"))
        names = list_peer_notices(cfg, "b")
        self.assertEqual(len(names), 1)
        exposure = read_json(peer_notices_dir(cfg, "b") / names[0])["message"]["sender_exposure"]
        RECORDS.append({"flow": "peer_send", "exposure": exposure,
                        "written": written.strftime("%Y-%m-%dT%H:%M:%SZ")})


class Ingress(_Observe, _Pump):

    def test_one_pump_places_a_notice(self):
        self.begin("ingress", self.tmp)
        self.port.entries[E1] = entry(E1)
        self.op("pump", lambda: self.pump())
        self.assertEqual(len(self.notices()), 1)


class PeerVerbs(_Observe, _PeerBase):

    def test_init_restore_and_bound(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.begin("peer_verbs", self.state_dir)
        code, _o, err = self.op("init", lambda: _cli(self.cfg, "peer-store", "init",
                                                     "--never-admitted"))
        self.assertEqual(code, 0, err)
        code, _o, err = self.op("restored", lambda: _cli(
            self.cfg, "peer-store", "declare-restored", "--evidence", "restored ticket 9"))
        self.assertEqual(code, 0, err)
        b = (clock.now() + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # B is the operator's data; the bound raises H to it.
        RECORDS.append({"flow": "peer_verbs", "data": [b]})
        code, _o, err = self.op("bound", lambda: _cli(
            self.cfg, "peer-bound", "--at", b, "--evidence", "hub log line 4411",
            "--b-not-from-wall-clock"))
        self.assertEqual(code, 0, err)


def main() -> int:
    import unittest
    install_write_trace()
    suite = unittest.defaultTestLoader.loadTestsFromNames(
        [f"{__name__}.{c}" for c in ("MailOnce", "PeerSend", "Ingress", "PeerVerbs")])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    emitted = []
    src = clock._INSTALLED[0] if clock._INSTALLED else None
    if src is not None and hasattr(src, "emitted"):
        emitted = [t.strftime("%Y-%m-%dT%H:%M:%SZ") for t in src.emitted]
    if OUT:
        Path(OUT).write_text(json.dumps({"ok": result.wasSuccessful(), "records": RECORDS,
                                         "emitted": emitted}))
    return 0 if result.wasSuccessful() else 1

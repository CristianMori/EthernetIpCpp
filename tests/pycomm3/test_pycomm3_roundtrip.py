"""End-to-end round-trip against pycomm3 — the de facto Python client for
Allen-Bradley Logix controllers.

The C++ port's in-tree C++ tests prove the server speaks to our own
TagClient; this proves it speaks the exact wire dialect pycomm3 (and by
extension Studio 5000) expects. Covers every atomic CIP type the server
exposes, including the Logix bit-string family and SHORT_STRING.

Mirrors tests/pycomm3/test_pycomm3_roundtrip.py in the sibling Python port
(EthernetIPPython). The server is the C++ sample built from
samples/logix_pycomm3_host/ and launched as a subprocess bound to a free
TCP port on 127.0.0.1.

Skipped automatically if pycomm3 is not installed.
"""
from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pycomm3 = pytest.importorskip("pycomm3")

from pycomm3 import LogixDriver


# (name, type_code_label, initial_value, write_value) — bit-string types take
# a list of booleans per pycomm3's write encoding; atomics take a Python
# int/float/bool. The C++ host seeds initial values from the same list; keep
# the two in lock-step with the sibling Python port's test.
def _bits(value: int, width: int) -> list:
    return [bool((value >> i) & 1) for i in range(width)]


BOOL  = "BOOL"
SINT  = "SINT"
INT   = "INT"
DINT  = "DINT"
LINT  = "LINT"
USINT = "USINT"
UINT  = "UINT"
UDINT = "UDINT"
ULINT = "ULINT"
REAL  = "REAL"
LREAL = "LREAL"
BYTE  = "BYTE"
WORD  = "WORD"
DWORD = "DWORD"
LWORD = "LWORD"

TYPES = [
    ("TestBool",  BOOL,  True,       False),
    ("TestSint",  SINT,  -5,         127),
    ("TestInt",   INT,   -1234,      32000),
    ("TestDint",  DINT,  -1_000_000, 2_000_000_000),
    ("TestLint",  LINT,  -1,         0x7FFF_FFFF_FFFF_FFFF),
    ("TestUsint", USINT, 42,         0xFF),
    ("TestUint",  UINT,  0xBEEF,     0xFFFF),
    ("TestUdint", UDINT, 0xDEADBEEF, 0xFFFF_FFFF),
    ("TestUlint", ULINT, 1_234_567_890_123, 0xFFFF_FFFF_FFFF_FFFF),
    ("TestReal",  REAL,  3.14,       -2.71828),
    ("TestLreal", LREAL, 3.141592653589793, -2.718281828459045),
    ("TestByte",  BYTE,  _bits(0xAB, 8),   _bits(0xCD, 8)),
    ("TestWord",  WORD,  _bits(0x1234, 16), _bits(0xABCD, 16)),
    ("TestDword", DWORD, _bits(0xDEADBEEF, 32), _bits(0xCAFEBABE, 32)),
    ("TestLword", LWORD, _bits(0x1234_5678_9ABC_DEF0, 64),
                         _bits(0xFEDC_BA98_7654_3210, 64)),
]


REPO_ROOT = Path(__file__).resolve().parents[2]


def _find_host_binary() -> Path:
    """Locate the built logix_pycomm3_host executable under build/.

    Supports both multi-config generators (build/.../Debug/) and
    single-config (Ninja) layouts. Fails loudly if the sample has not been
    built — this test treats the sample binary as a prerequisite the user
    (or CI) builds separately via the project's CMake preset.
    """
    build_dir = REPO_ROOT / "build"
    exe_name = "logix_pycomm3_host.exe" if os.name == "nt" else "logix_pycomm3_host"
    candidates = list(build_dir.rglob(exe_name))
    if not candidates:
        raise FileNotFoundError(
            f"logix_pycomm3_host binary not found under {build_dir}. "
            "Build samples first (cmake --build build --target logix_pycomm3_host)."
        )
    # Prefer the most recently modified binary when several configs exist.
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _grab_free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as exc:
            last_err = exc
            time.sleep(0.1)
    raise TimeoutError(f"server on {host}:{port} not reachable within "
                       f"{timeout:.1f}s (last error: {last_err!r})")


@pytest.fixture(scope="module")
def host_server():
    """Spawn the C++ Logix host once per test module, torn down on exit."""
    binary = _find_host_binary()
    port = _grab_free_port()
    proc = subprocess.Popen(
        [str(binary), "--bind", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        _wait_for_port("127.0.0.1", port, timeout=10.0)
        yield port
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)
        if proc.stdout is not None:
            try:
                remaining = proc.stdout.read()
                if remaining:
                    sys.stdout.write("\n[host stdout]\n" + remaining)
            except Exception:
                pass


def _values_match(ty_label: str, got, expected) -> bool:
    if ty_label == BOOL:
        return bool(got) == bool(expected)
    if ty_label == REAL:
        return abs(float(got) - float(expected)) < 1e-5
    if ty_label == LREAL:
        return abs(float(got) - float(expected)) < 1e-12
    if ty_label == DWORD:
        # pycomm3 collapses a raw DWORD read to bit 0 — the full-32 test
        # below proves the server stored every bit.
        exp_bit = expected[0] if isinstance(expected, (list, tuple)) else bool(expected & 1)
        return bool(got) == exp_bit
    if ty_label in (BYTE, WORD, LWORD):
        got_list = list(got) if isinstance(got, (list, tuple)) else [got]
        exp_list = list(expected) if isinstance(expected, (list, tuple)) else [expected]
        return got_list == exp_list
    return got == expected


def test_pycomm3_every_atomic_type_round_trips(host_server):
    port = host_server
    failures: dict[str, tuple[str, object]] = {}

    with LogixDriver(f"127.0.0.1:{port}",
                     init_tags=True,
                     init_program_tags=False) as plc:
        tag_names = sorted(plc.tags.keys())
        expected_names = {t[0] for t in TYPES} | {"TestShortString"}
        missing = expected_names - set(tag_names)
        assert not missing, f"pycomm3 did not enumerate: {missing}"

        for name, ty, initial, write_val in TYPES:
            r = plc.read(name)
            if r.error:
                failures[name] = ("read-init-error", r.error)
                continue
            initial_ok = _values_match(ty, r.value, initial)
            w = plc.write((name, write_val))
            if w.error:
                failures[name] = ("write-error", w.error)
                continue
            r2 = plc.read(name)
            if r2.error:
                failures[name] = ("read-back-error", r2.error)
                continue
            readback_ok = _values_match(ty, r2.value, write_val)
            if not (initial_ok and readback_ok):
                failures[name] = ("mismatch", {
                    "initial":    r.value,
                    "wrote":      write_val,
                    "back":       r2.value,
                    "initial_ok": initial_ok,
                    "readback_ok": readback_ok,
                })

        # DWORD full-32 proof read — pycomm3's bare DWORD read returns a
        # single bool; TagName{32} forces a 32-bit array read.
        r = plc.read("TestDword{32}")
        expected_dword_bits = _bits(0xCAFEBABE, 32)
        if r.error or list(r.value) != expected_dword_bits:
            failures["TestDword{32}"] = (
                "mismatch",
                {"val": (list(r.value) if r.value else None),
                 "err": r.error},
            )

        # SHORT_STRING round-trip — pycomm3 writes [len][chars]; the server
        # fix for the variable-length format landed in commit a89cb55.
        r = plc.read("TestShortString")
        if r.error:
            failures["TestShortString"] = ("read-init-error", r.error)
        else:
            w = plc.write(("TestShortString", "hello"))
            if w.error:
                failures["TestShortString"] = ("write-error", w.error)
            else:
                r2 = plc.read("TestShortString")
                if r2.value != "hello":
                    failures["TestShortString"] = (
                        "mismatch", {"back": r2.value, "err": r2.error},
                    )

        # ---- Yellow-row coverage -----------------------------------------
        # Mirrors the sibling Python port's test extension verbatim. Each
        # failing case records a diagnostic payload so the assertion dump at
        # the end explains what went wrong on the wire.
        def _fail(label: str, detail) -> None:
            failures[label] = ("mismatch", detail)

        # Row 17: 1-D array indexed read/write.
        r = plc.read("DintArr[5]")
        if r.error or r.value != 105:
            _fail("17 DintArr[5] read", {"err": r.error, "val": r.value})
        w = plc.write(("DintArr[5]", 999))
        r2 = plc.read("DintArr[5]")
        if w.error or r2.value != 999:
            _fail("17 DintArr[5] round-trip", {"w": w.error, "back": r2.value})

        # Row 18: whole array read.
        r = plc.read("DintArr{10}")
        if r.error or not r.value or list(r.value)[0] != 100 or list(r.value)[9] != 109:
            _fail("18 DintArr{10}",
                   {"err": r.error,
                    "vals": list(r.value) if r.value else None})

        # Rows 19 + 20: fragmented read + write of 10 elements.
        w = plc.write(("DintArr{10}", list(range(1000, 1010))))
        r = plc.read("DintArr{10}")
        if w.error or not r.value or list(r.value) != list(range(1000, 1010)):
            _fail("19-20 fragmented r/w",
                   {"w": w.error,
                    "back": list(r.value) if r.value else None})

        # Row 21: bit of atomic.
        r = plc.read("FlagsDint.1")
        if r.error or bool(r.value) is not True:
            _fail("21 FlagsDint.1 read", {"err": r.error, "val": r.value})
        w = plc.write(("FlagsDint.0", True))
        r2 = plc.read("FlagsDint.0")
        if w.error or bool(r2.value) is not True:
            _fail("21 FlagsDint bit write",
                   {"w": w.error, "back": r2.value})

        # Row 22: BOOL array (DWORD-packed).
        r = plc.read("Flags32[3]")
        if r.error:
            _fail("22 Flags32[3] read", {"err": r.error, "val": r.value})
        w = plc.write(("Flags32[7]", True))
        r2 = plc.read("Flags32[7]")
        if w.error or bool(r2.value) is not True:
            _fail("22 Flags32 bit write",
                   {"w": w.error, "back": r2.value})

        # Row 23: multi-dim array.
        r = plc.read("Matrix[1,2]")
        if r.error or r.value != 12:
            _fail("23 Matrix[1,2] read", {"err": r.error, "val": r.value})
        w = plc.write(("Matrix[0,1]", 777))
        r2 = plc.read("Matrix[0,1]")
        if w.error or r2.value != 777:
            _fail("23 Matrix write",
                   {"w": w.error, "back": r2.value})

        # Row 24: Logix STRING UDT whole-struct round-trip.
        r = plc.read("Greeting")
        if r.error or r.value != "Hello pycomm3":
            _fail("24 Greeting read", {"err": r.error, "val": r.value})
        w = plc.write(("Greeting", "written back"))
        r2 = plc.read("Greeting")
        if w.error or r2.value != "written back":
            _fail("24 Greeting round-trip",
                   {"w": w.error, "back": r2.value})

        # Row 25: STRING array element round-trip.
        w = plc.write(("GreetingArr[1]", "second"))
        r = plc.read("GreetingArr[1]")
        if w.error or r.error or r.value != "second":
            _fail("25 GreetingArr[1]",
                   {"w": w.error, "r": r.error, "val": r.value})

        # Row 26: UDT whole-struct read (returns dict).
        r = plc.read("MotorA")
        if (r.error or not isinstance(r.value, dict)
                or abs(r.value.get("Speed", 0) - 3.14) >= 1e-4
                or r.value.get("Fault") is not True
                or r.value.get("RunCount") != 42):
            _fail("26 MotorA whole-struct", {"err": r.error, "val": r.value})

        # Row 27: UDT member access.
        r = plc.read("MotorA.Speed")
        if r.error or abs(r.value - 3.14) >= 1e-5:
            _fail("27 MotorA.Speed", {"err": r.error, "val": r.value})
        r = plc.read("MotorA.RunCount")
        if r.error or r.value != 42:
            _fail("27 MotorA.RunCount", {"err": r.error, "val": r.value})
        w = plc.write(("MotorA.Speed", -1.5))
        r2 = plc.read("MotorA.Speed")
        if w.error or abs(r2.value - (-1.5)) >= 1e-5:
            _fail("27 MotorA.Speed write",
                   {"w": w.error, "back": r2.value})

        # Row 29: BOOL member of UDT.
        r = plc.read("MotorA.Fault")
        if r.error or bool(r.value) is not True:
            _fail("29 MotorA.Fault read", {"err": r.error, "val": r.value})
        w = plc.write(("MotorA.Fault", False))
        r2 = plc.read("MotorA.Fault")
        if w.error or bool(r2.value) is not False:
            _fail("29 MotorA.Fault write",
                   {"w": w.error, "back": r2.value})

        # Row 31: array of UDTs with member access.
        w = plc.write(("MotorArr[1].Speed", 7.77))
        r = plc.read("MotorArr[1].Speed")
        if w.error or r.error or abs(r.value - 7.77) >= 1e-4:
            _fail("31 MotorArr[1].Speed",
                   {"w": w.error, "r": r.error, "val": r.value})

        # TIMER UDT -- same access pattern as a user UDT; this is an explicit
        # witness that `MyTimer.PRE` and `MyTimer.EN` work.
        r = plc.read("MyTimer.PRE")
        if r.error or r.value != 1000:
            _fail("TIMER MyTimer.PRE read", {"err": r.error, "val": r.value})
        r = plc.read("MyTimer.EN")
        if r.error or bool(r.value) is not True:
            _fail("TIMER MyTimer.EN read", {"err": r.error, "val": r.value})
        w = plc.write(("MyTimer.PRE", 2000))
        r = plc.read("MyTimer.PRE")
        if w.error or r.value != 2000:
            _fail("TIMER MyTimer.PRE write",
                   {"w": w.error, "back": r.value})
        w = plc.write(("MyTimer.EN", False))
        r = plc.read("MyTimer.EN")
        if w.error or bool(r.value) is not False:
            _fail("TIMER MyTimer.EN write",
                   {"w": w.error, "back": r.value})

        # AOI-backing UDT -- same mechanism, confirming AOI tags are not
        # special on the wire.
        r = plc.read("MyAOI.Enable")
        if r.error or bool(r.value) is not True:
            _fail("AOI MyAOI.Enable read", {"err": r.error, "val": r.value})
        r = plc.read("MyAOI.Setpoint")
        if r.error or abs(r.value - 42.5) >= 1e-5:
            _fail("AOI MyAOI.Setpoint read",
                   {"err": r.error, "val": r.value})
        w = plc.write(("MyAOI.Setpoint", 99.9))
        r = plc.read("MyAOI.Setpoint")
        if w.error or abs(r.value - 99.9) >= 1e-5:
            _fail("AOI MyAOI.Setpoint write",
                   {"w": w.error, "back": r.value})
        w = plc.write(("MyAOI.Enable", False))
        r = plc.read("MyAOI.Enable")
        if w.error or bool(r.value) is not False:
            _fail("AOI MyAOI.Enable write",
                   {"w": w.error, "back": r.value})

        # Rows 39-40: multi-service batch read & write.
        batch = plc.read("DintArr[0]", "DintArr[1]", "DintArr[2]")
        if (any(t.error for t in batch)
                or [t.value for t in batch] != [1000, 1001, 1002]):
            _fail("39 batch read",
                   [(t.tag, t.value, t.error) for t in batch])
        res = plc.write(("DintArr[0]", 5000),
                         ("DintArr[1]", 5001),
                         ("DintArr[2]", 5002))
        r = plc.read("DintArr[0]", "DintArr[1]", "DintArr[2]")
        if (any(t.error for t in res)
                or [t.value for t in r] != [5000, 5001, 5002]):
            _fail("40 batch write",
                   {"res_errs": [t.error for t in res],
                    "back": [t.value for t in r]})

    assert not failures, f"pycomm3 round-trip failures:\n{failures}"

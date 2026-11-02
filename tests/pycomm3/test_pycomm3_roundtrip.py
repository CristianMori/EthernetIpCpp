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

    assert not failures, f"pycomm3 round-trip failures:\n{failures}"

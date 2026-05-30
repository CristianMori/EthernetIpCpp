"""Smoke test for samples/logix_host using pycomm3.

Reads + writes each tag the host exposes (rate / temperature / counts),
prints PASS/FAIL per check. Exit code 0 on full pass.
"""
from __future__ import annotations

import sys
from pycomm3 import LogixDriver

HOST = "127.0.0.1"
fail = 0


def check(label: str, actual, expected) -> None:
    global fail
    ok = actual == expected
    if not ok:
        fail += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}  (expected {expected!r})")


def main() -> int:
    # Default init_tags=True forces pycomm3 to fetch the tag list via Symbol
    # Object Get_Instance_Attribute_List (0x55) at connect — exercises tag
    # browsing and is required so pycomm3 knows each tag's type for reads.
    with LogixDriver(HOST) as plc:
        print(f"Connected to {HOST}:44818")
        info = plc.info
        print(f"  identity vendor={info.get('vendor')} "
              f"serial={info.get('serial')} "
              f"product={info.get('product_name')!r}\n")

        # ---- initial reads (preloaded values) ----
        print("Initial reads:")
        r = plc.read("rate")
        check("rate", r.value, 534)
        r = plc.read("temperature")
        check("temperature", r.value, 72.5)
        r = plc.read("counts[0]")
        check("counts[0]", r.value, 0)

        # ---- write + read round-trip ----
        print("\nWrite then read:")
        plc.write(("rate", 4242))
        check("rate after write", plc.read("rate").value, 4242)

        plc.write(("temperature", 99.25))
        check("temperature after write", plc.read("temperature").value, 99.25)

        plc.write(("counts[3]", 7))
        check("counts[3] after write", plc.read("counts[3]").value, 7)

        # ---- array read ----
        print("\nArray read:")
        arr = plc.read("counts{10}")
        ok = arr.value == [0, 0, 0, 7, 0, 0, 0, 0, 0, 0]
        if not ok:
            global fail
            fail += 1
        print(f"  {'PASS' if ok else 'FAIL'}  counts{{10}}: {arr.value!r}")

    print(f"\n{'ALL PASS' if fail == 0 else f'{fail} FAILURES'}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

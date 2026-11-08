"""Checks that AetherEDR works on this machine.

    python -m edr.selftest

Spawns a harmless child process that holds an RWX page containing a marker string, then checks that
the collector can see it (process, memory map, RWX flag, header/entropy), that the embedded YARA
engine finds the marker inside the child's live memory, and that sockets map back to a PID.
Exit code 0 = every check passed. Run elevated (root / Administrator) to mirror production.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aether.settings")

MARKER = b"AETHEREDR_YARA_SELFTEST_MARKER_7f3a"

CHILD_POSIX = (
    "import mmap,os,sys,time;"
    "m=mmap.mmap(-1,8192,prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);"
    f"m.write({MARKER!r});print('ready',os.getpid(),flush=True);time.sleep(120)"
)
CHILD_WINDOWS = (
    "import ctypes,os,time;k=ctypes.windll.kernel32;"
    "k.VirtualAlloc.restype=ctypes.c_void_p;"
    "k.VirtualAlloc.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_ulong,ctypes.c_ulong];"
    "p=k.VirtualAlloc(None,8192,0x3000,0x40);"
    f"ctypes.memmove(p,{MARKER!r},{len(MARKER)});print('ready',os.getpid(),flush=True);time.sleep(120)"
)


def main() -> int:
    import django

    django.setup()
    import psutil

    from edr.collector import memory
    from edr.collector.collector import Collector, host_info
    from edr.engine import yara_scanner

    results: list[tuple[str, str, str]] = []

    def check(name: str, ok: bool | None, detail: str = "") -> bool:
        results.append((name, "SKIP" if ok is None else "PASS" if ok else "FAIL", detail))
        return bool(ok)

    info = host_info()
    print(f"AetherEDR self-test on {info['hostname']} ({info['os_version']}), elevated={info['is_admin']}\n")
    check("Python can enumerate processes", len(psutil.pids()) > 1, f"{len(psutil.pids())} processes")
    if not memory.supported():
        check("Memory introspection", None, "not supported on this OS (process and network telemetry still work)")
        _report(results)
        return 0

        # in a Windows venv python.exe is a stub that starts the real interpreter as a child, so
    # start the base interpreter directly and use the PID the fixture reports
    exe = getattr(sys, "_base_executable", None) or sys.executable if sys.platform == "win32" else sys.executable
    child = subprocess.Popen([exe, "-c", CHILD_WINDOWS if sys.platform == "win32" else CHILD_POSIX],
                             stdout=subprocess.PIPE, text=True)
    try:
        parts = child.stdout.readline().split()
        ready = parts[:1] == ["ready"] and len(parts) == 2 and parts[1].isdigit()
        fixture = int(parts[1]) if ready else child.pid
        check("Fixture process started", ready, f"PID {fixture}")
        if not ready:
            _report(results)
            return 1

        try:
            analysis = memory.analyze(fixture)
            s = analysis["summary"]
            check("Memory map readable", s["total_regions"] > 0, f"{s['total_regions']} regions")
            rwx = [r for r in analysis["regions"] if r["rwx"]]
            check("RWX region detected", bool(rwx), f"{s['rwx_regions']} RWX, {s['unbacked_exec']} unbacked executable")
            check("Region bytes sampled (entropy)", bool(rwx) and rwx[0]["entropy"] is not None,
                  f"entropy {rwx[0]['entropy']}" if rwx else "")
        except memory.MemoryAccessError as exc:
            check("Memory map readable", False, f"{exc} (try running as root / Administrator)")
            _report(results)
            return 1

        if not yara_scanner.AVAILABLE:
            check("YARA memory scanning", None, "yara-python not installed (see requirements-yara.txt)")
        else:
          try:
            rules = yara_scanner.builtin_rules()
            check("YARA rules compile", True, f"{len(list(rules))} built-in rules")
            res = yara_scanner.scan_process(fixture, [rules], scope="flagged", include_file=False)
            hit = [m for m in res["matches"] if m["rule"] == "AetherEDR_SelfTest"]
            check("YARA finds marker in live process memory", bool(hit),
                  f"scanned {res['regions_scanned']} region(s), {res['bytes_scanned']} bytes")
          except Exception as exc:  # noqa: BLE001
            check("YARA engine", False, f"{type(exc).__name__}: {exc}")

        col = Collector(initial_spread=0.0, memscan_delays=(0.0,))
        batch = col.poll()
        starts = [e for e in batch["events"] if e["type"] == "process_start" and e["pid"] == fixture]
        parent = os.getpid() if fixture == child.pid else child.pid  # the stub sits in between
        check("Collector reports the process with lineage", bool(starts) and starts[0]["ppid"] == parent,
              f"ppid {starts[0]['ppid']}" if starts else "missing")
    finally:
        child.kill()
        child.wait()

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.create_connection(server.getsockname())
    try:
        col = Collector(initial_spread=0.0, memscan=False)
        net = [e for e in col.poll()["events"] if e["type"] == "net_connect" and e["pid"] == os.getpid()]
        port = server.getsockname()[1]
        check("Sockets map to the owning PID",
              any(e["lport"] == port and e["direction"] == "listen" for e in net)
              and any(e["rport"] == port and e["direction"] == "outbound" for e in net),
              f"{len(net)} sockets attributed")
    finally:
        client.close()
        server.close()

    _events_check(check)
    if sys.platform == "win32":
        _windows_protection_check(check)

    from edr.engine import netintel

    check("Offline GeoIP/ASN lookup", netintel.geo().lookup("8.8.8.8").get("asn") == 15169,
          f"{netintel.geo().loaded_extra} extra ranges loaded from data/geo_asn.csv" if netintel.geo().loaded_extra
          else "built-in seed only; add data/geo_asn.csv for full coverage")
    return _report(results)


def _events_check(check) -> None:
    """Does the OS announce a process that starts and exits within a moment, the case polling cannot see?"""
    from edr.collector.collector import Collector

    col = Collector(memscan=False, initial_spread=0.0)
    col.start_events()
    try:
        if col.events is None:
            check("Short-lived process notifications", None, "no event source on this OS, polling only")
            return
        deadline = time.time() + 6
        while not col.events.active and col.events.is_alive() and time.time() < deadline:
            time.sleep(0.1)
        if not col.events.active:
            check("Short-lived process notifications", None, f"polling only: {col.events.error or 'source did not start'}")
            return
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()
        found = False
        deadline = time.time() + 6
        while time.time() < deadline and not found:
            found = any(h["info"]["pid"] == child.pid for h in list(col.events.pending))
            time.sleep(0.1)
        check("Short-lived process notifications", found,
              f"{col.events.kind}: a process that lived about 50 ms was announced" if found
              else f"{col.events.kind} source is running but did not announce a test process")
    finally:
        col.stop_events()


def _windows_protection_check(check) -> None:
    from edr.collector import _windows as w
    from edr.collector import memory

    own = w.protection_level(os.getpid())
    check("Protected-process query", own == 0, "this process is not protected, as expected" if own == 0 else f"unexpected result {own!r}")
    try:
        memory.analyze(4)       # the System process refuses every user-mode reader
        check("Unreadable process is classified", False, "System (PID 4) was readable, unexpected")
    except memory.MemoryAccessError as exc:
        check("Unreadable process is classified", exc.reason in ("protected", "denied"), f"System (PID 4): {exc.reason}")


def _report(results) -> int:
    width = max(len(n) for n, _, _ in results)
    for name, status, detail in results:
        print(f"  {status:<4}  {name:<{width}}  {detail}")
    failed = [r for r in results if r[1] == "FAIL"]
    print(f"\n{'All checks passed.' if not failed else f'{len(failed)} check(s) failed.'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

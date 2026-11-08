"""Process memory reading for Linux and Windows.

Linux  : /proc/<pid>/maps + /proc/<pid>/mem
Windows: VirtualQueryEx + ReadProcessMemory through ctypes (kernel32/psapi)

Public API
    enumerate_regions(pid) -> list[Region]
    read_memory(pid, address, size) -> bytes
    analyze(pid) -> dict           # summary + flagged regions (used by the collector)
"""
from __future__ import annotations

import math
import sys
from collections import Counter
from dataclasses import asdict, dataclass

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")


class MemoryAccessError(Exception):
    """The process is gone or access was denied.

    reason: "gone" (exited), "protected" (Windows protected process, memory reads are blocked by design),
    "denied" (no permission, usually another user's process while not elevated), "other".
    """

    def __init__(self, message: str, reason: str = "other") -> None:
        super().__init__(message)
        self.reason = reason


REASON_TEXT = {
    "protected": "This is a protected process. Windows blocks memory reads of these by design, even for Administrator.",
    "denied": "No permission to read this process. Run AetherEDR as Administrator / root to cover other users' processes.",
    "gone": "The process has exited.",
    "other": "The memory could not be read.",
}


@dataclass
class Region:
    start: int
    size: int
    perms: str            # rwxp style on Linux; synthesized on Windows (e.g. "rwx-")
    kind: str             # image | mapped | private | stack | heap | special | memfd | deleted
    path: str = ""
    protect: str = ""     # Windows protection constant name, e.g. PAGE_EXECUTE_READWRITE
    readable: bool = True
    writable: bool = False
    executable: bool = False
    rwx: bool = False
    unbacked: bool = False       # executable memory with no on-disk image behind it
    susp_path: bool = False      # executable mapping from a user-writable location
    header: str = ""             # "MZ-PE" | "ELF" when found at region start (filled by analyze)
    entropy: float | None = None  # Shannon entropy of first sampled bytes

    @property
    def end(self) -> int:
        return self.start + self.size

    def as_dict(self) -> dict:
        d = asdict(self)
        d["start"] = int(self.start)
        return d


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --- platform dispatch ---------------------------------------------------------
if IS_LINUX:
    from . import _linux as _impl
elif IS_WINDOWS:
    from . import _windows as _impl
else:  # macOS / BSD: process + socket telemetry only
    _impl = None


def supported() -> bool:
    return _impl is not None


def enumerate_regions(pid: int) -> list[Region]:
    if _impl is None:
        return []
    return _impl.enumerate_regions(pid)


def read_memory(pid: int, address: int, size: int) -> bytes:
    if _impl is None:
        raise MemoryAccessError("memory reads unsupported on this platform")
    return _impl.read_memory(pid, address, size)


def detect_header(sample: bytes) -> str:
    if sample[:2] == b"MZ":
        # confirm a plausible PE: e_lfanew -> "PE\0\0"
        if len(sample) >= 0x40:
            off = int.from_bytes(sample[0x3C:0x40], "little")
            if 0 < off < len(sample) - 4 and sample[off:off + 4] == b"PE\x00\x00":
                return "MZ-PE"
        return "MZ"
    if sample[:4] == b"\x7fELF":
        return "ELF"
    return ""


# Modules only JIT hosts load. A process with one of these mapped can have RWX and unbacked
# executable pages for good reason (V8, .NET, JVM, Qt QML, SpiderMonkey, LuaJIT, CEF)
JIT_RUNTIME_MODULES = ("clrjit", "coreclr", "libcoreclr", "libjvm", "jvm.dll", "libcef", "chrome_elf", "libnode",
                       "node.dll", "v8_context_snapshot", "qt5qml", "qt6qml", "libqt5qml", "libqt6qml", "mozjs",
                       "xul.dll", "libxul", "luajit", "lua51.dll")


def detect_runtimes(regions: list[Region]) -> list[str]:
    """JIT runtime modules mapped into the process (empty for plain native code)."""
    found: set[str] = set()
    for r in regions:
        if r.kind != "image" or not r.path:
            continue
        base = r.path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        for m in JIT_RUNTIME_MODULES:
            if m in base:
                found.add(base.split(".so")[0] if ".so" in base else base)
                break
    return sorted(found)[:6]


def is_flagged(r: Region) -> bool:
    return r.executable and (r.rwx or r.unbacked or r.susp_path)


def analyze(pid: int, max_flagged: int = 16, sample_bytes: int = 4096) -> dict:
    """Walk the address space, return a summary and the flagged regions."""
    regions = enumerate_regions(pid)
    summary = {
        "total_regions": len(regions),
        "exec_regions": 0,
        "rwx_regions": 0,
        "unbacked_exec": 0,
        "susp_path_exec": 0,
        "pe_in_private": 0,
        "private_bytes": 0,
        "exec_bytes": 0,
    }
    flagged: list[Region] = []
    for r in regions:
        if r.kind in ("private", "heap", "stack"):
            summary["private_bytes"] += r.size
        if r.executable:
            summary["exec_regions"] += 1
            summary["exec_bytes"] += r.size
        if r.rwx:
            summary["rwx_regions"] += 1
        if r.executable and r.unbacked:
            summary["unbacked_exec"] += 1
        if r.executable and r.susp_path:
            summary["susp_path_exec"] += 1
        if is_flagged(r):
            flagged.append(r)

    # biggest / most suspicious first, then sample bytes for header + entropy
    flagged.sort(key=lambda r: (not r.rwx, not r.unbacked, -r.size))
    out = []
    for r in flagged[:max_flagged]:
        try:
            sample = read_memory(pid, r.start, min(r.size, sample_bytes))
        except MemoryAccessError:
            sample = b""
        if sample:
            r.header = detect_header(sample)
            r.entropy = round(shannon_entropy(sample), 3)
            if r.header and r.unbacked:
                summary["pe_in_private"] += 1
        out.append(r.as_dict())
    summary["flagged_regions"] = len(flagged)
    summary["runtimes"] = detect_runtimes(regions)
    return {"summary": summary, "regions": out}

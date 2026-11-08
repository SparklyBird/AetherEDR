"""Linux memory reading through /proc. Plain Python, no ptrace."""
from __future__ import annotations

import os
import re

from .memory import MemoryAccessError, Region

_SUSP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/run/shm/")
_MAP_RE = re.compile(
    r"^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+(?P<perms>\S{4})\s+\S+\s+\S+\s+\S+\s*(?P<path>.*)$"
)


def classify(path: str, perms: str) -> tuple[str, bool, bool]:
    """(kind, unbacked, suspicious_path) for one mapping."""
    deleted = path.endswith(" (deleted)")
    clean = path[:-10] if deleted else path
    if not clean:
        return "private", True, False
    if clean.startswith("[stack"):
        return "stack", False, False
    if clean.startswith("[heap"):
        return "heap", False, False
    if clean in ("[vdso]", "[vvar]", "[vsyscall]", "[vvar_vclock]"):
        return "special", False, False
    if clean.startswith("[anon"):          # named anon VMAs (prctl PR_SET_VMA_ANON_NAME)
        return "private", True, False
    if clean.startswith("/memfd:"):
        return "memfd", True, True
    if clean.startswith("/dev/zero") or clean.startswith("/SYSV"):
        return "private", True, False      # anonymous *shared* mappings
    if deleted:
        return "deleted", True, True
    susp = clean.startswith(_SUSP_DIRS)
    return ("image" if "x" in perms else "mapped"), False, susp


def parse_maps(text: str) -> list[Region]:
    regions: list[Region] = []
    for line in text.splitlines():
        m = _MAP_RE.match(line)
        if not m:
            continue
        start, end = int(m["start"], 16), int(m["end"], 16)
        perms, path = m["perms"], m["path"].strip()
        kind, unbacked, susp = classify(path, perms)
        r = "r" in perms
        w = "w" in perms
        x = "x" in perms
        regions.append(
            Region(
                start=start, size=end - start, perms=perms, kind=kind, path=path,
                readable=r, writable=w, executable=x,
                rwx=(r and w and x),
                unbacked=unbacked and x,
                susp_path=susp and x,
            )
        )
    return regions


def enumerate_regions(pid: int) -> list[Region]:
    try:
        with open(f"/proc/{pid}/maps", "r", encoding="utf-8", errors="replace") as fh:
            return parse_maps(fh.read())
    except (FileNotFoundError, ProcessLookupError) as exc:
        raise MemoryAccessError(f"pid {pid} gone", "gone") from exc
    except PermissionError as exc:
        raise MemoryAccessError(f"access denied for pid {pid}", "denied") from exc


def read_memory(pid: int, address: int, size: int) -> bytes:
    if size <= 0:
        return b""
    try:
        fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    except (FileNotFoundError, ProcessLookupError) as exc:
        raise MemoryAccessError(f"cannot open /proc/{pid}/mem: {exc}", "gone") from exc
    except PermissionError as exc:
        raise MemoryAccessError(f"cannot open /proc/{pid}/mem: {exc}", "denied") from exc
    try:
        return os.pread(fd, size, address)
    except (OSError, OverflowError, ValueError) as exc:
        raise MemoryAccessError(f"read failed at {address:#x}: {exc}") from exc
    finally:
        os.close(fd)

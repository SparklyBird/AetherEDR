"""Windows memory constants and small helpers. No ctypes, so tests run on any OS."""
from __future__ import annotations

MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

PROTECT_NAMES = {
    PAGE_NOACCESS: "PAGE_NOACCESS", PAGE_READONLY: "PAGE_READONLY",
    PAGE_READWRITE: "PAGE_READWRITE", PAGE_WRITECOPY: "PAGE_WRITECOPY",
    PAGE_EXECUTE: "PAGE_EXECUTE", PAGE_EXECUTE_READ: "PAGE_EXECUTE_READ",
    PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
    PAGE_EXECUTE_WRITECOPY: "PAGE_EXECUTE_WRITECOPY",
}
EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
WRITE_MASK = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
READ_MASK = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ
             | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)


# droppers like to stage DLLs here. Matched case-insensitively against the device path
# GetMappedFileNameW returns, e.g. \\Device\\HarddiskVolume3\\Users\\x\\AppData\\Local\\Temp\\a.dll
SUSP_PATH_FRAGMENTS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\", "\\programdata\\temp\\",
                       "\\$recycle.bin\\", "\\perflogs\\")


def path_is_suspicious(path: str) -> bool:
    p = (path or "").lower().replace("/", "\\")
    return any(f in p for f in SUSP_PATH_FRAGMENTS)


def protect_info(protect: int) -> tuple[str, bool, bool, bool]:
    """Returns (name, readable, writable, executable)."""
    base = protect & 0xFF
    name = PROTECT_NAMES.get(base, f"0x{protect:X}")
    if protect & PAGE_GUARD:
        name += "|GUARD"
    return name, bool(base & READ_MASK), bool(base & WRITE_MASK), bool(base & EXEC_MASK)


def classify_region(mem_type: int, protect: int, mapped_path: str) -> dict:
    """Turn a MEMORY_BASIC_INFORMATION (Type, Protect) pair into Region fields."""
    name, r, w, x = protect_info(protect)
    kind = "image" if mem_type == MEM_IMAGE else "mapped" if mem_type == MEM_MAPPED else "private"
    return {
        "kind": kind,
        "protect": name,
        "readable": r, "writable": w, "executable": x,
        "perms": ("r" if r else "-") + ("w" if w else "-") + ("x" if x else "-") + "-",
        # EXECUTE_WRITECOPY on image sections is just the loader, only real
        # PAGE_EXECUTE_READWRITE counts as RWX
        "rwx": (protect & 0xFF) == PAGE_EXECUTE_READWRITE,
        "unbacked": x and kind == "private",
        # unnamed MEM_MAPPED sections are everywhere on Windows (shared memory, JIT double mappings,
        # CFG bitmaps), so only code mapped from a drop location counts
        "susp_path": x and kind in ("image", "mapped") and path_is_suspicious(mapped_path),
    }

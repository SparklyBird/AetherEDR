"""Windows memory reading with ctypes only (VirtualQueryEx / ReadProcessMemory).

No pywin32 needed. Requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ on the target;
run the agent as Administrator (SeDebugPrivilege is enabled opportunistically) to see
protected-but-not-PPL processes. PPL processes (e.g. lsass with RunAsPPL) are reported
as protected, and the collector reports them as such instead of leaving a silent gap.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from ._winconst import MEM_COMMIT, PAGE_NOACCESS, classify_region
from .memory import MemoryAccessError, Region

if sys.platform != "win32":  # pragma: no cover (only imported on Windows)
    raise ImportError("windows only")

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ProcessProtectionInformation = 61
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD)]
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        _fields_.append(("PartitionId", wintypes.WORD))
    _fields_ += [("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                 ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_psapi = ctypes.WinDLL("psapi", use_last_error=True)
_ntdll = ctypes.WinDLL("ntdll")

_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.GetCurrentProcess.restype = wintypes.HANDLE
_k32.VirtualQueryEx.restype = ctypes.c_size_t
_k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
_k32.ReadProcessMemory.restype = wintypes.BOOL
_k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
_ntdll.NtQueryInformationProcess.restype = wintypes.LONG
_ntdll.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
                                             ctypes.POINTER(wintypes.ULONG)]
_psapi.GetMappedFileNameW.restype = wintypes.DWORD
_psapi.GetMappedFileNameW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]

_MAX_USER_ADDR = 0x7FFFFFFEFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFEFFFF


def _enable_debug_privilege() -> None:
    """Try to enable SeDebugPrivilege. Only works when elevated."""
    try:
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY = 0x20, 0x8
        tok = wintypes.HANDLE()
        if not adv.OpenProcessToken(_k32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                    ctypes.byref(tok)):
            return

        class LUID(ctypes.Structure):
            _fields_ = [("Low", wintypes.DWORD), ("High", wintypes.LONG)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("Count", wintypes.DWORD), ("Luid", LUID), ("Attr", wintypes.DWORD)]

        luid = LUID()
        if adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            tp = TOKEN_PRIVILEGES(1, luid, 2)  # SE_PRIVILEGE_ENABLED
            adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None)
        _k32.CloseHandle(tok)
    except Exception:  # noqa: BLE001
        pass


_enable_debug_privilege()


def protection_level(pid: int) -> int | None:
    """PS_PROTECTION byte of a process: 0 for an ordinary process, non-zero for PP / PPL.
    A limited-information handle is enough to ask, and Windows grants it even for protected processes.
    None when it cannot be asked."""
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        level = ctypes.c_ubyte(0)
        got = wintypes.ULONG(0)
        status = _ntdll.NtQueryInformationProcess(h, ProcessProtectionInformation, ctypes.byref(level), 1,
                                                  ctypes.byref(got))
        return level.value if status >= 0 else None
    finally:
        _k32.CloseHandle(h)


def _open(pid: int):
    h = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        err = ctypes.get_last_error()
        if err == ERROR_INVALID_PARAMETER:  # no such process
            raise MemoryAccessError(f"pid {pid} gone", "gone")
        if err == ERROR_ACCESS_DENIED:
            if protection_level(pid):
                raise MemoryAccessError(f"pid {pid} is a protected process", "protected")
            raise MemoryAccessError(f"access denied for pid {pid}", "denied")
        raise MemoryAccessError(f"OpenProcess({pid}) failed: winerror {err}")
    return h


def _mapped_name(h, addr: int) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    n = _psapi.GetMappedFileNameW(h, ctypes.c_void_p(addr), buf, 1024)
    return buf.value if n else ""


def enumerate_regions(pid: int) -> list[Region]:
    h = _open(pid)
    regions: list[Region] = []
    try:
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        while addr < _MAX_USER_ADDR:
            got = _k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not got:
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize
            if size == 0:
                break
            if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_NOACCESS):
                probe = classify_region(mbi.Type, mbi.Protect, "x")
                path = _mapped_name(h, base) if probe["kind"] in ("image", "mapped") else ""
                regions.append(Region(start=base, size=size, path=path,
                                      **classify_region(mbi.Type, mbi.Protect, path)))
            nxt = base + size
            if nxt <= addr:
                break
            addr = nxt
    finally:
        _k32.CloseHandle(h)
    return regions


def read_memory(pid: int, address: int, size: int) -> bytes:
    if size <= 0:
        return b""
    h = _open(pid)
    try:
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        ok = _k32.ReadProcessMemory(h, ctypes.c_void_p(address), buf, size, ctypes.byref(got))
        if not ok and got.value == 0:
            raise MemoryAccessError(f"ReadProcessMemory failed at {address:#x}: winerror {ctypes.get_last_error()}")
        return buf.raw[: got.value]
    finally:
        _k32.CloseHandle(h)

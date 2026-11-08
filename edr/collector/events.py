"""Process start notifications from the operating system, so a process that lives for less than one poll
interval is still recorded.

Polling alone cannot see those: a process that starts and exits between two polls leaves nothing behind.
These sources only say "pid N just started". The collector reads the details right then and the normal
polling carries on for everything else (connections, memory, exits).

Linux    netlink process connector (needs root, a kernel with CONFIG_PROC_EVENTS)
Windows  WMI Win32_ProcessStartTrace through a PowerShell child process (needs Administrator)

Where a source is not available the collector falls back to polling and says why on the System sheet.
"""
from __future__ import annotations

import base64
import logging
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from typing import Callable

import psutil

log = logging.getLogger("aether.events")

ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]


class EventSource(threading.Thread):
    """Base: subclasses call self._seen(pid) for every new process the system announces."""

    kind = "none"

    def __init__(self, wake: Callable[[], None] | None = None) -> None:
        super().__init__(name=f"aether-events-{self.kind}", daemon=True)
        self.wake = wake or (lambda: None)
        self.pending: deque[dict] = deque(maxlen=2000)     # drained by the collector
        self.stop_event = threading.Event()
        self.active = False
        self.error: str | None = None
        self.seen = 0              # processes announced
        self.read = 0              # ... and still readable when we looked
        self.missed = 0            # ... already gone by then

    def _seen(self, pid: int, name: str | None = None, ppid: int | None = None) -> None:
        self.seen += 1
        ts = time.time()
        try:
            p = psutil.Process(pid)
            info = p.as_dict(attrs=ATTRS)
            if info.get("create_time") is None:
                raise psutil.NoSuchProcess(pid)
        except (psutil.Error, OSError):
            self.missed += 1
            if name:    # the system gave us the name and parent, so a short-lived process is still worth a record
                info = {"pid": pid, "ppid": ppid or 0, "name": name, "exe": "", "cmdline": [], "username": "",
                        "create_time": ts}
                self.pending.append({"proc": None, "info": info, "ts": ts, "partial": True})
                self.wake()
            return
        self.read += 1
        if not info.get("name") and name:
            info["name"] = name
        if not info.get("ppid") and ppid:
            info["ppid"] = ppid
        self.pending.append({"proc": p, "info": info, "ts": ts})
        self.wake()

    def status(self) -> dict:
        return {"kind": self.kind, "active": self.active and self.is_alive(), "error": self.error,
                "seen": self.seen, "read": self.read, "missed": self.missed}

    def stop(self) -> None:
        self.stop_event.set()


# -- Linux ---------------------------------------------------------------------------------------------
_NETLINK_CONNECTOR = 11
_CN_IDX_PROC = 1
_CN_VAL_PROC = 1
_PROC_CN_MCAST_LISTEN = 1
_PROC_EVENT_EXEC = 0x00000002
_NLMSG_DONE = 3
_NLMSG_HDR = struct.Struct("=IHHII")           # len, type, flags, seq, pid
_CN_MSG = struct.Struct("=IIIIHH")             # idx, val, seq, ack, len, flags
_PROC_EVENT = struct.Struct("=IIQ")            # what, cpu, timestamp_ns
_EXEC_DATA = struct.Struct("=II")              # process_pid, process_tgid


class ProcConnector(EventSource):
    kind = "netlink"

    def _open(self) -> socket.socket:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, _NETLINK_CONNECTOR)
        try:
            s.bind((0, _CN_IDX_PROC))               # port 0: the kernel picks one, so several listeners can coexist
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            except OSError:
                pass
            op = struct.pack("=I", _PROC_CN_MCAST_LISTEN)
            cn = _CN_MSG.pack(_CN_IDX_PROC, _CN_VAL_PROC, 0, 0, len(op), 0) + op
            s.send(_NLMSG_HDR.pack(_NLMSG_HDR.size + len(cn), _NLMSG_DONE, 0, 0, 0) + cn)
            s.settimeout(1.0)
            return s
        except OSError:
            s.close()
            raise

    def run(self) -> None:
        try:
            sock = self._open()
        except OSError as exc:
            self.error = f"netlink process connector not available ({exc.strerror or exc}). Needs root"
            log.info(self.error)
            return
        self.active = True
        try:
            while not self.stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(65536)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if exc.errno == 105:            # ENOBUFS: a burst overflowed the buffer, polling covers the gap
                        self.error = "event buffer overflowed during a burst, polling covered it"
                        continue
                    raise
                if addr[0] != 0:                    # only the kernel speaks here
                    continue
                self._parse(data)
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
            log.warning("process event source stopped: %s", self.error)
        finally:
            self.active = False
            sock.close()

    def _parse(self, data: bytes) -> None:
        off = 0
        while off + _NLMSG_HDR.size <= len(data):
            length = _NLMSG_HDR.unpack_from(data, off)[0]
            if length < _NLMSG_HDR.size or off + length > len(data):
                return
            body = off + _NLMSG_HDR.size + _CN_MSG.size
            if body + _PROC_EVENT.size + _EXEC_DATA.size <= off + length:
                what = _PROC_EVENT.unpack_from(data, body)[0]
                if what == _PROC_EVENT_EXEC:
                    pid, tgid = _EXEC_DATA.unpack_from(data, body + _PROC_EVENT.size)
                    if pid == tgid:                 # a thread calling exec is not a new process
                        self._seen(tgid)
            off += (length + 3) & ~3


# -- Windows -------------------------------------------------------------------------------------------
_PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try {
  Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier AetherStart | Out-Null
} catch {
  [Console]::Out.WriteLine('ERR|' + $_.Exception.Message); [Console]::Out.Flush(); exit 2
}
[Console]::Out.WriteLine('READY'); [Console]::Out.Flush()
while ($true) {
  $e = Wait-Event -SourceIdentifier AetherStart
  $n = $e.SourceEventArgs.NewEvent
  [Console]::Out.WriteLine(('P|' + $n.ProcessID + '|' + $n.ParentProcessID + '|' + $n.ProcessName)); [Console]::Out.Flush()
  Remove-Event -EventIdentifier $e.EventIdentifier
}
"""


class WmiStartTrace(EventSource):
    kind = "wmi"

    def run(self) -> None:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        # encoded, so quoting and line breaks in the script cannot be mangled on the way to PowerShell
        encoded = base64.b64encode(_PS_SCRIPT.encode("utf-16-le")).decode("ascii")
        try:
            proc = subprocess.Popen(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True,
                encoding="utf-8", errors="replace", creationflags=flags)
        except OSError as exc:
            self.error = f"PowerShell could not be started ({exc})"
            return
        self._proc = proc
        try:
            for line in proc.stdout:                # blocks until the child writes, ends when it exits
                if self.stop_event.is_set():
                    break
                line = line.strip()
                if line == "READY":
                    self.active = True
                elif line.startswith("ERR|"):
                    msg = line[4:]
                    self.error = ("Needs Administrator" if "denied" in msg.lower() else msg)[:200]
                elif line.startswith("P|"):
                    parts = line.split("|", 3)
                    try:
                        self._seen(int(parts[1]), name=parts[3] if len(parts) > 3 else None, ppid=int(parts[2]))
                    except (ValueError, IndexError):
                        continue
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.active = False
            if proc.poll() is None:
                proc.terminate()
            if not self.error and not self.stop_event.is_set():
                self.error = "the PowerShell watcher ended"

    def stop(self) -> None:
        super().stop()
        proc = getattr(self, "_proc", None)
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass


def create(wake: Callable[[], None] | None = None) -> EventSource | None:
    """The event source for this platform, not started yet. None where there is none."""
    if sys.platform.startswith("linux") and os.name == "posix":
        return ProcConnector(wake)
    if sys.platform == "win32":
        return WmiStartTrace(wake)
    return None

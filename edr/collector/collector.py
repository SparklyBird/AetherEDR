"""Telemetry collector.

Collects, with psutil + ctypes + /proc only (no osquery / Sysmon / Falco):
  * process creation / exit and parent-child lineage
  * per-process stats (CPU, RSS, threads) for the behavioural baseline
  * outbound TCP/UDP sockets and listening sockets mapped to PID + binary path
  * memory maps of processes, flagging unbacked executable and RWX regions

Collection is poll-based (default 5 s). Processes shorter-lived than the interval can be
missed; see README "Hardening roadmap" for kernel-event sources (ETW, proc connector).

Runs stand-alone:   python -m edr.collector.collector --once
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import random
import socket
import sys
import time
import threading
import uuid
from typing import Any, Iterable

import psutil

from . import events as osevents
from . import memory

log = logging.getLogger("aether.collector")
AGENT_VERSION = "1.0.0"
MAX_CMDLINE = 4096
MAX_HASH_BYTES = 200 * 1024 * 1024
_SKIP_STATES = {"TIME_WAIT", "CLOSE", "CLOSING", "NONE_SKIP"}


# ---- host identity -------------------------------------------------------------
def _machine_id() -> str:
    try:
        if sys.platform == "win32":
            import winreg  # noqa: PLC0415

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                return winreg.QueryValueEx(k, "MachineGuid")[0]
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if os.path.exists(p):
                return open(p).read().strip()
    except Exception:  # noqa: BLE001
        pass
    return f"{uuid.getnode():x}"


def is_admin() -> bool:
    try:
        if sys.platform == "win32":
            import ctypes  # noqa: PLC0415

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


def host_info() -> dict:
    hostname = socket.gethostname()
    ips: list[str] = []
    try:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    ips.append(a.address)
    except Exception:  # noqa: BLE001
        pass
    hid = hashlib.sha256(f"{_machine_id()}|{hostname}".encode()).hexdigest()[:16]
    return {
        "host_id": hid,
        "hostname": hostname,
        "os_name": platform.system(),
        "os_version": platform.platform(),
        "arch": platform.machine(),
        "ip_addresses": ips[:8],
        "agent_version": AGENT_VERSION,
        "is_admin": is_admin(),
        "boot_time": psutil.boot_time(),
        "capabilities": {
            "memory_introspection": memory.supported(),
            "net_attribution": True,
        },
    }


# ---- helpers -------------------------------------------------------------------
class _HashCache:
    def __init__(self) -> None:
        self._c: dict[tuple, str] = {}

    def sha256(self, path: str) -> str:
        try:
            st = os.stat(path)
            if st.st_size > MAX_HASH_BYTES:
                return ""
            key = (path, st.st_mtime_ns, st.st_size)
            if key in self._c:
                return self._c[key]
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            if len(self._c) > 5000:
                self._c.clear()
            self._c[key] = h.hexdigest()
            return self._c[key]
        except OSError:
            return ""


def _ms(ct: float) -> int:
    return int(round(ct * 1000))


def _endpoint(addr: Any) -> tuple[str, int]:
    if not addr:
        return "", 0
    return str(addr[0]), int(addr[1])


class Collector:
    def __init__(
        self,
        *,
        interval: float = 5.0,
        stats_interval: float = 30.0,
        memscan: bool = True,
        memscan_per_poll: int = 25,
        memscan_delays: tuple[float, ...] = (2.0, 30.0),
        memscan_period: float = 300.0,
        hash_binaries: bool = True,
        include_kernel_threads: bool = False,
        initial_spread: float = 60.0,
        use_events: bool = True,
    ) -> None:
        self.interval = interval
        self.stats_interval = stats_interval
        self.memscan = memscan and memory.supported()
        self.memscan_per_poll = memscan_per_poll
        self.memscan_delays = memscan_delays
        self.memscan_period = memscan_period
        self.hash_binaries = hash_binaries
        self.include_kernel_threads = include_kernel_threads
        self.initial_spread = initial_spread  # spreads first-poll memory scans over N seconds
        self.use_events = use_events
        self.events: osevents.EventSource | None = None   # started by start_events(), not by constructing
        self.wake = threading.Event()                     # set when the system announces a new process
        self.self_pid = os.getpid()
        self.host = host_info()
        self.known: dict[tuple[int, int], dict] = {}
        self.known_conns: dict[tuple, float] = {}
        self._hashes = _HashCache()
        self._first_poll = True
        self.stats: dict[str, Any] = {
            "polls": 0, "last_poll": None, "last_duration_ms": 0, "processes": 0,
            "events_emitted": 0, "unattributed_conns": 0, "mem_denied": 0, "mem_scans": 0,
            "short_lived": 0,
        }

    # -- filtering -----------------------------------------------------------------
    def _skip(self, info: dict) -> bool:
        pid = info.get("pid")
        if pid in (0, None):
            return True
        if sys.platform.startswith("linux") and not self.include_kernel_threads:
            if pid == 2 or info.get("ppid") == 2:
                return True
        return False

    # -- process events ------------------------------------------------------------
    def _start_event(self, proc: psutil.Process, info: dict, now: float) -> dict:
        pid = info["pid"]
        exe = info.get("exe") or ""
        exe_deleted = False
        if sys.platform.startswith("linux"):
            try:
                link = os.readlink(f"/proc/{pid}/exe")
                if link.endswith(" (deleted)"):
                    exe_deleted = True
                    exe = link[:-10]
                elif not exe:
                    exe = link
            except OSError:
                pass
        cmdline = " ".join(info.get("cmdline") or [])[:MAX_CMDLINE]
        try:
            cwd = proc.cwd() if proc is not None else ""
        except (psutil.Error, OSError):
            cwd = ""
        sha = self._hashes.sha256(exe) if (self.hash_binaries and exe and not exe_deleted) else ""
        return {
            "type": "process_start",
            "ts": now,
            "pid": pid,
            "ppid": info.get("ppid") or 0,
            "create_time": info["create_time"],
            "name": info.get("name") or os.path.basename(exe),
            "exe": exe,
            "exe_deleted": exe_deleted,
            "cmdline": cmdline,
            "cwd": cwd,
            "username": info.get("username") or "",
            "sha256": sha,
            "agent": pid == self.self_pid,
        }

    def _stats_event(self, key: tuple[int, int], rec: dict, now: float) -> dict | None:
        p: psutil.Process = rec["p"]
        try:
            with p.oneshot():
                return {
                    "type": "process_stats", "ts": now, "pid": key[0],
                    "create_time": rec["create_time"],
                    "cpu": p.cpu_percent(None),
                    "rss": p.memory_info().rss,
                    "threads": p.num_threads(),
                }
        except (psutil.Error, OSError):
            return None

    # -- network -------------------------------------------------------------------
    def _connections(self, current: dict[tuple[int, int], psutil.Process], now: float) -> list[dict]:
        by_pid = {k[0]: k for k in current}
        events: list[dict] = []
        seen: set[tuple] = set()
        try:
            conns: Iterable = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            conns = []
            for key, p in current.items():
                try:
                    for c in p.net_connections(kind="inet"):
                        conns.append(c._replace(pid=key[0]))
                except (psutil.Error, OSError):
                    continue
        unattributed = 0
        for c in conns:
            if c.pid is None or c.pid not in by_pid:
                unattributed += 1
                continue
            status = c.status or ""
            if status in _SKIP_STATES:
                continue
            laddr, lport = _endpoint(c.laddr)
            raddr, rport = _endpoint(c.raddr)
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            if proto == "tcp" and status == "LISTEN":
                direction = "listen"
            elif proto == "udp" and not raddr:
                direction = "listen"
            elif raddr:
                direction = "outbound"
            else:
                continue
            key = by_pid[c.pid]
            ck = (key, proto, laddr, lport, raddr, rport)
            seen.add(ck)
            if ck in self.known_conns:
                self.known_conns[ck] = now
                continue
            self.known_conns[ck] = now
            events.append({
                "type": "net_connect", "ts": now, "pid": key[0],
                "create_time": self.known[key]["create_time"] if key in self.known else 0,
                "direction": direction, "proto": proto,
                "laddr": laddr, "lport": lport, "raddr": raddr, "rport": rport, "status": status,
            })
        # forget closed sockets so reconnects (beaconing) are seen as new again
        for ck in [k for k in self.known_conns if k not in seen]:
            del self.known_conns[ck]
        self.stats["unattributed_conns"] = unattributed
        return events

    # -- memory --------------------------------------------------------------------
    def _schedule_next_mem(self, rec: dict, now: float) -> None:
        stage = rec["mem_stage"]
        if stage < len(self.memscan_delays):
            delay = self.memscan_delays[stage]
        else:
            delay = self.memscan_period * random.uniform(0.9, 1.1)
        rec["mem_stage"] = stage + 1
        rec["next_mem"] = now + delay

    def scan_memory(self, pid: int, create_time: float, now: float | None = None) -> dict | None:
        try:
            result = memory.analyze(pid)
        except memory.MemoryAccessError as exc:
            self.stats["mem_denied"] += 1
            log.debug("memory scan skipped pid=%s: %s", pid, exc)
            if exc.reason == "gone":
                return None
            # tell the server why, so a blind spot shows up as one instead of looking like a clean process
            return {"type": "memory_unreadable", "ts": now or time.time(), "pid": pid, "create_time": create_time,
                    "reason": exc.reason if exc.reason in ("protected", "denied") else "other"}
        self.stats["mem_scans"] += 1
        return {
            "type": "memory_scan", "ts": now or time.time(), "pid": pid, "create_time": create_time,
            "summary": result["summary"], "regions": result["regions"],
        }

    def _memory_events(self, now: float) -> list[dict]:
        if not self.memscan:
            return []
        due = sorted(
            ((rec["next_mem"], key) for key, rec in self.known.items() if rec["next_mem"] <= now),
            key=lambda t: t[0],
        )[: self.memscan_per_poll]
        events: list[dict] = []
        for _, key in due:
            rec = self.known[key]
            ev = self.scan_memory(key[0], rec["create_time"], now)
            self._schedule_next_mem(rec, now)
            if ev and ev["type"] == "memory_unreadable":
                if rec.get("unreadable") == ev["reason"]:
                    ev = None            # already told the server, retries stay quiet
                else:
                    rec["unreadable"] = ev["reason"]
            elif ev:
                rec.pop("unreadable", None)
            if ev:
                events.append(ev)
        return events

    # -- OS notifications ----------------------------------------------------------
    def start_events(self) -> None:
        """Listen for process starts between polls and set self.wake when one arrives. Does nothing when the
        platform has no source or it is switched off, and the status says why."""
        if not self.use_events or self.events is not None:
            return
        src = osevents.create(self.wake.set)
        if src is None:
            return
        self.events = src
        src.start()

    def stop_events(self) -> None:
        if self.events is not None:
            self.events.stop()
        self.wake.set()

    def event_status(self) -> dict:
        if not self.use_events:
            return {"kind": "none", "active": False, "error": "switched off (AETHER_EVENTS=0)"}
        if self.events is None:
            return {"kind": "none", "active": False, "error": "no event source on this platform"}
        return self.events.status()

    def _take_hints(self) -> dict[tuple[int, int], dict]:
        out: dict[tuple[int, int], dict] = {}
        if self.events is None:
            return out
        while True:
            try:
                h = self.events.pending.popleft()
            except IndexError:
                return out
            info = h["info"]
            if not self._skip(info):
                out[(info["pid"], _ms(info["create_time"]))] = h

    def _track(self, key: tuple[int, int], p: psutil.Process, info: dict, now: float, events: list[dict],
               ts: float | None = None) -> None:
        """First sight of a process: emit its start and begin following it."""
        try:
            p.cpu_percent(None)  # prime
        except psutil.Error:
            pass
        events.append(self._start_event(p, info, ts or now))
        self.known[key] = {
            "p": p, "create_time": info["create_time"],
            "next_stats": now + self.stats_interval,
            "mem_stage": 0,
            "next_mem": now + (random.uniform(0.0, self.initial_spread) if self._first_poll else self.memscan_delays[0]),
        }

    def _short_lived(self, hints: dict, now: float, events: list[dict]) -> None:
        """Announced by the system, started and gone before any poll saw it: record both ends."""
        for key, h in hints.items():
            if key in self.known:
                continue
            events.append(self._start_event(h.get("proc"), h["info"], h["ts"]))
            events.append({"type": "process_exit", "ts": now, "pid": key[0], "create_time": h["info"]["create_time"]})
            self.stats["short_lived"] += 1

    def flush_hints(self) -> dict | None:
        """Between polls: handle processes the system announced, without scanning everything again."""
        if self._first_poll or self.events is None:
            return None
        hints = self._take_hints()
        if not hints:
            return None
        now = time.time()
        events: list[dict] = []
        ghosts: dict = {}
        for key, h in hints.items():
            if key in self.known:
                continue
            p = h.get("proc")
            if p is None:                       # only name and parent were known, try once more for the rest
                try:
                    p = psutil.Process(key[0])
                    fresh = p.as_dict(attrs=osevents.ATTRS)
                    if fresh.get("create_time") is not None:
                        key = (key[0], _ms(fresh["create_time"]))
                        h = dict(h, info=dict(fresh, name=fresh.get("name") or h["info"]["name"]))
                        if key in self.known:
                            continue
                except (psutil.Error, OSError):
                    p = None
            try:
                alive = p is not None and p.is_running()
            except psutil.Error:
                alive = False
            if alive:
                self._track(key, p, h["info"], now, events, ts=h["ts"])
            else:
                ghosts[key] = h
        self._short_lived(ghosts, now, events)
        if not events:
            return None
        self.stats["events_emitted"] += len(events)
        return {"host": self.host, "events": events, "sent_at": now}

    # -- main poll -----------------------------------------------------------------
    def poll(self) -> dict:
        t0 = time.time()
        now = t0
        events: list[dict] = []
        current: dict[tuple[int, int], psutil.Process] = {}
        infos: dict[tuple[int, int], dict] = {}

        attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
        for p in psutil.process_iter(attrs):
            info = p.info
            if self._skip(info) or info.get("create_time") is None:
                continue
            key = (info["pid"], _ms(info["create_time"]))
            current[key] = p
            infos[key] = info

        hints = self._take_hints()
        for key, p in current.items():
            if key in self.known:
                continue
            self._track(key, p, infos[key], now, events, ts=hints.pop(key, {}).get("ts"))
        pids_now = {k[0] for k in current}
        self._short_lived({k: h for k, h in hints.items() if k not in current and not (h.get("partial") and k[0] in pids_now)},
                          now, events)

        for key in [k for k in self.known if k not in current]:
            rec = self.known.pop(key)
            events.append({"type": "process_exit", "ts": now, "pid": key[0], "create_time": rec["create_time"]})

        if not self._first_poll:
            for key, rec in self.known.items():
                if rec["next_stats"] <= now:
                    rec["next_stats"] = now + self.stats_interval
                    ev = self._stats_event(key, rec, now)
                    if ev:
                        events.append(ev)

        events.extend(self._connections(current, now))
        events.extend(self._memory_events(now))

        payload_live = [[k[0], infos[k]["create_time"]] for k in current] if self._first_poll else None
        self._first_poll = False
        self.stats.update(
            polls=self.stats["polls"] + 1, last_poll=now, processes=len(current),
            last_duration_ms=int((time.time() - t0) * 1000),
            events_emitted=self.stats["events_emitted"] + len(events),
        )
        batch = {"host": self.host, "events": events, "sent_at": time.time()}
        if payload_live is not None:
            # every process alive right now. The server closes any it still has as running that is not
            # listed here (they exited while the app was closed or the PC rebooted)
            batch["live"] = payload_live
        return batch


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="AetherEDR collector (stand-alone, prints JSON)")
    ap.add_argument("--once", action="store_true", help="single poll then exit")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--no-memory", action="store_true")
    args = ap.parse_args(argv)
    c = Collector(interval=args.interval, memscan=not args.no_memory, memscan_delays=(0.0,), initial_spread=0.0)
    while True:
        batch = c.poll()
        if args.once:
            # second poll right away so memory scans scheduled in the first one run
            batch["events"].extend(c.poll()["events"])
        print(json.dumps(batch, default=str))
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())

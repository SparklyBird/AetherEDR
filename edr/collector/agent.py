"""Runs the Collector and sends its batches to a sink.

LocalSink  - in-process ingestion straight into the embedded SQLite DB
HttpSink   - POST /api/ingest/ to a remote AetherEDR server (agent-only mode)
"""
from __future__ import annotations

import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import deque

from .collector import Collector

log = logging.getLogger("aether.agent")
CHUNK = 500


class LocalSink:
    def send(self, batch: dict) -> None:
        from edr.engine.pipeline import ingest  # noqa: PLC0415 (needs Django set up)

        ingest(batch)


class HttpSink:
    def __init__(self, server: str, key: str, timeout: float = 20.0, ca_cert: str | None = None) -> None:
        self.url = server.rstrip("/") + "/api/ingest/"
        self.key = key
        self.timeout = timeout
        # a self-signed server certificate is trusted by pointing at that one file, nothing else is switched off
        self.context = ssl.create_default_context(cafile=ca_cert) if ca_cert else None

    def send(self, batch: dict) -> None:
        events = batch["events"]
        for i in range(0, max(len(events), 1), CHUNK):
            part = dict(batch, events=events[i : i + CHUNK])
            if i:
                part.pop("live", None)  # the full list only needs to go once
            req = urllib.request.Request(
                self.url,
                data=json.dumps(part, default=str).encode(),
                headers={"Content-Type": "application/json", "X-Aether-Key": self.key},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.context) as resp:  # noqa: S310
                resp.read()


class AgentThread(threading.Thread):
    def __init__(self, sink, collector: Collector | None = None, interval: float = 5.0) -> None:
        super().__init__(name="aether-agent", daemon=True)
        self.sink = sink
        self.collector = collector or Collector(interval=interval)
        self.interval = interval
        self.stop_event = threading.Event()
        self.pending: deque[dict] = deque(maxlen=200)  # retry buffer while the sink is down
        self.last_error: str | None = None
        self.cycles = 0
        self.failures = 0
        self.last_ok: float | None = None       # epoch seconds of the last good cycle
        self.last_cycle_ms: int | None = None

    def run(self) -> None:
        log.info("collector started (interval %.1fs, memory introspection=%s)",
                 self.interval, self.collector.memscan)
        try:
            self.collector.start_events()
        except Exception:  # noqa: BLE001 - polling works without it
            log.exception("process event source could not start")
        next_full = 0.0
        while not self.stop_event.is_set():
            started = time.time()
            full = started >= next_full
            try:
                # a full scan every interval; in between, only the processes the system announced
                batch = self.collector.poll() if full else self.collector.flush_hints()
                if batch is not None:
                    self.pending.append(batch)
                while self.pending:
                    self.sink.send(self.pending[0])
                    self.pending.popleft()
                self.last_error = None
                self.last_ok = time.time()
            except (urllib.error.URLError, OSError) as exc:
                self.failures += 1
                self.last_error = f"sink unavailable: {exc}"
                if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                    self.last_error += " (the server uses a self-signed certificate: pass its server.crt with --ca-cert)"
                log.warning(self.last_error)
            except Exception as exc:  # noqa: BLE001
                self.failures += 1
                self.last_error = f"{type(exc).__name__}: {exc}"
                log.exception("collector cycle failed")
                self.pending.clear()
            finally:
                if full:
                    self.cycles += 1
                    self.last_cycle_ms = int((time.time() - started) * 1000)
                try:
                    from django.db import close_old_connections  # noqa: PLC0415

                    close_old_connections()   # a stale SQLite handle would break every later cycle
                except Exception:  # noqa: BLE001
                    pass
            if full:
                next_full = started + max(0.5, self.interval)
            wake = self.collector.wake
            if wake.wait(max(0.0, next_full - time.time())) and not self.stop_event.is_set():
                wake.clear()
                self.stop_event.wait(0.25)      # let a burst of new processes gather into one batch
            elif self.stop_event.is_set():
                break

    def stop(self) -> None:
        self.stop_event.set()
        self.collector.stop_events()


class Supervisor(threading.Thread):
    """Restarts the collector thread if it dies and logs that it did."""

    def __init__(self, state: dict, interval: float = 15.0) -> None:
        super().__init__(name="aether-supervisor", daemon=True)
        self.state = state
        self.interval = interval
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.wait(self.interval):
            agent = self.state.get("agent")
            if agent is None or agent.stop_event.is_set() or agent.is_alive():
                continue
            log.error("collector thread died (%s); restarting", agent.last_error or "unknown reason")
            fresh = AgentThread(agent.sink, agent.collector, interval=agent.interval)
            fresh.restarts = getattr(agent, "restarts", 0) + 1
            fresh.last_error = f"restarted after: {agent.last_error or 'unexpected stop'}"
            self.state["agent"] = fresh
            fresh.start()

    def stop(self) -> None:
        self.stop_event.set()

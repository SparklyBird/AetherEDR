"""State shared between the launcher and the API views."""
from __future__ import annotations

import threading
import time

from .engine import yara_scanner
from .engine.anomaly import engine as anomaly_engine

state: dict = {"agent": None, "mode": "server", "started_at": time.time()}

# the launcher puts a function in state["shutdown"] that stops the whole program; nothing else does
SHUTDOWN_DELAY = 0.7


def can_stop() -> bool:
    return callable(state.get("shutdown"))


def request_shutdown(delay: float | None = None) -> bool:
    """Stop the program a moment from now, so the HTTP reply that asked for it still gets out.
    False when there is no stop function (tests, manage.py runserver)."""
    hook = state.get("shutdown")
    if not callable(hook):
        return False
    state["stopping"] = True          # live streams end on their own, so the server is not kept waiting for them
    timer = threading.Timer(SHUTDOWN_DELAY if delay is None else delay, hook)
    timer.daemon = True
    timer.start()
    return True


def agent_status() -> dict:
    agent = state.get("agent")
    out = {
        "mode": state["mode"],
        "uptime_s": int(time.time() - state["started_at"]),
        "collector_running": bool(agent and agent.is_alive()),
        "yara": yara_scanner.AVAILABLE,
        "can_stop": can_stop(),
        "baseline": {"trained": anomaly_engine.ready, "samples": anomaly_engine.trained_on,
                     "trained_at": anomaly_engine.trained_at},
    }
    if agent:
        c = agent.collector
        out.update({
            "interval": agent.interval, "memory_introspection": c.memscan,
            "is_admin": c.host["is_admin"], "stats": c.stats, "last_error": agent.last_error,
            "cycles": agent.cycles, "failures": agent.failures, "last_ok": agent.last_ok,
            "last_cycle_ms": agent.last_cycle_ms, "restarts": getattr(agent, "restarts", 0),
            "hostname": c.host["hostname"], "events": c.event_status(),
        })
    return out

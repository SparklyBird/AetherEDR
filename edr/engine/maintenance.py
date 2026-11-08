"""Periodic cleanup: retrains the baseline and prunes old rows."""
from __future__ import annotations

import logging
import threading
from datetime import timedelta

from django.conf import settings
from django.db import close_old_connections, connection, transaction
from django.db.models import Count, Q
from django.utils import timezone

from edr.models import Alert, Connection, MemoryScan, Process, YaraJob

from . import pipeline
from .anomaly import engine

log = logging.getLogger("aether.maintenance")


def retrain_baseline() -> bool:
    cfg = settings.AETHER
    qs = (Process.objects.filter(mem_scanned_at__isnull=False, is_agent=False)
          .select_related(*pipeline.ANCESTOR_SELECT).order_by("-id")[:20000])
    procs = list(qs)
    if len(procs) < cfg["BASELINE_MIN_SAMPLES"]:
        return False
    freq = dict(Process.objects.values_list("exe").annotate(n=Count("id")))
    rows = []
    for p in procs:
        rows.append({
            "name": p.name, "exe": p.exe, "cmdline": p.cmdline, "last_cpu": p.last_cpu, "last_rss": p.last_rss,
            "last_threads": p.last_threads, "mem_summary": p.mem_summary, "net_out": p.net_out,
            "net_remotes": p.net_remotes, "net_listen": p.net_listen, "depth": len(pipeline._ancestors(p)),
            "exe_freq": freq.get(p.exe, 1),
        })
    return engine.train(rows, cfg["BASELINE_MIN_SAMPLES"])


def prune() -> dict:
    days = settings.AETHER["RETENTION_DAYS"]
    cutoff = timezone.now() - timedelta(days=days)
    out = {}
    stale = Process.objects.filter(ended_at__lt=cutoff)
    kept = _ancestors_of_running()      # an old parent of something still running stays, so the lineage holds
    if kept:
        stale = stale.exclude(pk__in=kept)
    out["processes"] = stale.delete()[0]
    out["connections"] = Connection.objects.filter(first_seen__lt=cutoff).delete()[0]
    out["memory_scans"] = MemoryScan.objects.filter(ts__lt=cutoff).delete()[0]
    out["yara_jobs"] = YaraJob.objects.filter(requested_at__lt=cutoff).delete()[0]
    out["alerts"] = Alert.objects.filter(last_seen__lt=cutoff, status__in=("closed", "false_positive")).delete()[0]
    return out


def _ancestors_of_running(host_id: int | None = None) -> set[int]:
    """Ids of ended processes that are a parent, grandparent and so on of something still running.
    Deleting one would cut a running process loose from its lineage, so these stay."""
    qs = Process.objects.filter(ended_at__isnull=True, parent__isnull=False)
    if host_id is not None:
        qs = qs.filter(host_id=host_id)
    keep: set[int] = set()
    frontier = set(qs.values_list("parent_id", flat=True))
    while frontier:
        keep |= frontier
        ids = list(frontier)
        nxt: set[int] = set()
        for i in range(0, len(ids), 500):
            nxt |= set(Process.objects.filter(pk__in=ids[i:i + 500], parent__isnull=False).values_list("parent_id", flat=True))
        frontier = nxt - keep
    ids = list(keep)
    ended: set[int] = set()
    for i in range(0, len(ids), 500):
        ended |= set(Process.objects.filter(pk__in=ids[i:i + 500], ended_at__isnull=False).values_list("pk", flat=True))
    return ended


def clear_history(days: int | None = None, *, alerts: bool = True, host_id: int | None = None, dry_run: bool = False) -> dict:
    """Manual cleanup from the console.

    Removes processes that have ended (and their sockets, memory scans and YARA jobs), plus the alerts that
    belong to nothing still running. days=None or 0 means everything that qualifies, otherwise only rows
    older than that many days. Running processes are never touched: they would be re-created on the next poll
    with the same findings. Exceptions and the response log are kept.
    """
    cutoff = timezone.now() - timedelta(days=days) if days else None
    procs = Process.objects.filter(ended_at__isnull=False)
    if cutoff:
        procs = procs.filter(ended_at__lt=cutoff)
    if host_id is not None:
        procs = procs.filter(host_id=host_id)
    kept = _ancestors_of_running(host_id)
    if kept:
        procs = procs.exclude(pk__in=kept)
    pids = procs.values("pk")

    stale_alerts = Alert.objects.filter(Q(process__isnull=True) | Q(process__ended_at__isnull=False))
    if cutoff:
        stale_alerts = stale_alerts.filter(last_seen__lt=cutoff)
    if host_id is not None:
        stale_alerts = stale_alerts.filter(host_id=host_id)

    out = {
        "processes": procs.count(),
        "connections": Connection.objects.filter(process__in=pids).count(),
        "memory_scans": MemoryScan.objects.filter(process__in=pids).count(),
        "yara_jobs": YaraJob.objects.filter(process__in=pids).count(),
        "alerts": stale_alerts.count() if alerts else 0,
    }
    out["running_kept"] = Process.objects.filter(ended_at__isnull=True, **({"host_id": host_id} if host_id is not None else {})).count()
    out["lineage_kept"] = len(kept)
    if dry_run:
        return out
    with transaction.atomic():
        if alerts:
            stale_alerts.delete()
        procs.delete()      # sockets, scans and YARA jobs go with them
    pipeline._PREV_CACHE.clear()
    log.info("history cleared (days=%s, alerts=%s): %s", days, alerts, out)
    return out


def compact() -> bool:
    """Give freed pages back to the OS so the database file shrinks. Best effort: skipped when busy."""
    try:
        with connection.cursor() as cur:
            cur.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            cur.execute("VACUUM")
        return True
    except Exception:  # noqa: BLE001 - locked by the collector, or running inside a test transaction
        log.info("compact skipped", exc_info=True)
        return False


class MaintenanceThread(threading.Thread):
    def __init__(self) -> None:
        super().__init__(name="aether-maintenance", daemon=True)
        self.stop_event = threading.Event()

    def run(self) -> None:
        every = settings.AETHER["BASELINE_RETRAIN_EVERY"]
        first = True
        while not self.stop_event.wait(45 if first else every):
            first = False
            close_old_connections()
            try:
                retrain_baseline()
                n = prune()
                if any(n.values()):
                    log.info("retention prune: %s", n)
            except Exception:  # noqa: BLE001
                log.exception("maintenance cycle failed")
            finally:
                connection.close()

    def stop(self) -> None:
        self.stop_event.set()

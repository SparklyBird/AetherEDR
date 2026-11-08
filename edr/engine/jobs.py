"""Background YARA scan jobs. Small thread pool, one DB connection per worker."""
from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import psutil
from django.db import close_old_connections, connection
from django.utils import timezone

from edr.collector.collector import host_info
from edr.models import Process, YaraJob

from . import pipeline, yara_scanner

log = logging.getLogger("aether.jobs")
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="aether-yara")
_local_host_id: str | None = None
AUTO_COOLDOWN = timedelta(minutes=10)


def local_host_id() -> str:
    global _local_host_id
    if _local_host_id is None:
        _local_host_id = host_info()["host_id"]
    return _local_host_id


def submit(job_id: int) -> None:
    _pool.submit(_run, job_id)


def submit_auto(process_id: int) -> int | None:
    """Queue a scan of flagged regions unless one ran recently."""
    if not yara_scanner.AVAILABLE:
        return None
    host_id = Process.objects.filter(pk=process_id).values_list("host__host_id", flat=True).first()
    if host_id != local_host_id():
        return None  # memory can only be read on the endpoint that owns the process
    since = timezone.now() - AUTO_COOLDOWN
    if YaraJob.objects.filter(process_id=process_id, requested_at__gte=since).exists():
        return None
    job = YaraJob.objects.create(process_id=process_id, scope="flagged", auto=True, requested_at=timezone.now())
    submit(job.id)
    return job.id


def _fail(job: YaraJob, msg: str) -> None:
    job.status, job.error, job.finished_at = "error", msg, timezone.now()
    job.save(update_fields=["status", "error", "finished_at"])


def _run(job_id: int) -> None:
    close_old_connections()
    try:
        job = YaraJob.objects.select_related("process", "process__host").get(pk=job_id)
        job.status, job.started_at = "running", timezone.now()
        job.save(update_fields=["status", "started_at"])
        p: Process = job.process

        if p.host.host_id != local_host_id():
            return _fail(job, "Memory scans run on the endpoint that owns the process; this process belongs to a remote host.")
        if p.pid == os.getpid() or p.is_agent:
            return _fail(job, "Refusing to scan the AetherEDR agent itself (its own rule text would match).")
        if p.ended_at is not None:
            return _fail(job, "Process has exited; its memory is gone.")
        try:
            live = psutil.Process(p.pid)
            if abs(live.create_time() * 1000 - p.create_ms) > 1500:
                return _fail(job, "PID was reused by another process.")
        except psutil.Error:
            return _fail(job, "Process is no longer running.")

        rule_sets = []
        try:
            if job.use_builtin:
                rule_sets.append(yara_scanner.builtin_rules())
            if job.custom_rules.strip():
                rule_sets.append(yara_scanner.compile_custom(job.custom_rules))
        except yara_scanner.RuleError as exc:
            return _fail(job, str(exc))
        if not rule_sets:
            return _fail(job, "No rules selected.")

        res = yara_scanner.scan_process(p.pid, rule_sets, scope=job.scope, exe_path=p.exe if not p.exe_deleted else "",
                                        include_file=job.include_file)
        job.matches = res["matches"]
        job.regions_scanned, job.bytes_scanned = res["regions_scanned"], res["bytes_scanned"]
        job.status, job.finished_at = "done", timezone.now()
        job.save()
        if res["matches"]:
            pipeline.raise_yara_alerts(job, res["matches"])
    except Exception as exc:  # noqa: BLE001
        log.exception("yara job %s failed", job_id)
        try:
            _fail(YaraJob.objects.get(pk=job_id), f"{type(exc).__name__}: {exc}")
        except Exception:  # noqa: BLE001
            pass
    finally:
        connection.close()

from __future__ import annotations

import csv
import io
import json
import logging
import os
import platform
import sys
import time
from collections import defaultdict
from datetime import timedelta

import psutil
from django.conf import settings
from django.db import connection
from django.db.models import Count, Q
from django.http import HttpResponse, StreamingHttpResponse
from django.utils import timezone
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, NotFound, ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from aether import __version__

from . import runtime
from .auth import IsAgentOrOperator
from .collector import memory as memlib
from .engine import catalog as rule_catalog
from .engine import jobs, maintenance, pipeline, rules, yara_scanner
from .models import ActionLog, Alert, Connection, Host, MemoryScan, Process, Suppression, YaraJob
from .serializers import (ActionLogSerializer, AlertSerializer, AlertUpdateSerializer, ConnectionSerializer, HostSerializer,
                          IngestSerializer, MemoryScanSerializer, ProcessListSerializer, SuppressionSerializer,
                          YaraJobSerializer, YaraRequestSerializer)

log = logging.getLogger("aether.api")


class YaraUnavailable(APIException):
    status_code = 503
    default_detail = yara_scanner.UNAVAILABLE_MSG
    default_code = "yara_unavailable"


def _need_yara() -> None:
    if not yara_scanner.AVAILABLE:
        raise YaraUnavailable()


def _csv(request, name: str) -> list[str]:
    return [v for v in request.query_params.get(name, "").split(",") if v]


def _int(request, name: str, default: int | None = None) -> int | None:
    raw = request.query_params.get(name)
    if raw in (None, ""):
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValidationError({name: "must be an integer"})


# ---------------------------------------------------------------------------------------
class HealthView(APIView):
    authentication_classes: list = []
    permission_classes = [AllowAny]

    def get(self, request):
        from aether import __version__

        try:
            connection.ensure_connection()
            db = "ok"
        except Exception as exc:  # noqa: BLE001
            log.error("health: database unavailable: %s", exc)
            db = "unavailable"
        return Response({"status": "ok" if db == "ok" else "degraded", "db": db, "version": __version__})


class IngestView(APIView):
    permission_classes = [IsAgentOrOperator]

    def post(self, request):
        ser = IngestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        result = pipeline.ingest(ser.validated_data)
        return Response(result, status=status.HTTP_202_ACCEPTED)


class HostViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = HostSerializer

    def get_queryset(self):
        return Host.objects.annotate(
            process_count=Count("processes", filter=Q(processes__ended_at__isnull=True), distinct=True),
            open_alerts=Count("alerts", filter=Q(alerts__status="open"), distinct=True),
        )


class ProcessViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ProcessListSerializer
    ORDERING = {"risk_score", "started_at", "name", "pid", "net_out", "last_rss", "last_cpu"}

    def get_queryset(self):
        qs = Process.objects.select_related("host")
        q = self.request.query_params
        if q.get("host"):
            qs = qs.filter(host_id=q["host"])
        if q.get("search"):
            s = q["search"]
            qs = qs.filter(Q(name__icontains=s) | Q(exe__icontains=s) | Q(cmdline__icontains=s) | Q(username__icontains=s))
        if q.get("min_score"):
            qs = qs.filter(risk_score__gte=_int(self.request, "min_score"))
        if q.get("alive") in ("1", "true"):
            qs = qs.filter(ended_at__isnull=True)
        elif q.get("alive") in ("0", "false"):
            qs = qs.filter(ended_at__isnull=False)
        if q.get("pid"):
            qs = qs.filter(pid=_int(self.request, "pid"))
        order = q.get("ordering", "-risk_score")
        if order.lstrip("-") in self.ORDERING:
            qs = qs.order_by(order, "-id")
        return qs

    def retrieve(self, request, *args, **kwargs):
        p = self.get_object()
        data = ProcessListSerializer(p).data
        ancestors = []
        cur, seen = p.parent, {p.id}
        while cur is not None and cur.id not in seen and len(ancestors) < 16:
            ancestors.append(ProcessListSerializer(cur).data)
            seen.add(cur.id)
            cur = cur.parent
        data.update({
            "yara_available": yara_scanner.AVAILABLE, "cwd": p.cwd, "findings": p.findings, "muted": p.muted, "mem_summary": p.mem_summary, "mem_regions": p.mem_regions,
            "mem_scanned_at": p.mem_scanned_at, "mem_unreadable": p.mem_unreadable, "yara_hits": p.yara_hits,
            "last_threads": p.last_threads,
            "net_remotes": p.net_remotes,
            "ancestors": ancestors,
            "children": ProcessListSerializer(p.children.select_related("host").order_by("-risk_score")[:50], many=True).data,
            "connections": ConnectionSerializer(p.connections.select_related("process")[:150], many=True).data,
            "alerts": AlertSerializer(p.alerts.select_related("host")[:50], many=True).data,
            "yara_jobs": YaraJobSerializer(p.yara_jobs.select_related("process")[:10], many=True).data,
        })
        return Response(data)

    # -- export ---------------------------------------------------------------------------
    EXPORT_CAP = 5000
    EXPORT_CONN_CAP = 25
    EXPORT_CSV_COLUMNS = ["host", "pid", "ppid", "process", "path", "user", "started_at", "ended_at", "running", "risk",
                          "severity", "state", "rule_id", "weight", "title", "tactic", "technique", "description",
                          "lineage", "cmdline", "evidence", "silenced_by", "sha256"]

    @action(detail=False, methods=["get"], url_path="export")
    def export(self, request):
        """Flagged processes with findings, evidence and context. JSON has everything, CSV has one row per finding.

        Default is every process at or above the alert threshold. Same filters as the list
        (`host`, `min_score`, `alive`, `search`). Uses `type` because DRF reserves `format`.
        """
        kind = request.query_params.get("type", "json").lower()
        if kind not in ("csv", "json"):
            raise ValidationError({"type": "csv or json"})
        cfg = settings.AETHER
        qs = self.get_queryset()
        if not request.query_params.get("min_score"):
            qs = qs.filter(risk_score__gte=cfg["ALERT_THRESHOLD"])
        qs = qs.select_related(*pipeline.ANCESTOR_SELECT)
        total = qs.count()
        procs = list(qs[: self.EXPORT_CAP])
        conns = self._export_conns([p.id for p in procs])
        records = [self._export_record(p, conns.get(p.id, [])) for p in procs]
        now = timezone.now()
        stamp = now.strftime("%Y%m%d-%H%M")

        if kind == "json":
            by_sev: dict[str, int] = defaultdict(int)
            by_rule: dict[tuple, dict] = {}
            for r in records:
                by_sev[r["severity"]] += 1
                for f in r["findings"]:
                    e = by_rule.setdefault((f["rule_id"], f["weight"]), {
                        "rule_id": f["rule_id"], "weight": f["weight"], "title": f["title"], "processes": 0})
                    e["processes"] += 1
            doc = {
                "meta": {
                    "generated_at": now.isoformat(), "tool": "AetherEDR", "version": __version__,
                    "filters": {k: request.query_params.get(k) for k in ("host", "min_score", "alive", "search")
                                if request.query_params.get(k)} | {"effective_min_score": _int(request, "min_score", cfg["ALERT_THRESHOLD"])},
                    "alert_threshold": cfg["ALERT_THRESHOLD"], "matched": total, "exported": len(records),
                    "truncated": total > len(records),
                    "scoring": "risk = 100 * (1 - prod(1 - weight/100)) over active findings; "
                               "severity: >=80 critical, >=60 high, >=40 medium, else low. "
                               "Silenced findings are listed under 'silenced' and do not count.",
                    "caution": "Command lines and paths are copied verbatim and can contain secrets or user names.",
                },
                "summary": {
                    "by_severity": dict(by_sev),
                    "by_rule": sorted(by_rule.values(), key=lambda e: (-e["processes"], -e["weight"], e["rule_id"])),
                },
                "processes": records,
            }
            resp = HttpResponse(json.dumps(doc, default=str, indent=1), content_type="application/json")
        else:
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(self.EXPORT_CSV_COLUMNS)
            for r in records:
                base = {
                    "host": r["host"], "pid": r["pid"], "ppid": r["ppid"], "process": r["name"], "path": r["exe"],
                    "user": r["username"], "started_at": r["started_at"], "ended_at": r["ended_at"] or "",
                    "running": "yes" if r["alive"] else "no", "risk": r["risk_score"], "severity": r["severity"],
                    "lineage": r["lineage"], "cmdline": r["cmdline"], "sha256": r["sha256"],
                }
                rows = [("active", f) for f in r["findings"]] + [("silenced", f) for f in r["silenced"]]
                for state, f in rows or [("active", {})]:
                    ev = json.dumps(f.get("evidence") or {}, default=str, separators=(",", ":"))
                    row = dict(base, state=state, rule_id=f.get("rule_id", ""), weight=f.get("weight", ""),
                               title=f.get("title", ""), tactic=f.get("tactic", ""), technique=f.get("technique", ""),
                               description=f.get("description", ""), evidence=ev[:2000],
                               silenced_by=f.get("suppression", ""))
                    w.writerow([_cell(row.get(c)) for c in self.EXPORT_CSV_COLUMNS])
            resp = HttpResponse("\ufeff" + buf.getvalue(), content_type="text/csv; charset=utf-8")
        resp["Content-Disposition"] = f'attachment; filename="AetherEDR-processes-{stamp}.{kind}"'
        return resp

    def _export_conns(self, ids: list[int]) -> dict[int, list[dict]]:
        out: dict[int, list[dict]] = defaultdict(list)
        for i in range(0, len(ids), 500):  # in chunks to stay under the SQLite variable limit
            rows = Connection.objects.filter(process_id__in=ids[i:i + 500]).order_by("process_id", "-first_seen")
            for c in rows.iterator():
                bucket = out[c.process_id]
                if len(bucket) < self.EXPORT_CONN_CAP:
                    bucket.append({"direction": c.direction, "proto": c.proto, "local": f"{c.laddr}:{c.lport}",
                                   "remote": f"{c.raddr}:{c.rport}" if c.raddr else "", "scope": c.scope,
                                   "country": c.country, "asn": c.asn, "as_org": c.as_org, "hostname": c.hostname,
                                   "status": c.status, "first_seen": c.first_seen})
        return out

    @staticmethod
    def _export_record(p: Process, conns: list[dict]) -> dict:
        anc = pipeline._ancestors(p)
        chain = " > ".join([f"{a.basename}[{a.pid}]" for a in reversed(anc)] + [f"{p.basename}[{p.pid}]"])
        return {
            "id": p.id, "host": p.host.hostname, "pid": p.pid, "ppid": p.ppid, "name": p.basename, "exe": p.exe,
            "cmdline": p.cmdline, "cwd": p.cwd, "username": p.username, "sha256": p.sha256,
            "started_at": p.started_at, "ended_at": p.ended_at, "alive": p.alive, "exe_deleted": p.exe_deleted,
            "risk_score": p.risk_score, "severity": rules.severity_for(p.risk_score), "anomaly": p.anomaly,
            "lineage": chain,
            "ancestors": [{"pid": a.pid, "name": a.basename, "exe": a.exe, "cmdline": a.cmdline} for a in anc],
            "findings": p.findings, "silenced": p.muted,
            "memory": {"scanned_at": p.mem_scanned_at, "summary": p.mem_summary, "flagged_regions": p.mem_regions},
            "network": {"outbound": [c for c in conns if c["direction"] == "outbound"],
                        "listening": [c for c in conns if c["direction"] == "listen"],
                        "note": f"newest {len(conns)} connections kept per process" if len(conns) >= 25 else ""},
            "yara_hits": p.yara_hits,
            "resources": {"cpu": p.last_cpu, "rss": p.last_rss, "threads": p.last_threads},
        }

    # -- memory ---------------------------------------------------------------------------
    @action(detail=True, methods=["get"], url_path="memory")
    def memory(self, request, pk=None):
        p = self.get_object()
        scans = MemoryScanSerializer(p.memory_scans.all()[:5], many=True).data
        return Response({"summary": p.mem_summary, "regions": p.mem_regions, "scanned_at": p.mem_scanned_at,
                         "history": scans})

    def _live(self, p: Process) -> None:
        """Make sure p is still the same live local process (guards against PID reuse)."""
        if p.host.host_id != jobs.local_host_id():
            raise ValidationError("Live memory access only works for processes on the endpoint running this agent.")
        if p.ended_at is not None or p.is_agent or p.pid == os.getpid():
            raise ValidationError("Process is not inspectable (exited or the agent itself).")
        try:
            if abs(psutil.Process(p.pid).create_time() * 1000 - p.create_ms) > 1500:
                raise ValidationError("PID was reused by a different process.")
        except psutil.Error:
            raise ValidationError("Process is no longer running.")

    @action(detail=True, methods=["get"], url_path="memory/map")
    def memory_map(self, request, pk=None):
        """Address space layout. Live if possible, otherwise the last flagged regions."""
        p = self.get_object()
        try:
            self._live(p)
            regions = memlib.enumerate_regions(p.pid)
        except ValidationError as exc:
            return Response({"live": False, "reason": " ".join(map(str, exc.detail)), "total": len(p.mem_regions),
                             "regions": p.mem_regions})
        except memlib.MemoryAccessError as exc:
            return Response({"live": False, "reason": memlib.REASON_TEXT.get(exc.reason, str(exc)), "unreadable": exc.reason,
                             "total": len(p.mem_regions), "regions": p.mem_regions})
        regions.sort(key=lambda r: r.start)
        out = []
        for r in regions[:3000]:
            d = r.as_dict()
            d["flagged"] = memlib.is_flagged(r)
            out.append(d)
        return Response({"live": True, "total": len(regions), "regions": out})

    @action(detail=True, methods=["get"], url_path="memory/read")
    def memory_read(self, request, pk=None):
        """Hex dump of an executable region. Size is capped and data heaps are refused."""
        p = self.get_object()
        self._live(p)
        try:
            addr = int(request.query_params.get("address", ""), 0)
            size = min(int(request.query_params.get("size", 256)), settings.AETHER["MEMREAD_MAX"])
        except ValueError:
            raise ValidationError("address and size must be integers")
        if size <= 0 or addr < 0:
            raise ValidationError("invalid range")
        try:
            region = next((r for r in memlib.enumerate_regions(p.pid) if r.start <= addr < r.end), None)
            if region is None or not region.executable:
                raise ValidationError("address is not inside an executable region of this process")
            size = min(size, region.end - addr)
            data = memlib.read_memory(p.pid, addr, size)
        except memlib.MemoryAccessError as exc:
            raise ValidationError(str(exc))
        return Response({
            "address": f"{addr:#x}", "size": len(data), "hex": data.hex(), "entropy": round(memlib.shannon_entropy(data), 3),
            "header": memlib.detect_header(data), "region": region.as_dict(),
        })

    PROTECTED = {"system", "system idle process", "registry", "memory compression", "smss.exe", "csrss.exe",
                 "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsm.exe", "dwm.exe", "fontdrvhost.exe",
                 "init", "systemd", "kthreadd", "launchd"}

    @action(detail=True, methods=["post"], url_path="respond")
    def respond(self, request, pk=None):
        """Suspend, resume or terminate a process on this machine. Logged in ActionLog."""
        p = self.get_object()
        kind = (request.data.get("action") if isinstance(request.data, dict) else "") or ""
        if kind not in ("suspend", "resume", "terminate"):
            raise ValidationError({"action": "suspend, resume or terminate"})
        self._live(p)
        mine = {os.getpid()}
        try:
            mine |= {a.pid for a in psutil.Process().parents()}
        except psutil.Error:
            pass
        if p.pid <= 4 or p.pid in mine or p.basename.lower() in self.PROTECTED:
            raise ValidationError(f"{p.basename} is protected: stopping it would take down the system or AetherEDR itself.")
        ok, detail = False, ""
        try:
            proc = psutil.Process(p.pid)
            if abs(proc.create_time() * 1000 - p.create_ms) > 1500:
                raise ValidationError("PID was reused by a different process.")
            if kind == "suspend":
                proc.suspend()
            elif kind == "resume":
                proc.resume()
            else:
                proc.terminate()
                try:
                    proc.wait(3)
                except psutil.TimeoutExpired:
                    proc.kill()
                    detail = "did not exit on request; killed"
            ok = True
        except psutil.AccessDenied:
            detail = "Access denied. Start AetherEDR as Administrator (or root) to act on this process."
        except psutil.NoSuchProcess:
            detail = "Process had already exited."
            ok = kind == "terminate"
        entry = ActionLog.objects.create(kind=kind, process=p, pid=p.pid, name=p.basename[:255], ok=ok, detail=detail[:255])
        log.warning("response action %s on %s[%s]: %s %s", kind, p.basename, p.pid, "ok" if ok else "failed", detail)
        if not ok:
            raise APIException(detail or "Action failed.")
        return Response(ActionLogSerializer(entry).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="yara-scan")
    def yara_scan(self, request, pk=None):
        _need_yara()
        p = self.get_object()
        ser = YaraRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        if d["custom_rules"].strip():
            try:
                yara_scanner.compile_custom(d["custom_rules"])
            except yara_scanner.RuleError as exc:
                raise ValidationError({"custom_rules": str(exc)})
        elif not d["use_builtin"]:
            raise ValidationError("select built-in rules or provide custom rules")
        job = YaraJob.objects.create(process=p, requested_at=timezone.now(), **d)
        jobs.submit(job.id)
        return Response(YaraJobSerializer(job).data, status=status.HTTP_202_ACCEPTED)


class ConnectionViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ConnectionSerializer

    def get_queryset(self):
        qs = Connection.objects.select_related("process")
        q = self.request.query_params
        if q.get("process"):
            qs = qs.filter(process_id=q["process"])
        if q.get("host"):
            qs = qs.filter(process__host_id=q["host"])
        if q.get("direction"):
            qs = qs.filter(direction=q["direction"])
        if q.get("scope"):
            qs = qs.filter(scope=q["scope"])
        if q.get("country"):
            qs = qs.filter(country=q["country"].upper())
        if q.get("search"):
            s = q["search"]
            qs = qs.filter(Q(raddr__icontains=s) | Q(process__name__icontains=s) | Q(as_org__icontains=s) | Q(hostname__icontains=s))
        return qs


class SSERenderer(BaseRenderer):
    media_type = "text/event-stream"
    format = "sse"
    charset = "utf-8"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        if isinstance(data, (bytes, str)):
            return data
        return json.dumps(data)


class AlertViewSet(mixins.UpdateModelMixin, viewsets.ReadOnlyModelViewSet):
    http_method_names = ["get", "patch", "head", "options"]

    def get_serializer_class(self):
        return AlertUpdateSerializer if self.action == "partial_update" else AlertSerializer

    def get_queryset(self):
        qs = Alert.objects.select_related("host")
        q = self.request.query_params
        if _csv(self.request, "status"):
            qs = qs.filter(status__in=_csv(self.request, "status"))
        if _csv(self.request, "severity"):
            qs = qs.filter(severity__in=_csv(self.request, "severity"))
        if q.get("host"):
            qs = qs.filter(host_id=q["host"])
        if q.get("process"):
            qs = qs.filter(process_id=q["process"])
        if q.get("since_id"):
            qs = qs.filter(id__gt=_int(self.request, "since_id"))
        if q.get("min_score"):
            qs = qs.filter(score__gte=_int(self.request, "min_score"))
        if q.get("search"):
            s = q["search"]
            qs = qs.filter(Q(title__icontains=s) | Q(process_name__icontains=s) | Q(remote_ip__icontains=s) | Q(rule_id__icontains=s))
        return qs.order_by("-id")

    def partial_update(self, request, *args, **kwargs):
        obj = self.get_object()
        ser = AlertUpdateSerializer(obj, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(AlertSerializer(obj).data)

    EXPORT_COLUMNS = ["id", "first_seen", "last_seen", "host_name", "severity", "score", "status", "rule_id", "title",
                      "tactic", "technique", "process_name", "pid", "process_path", "remote_ip"]

    @action(detail=False, methods=["get"], url_path="export")
    def export(self, request):
        """Alerts as CSV or JSON with the same filters as the list. Uses `type` because DRF reserves `format`."""
        kind = request.query_params.get("type", "csv").lower()
        if kind not in ("csv", "json"):
            raise ValidationError({"type": "csv or json"})
        qs = self.get_queryset()
        hours = _int(request, "hours")
        if hours:
            qs = qs.filter(last_seen__gte=timezone.now() - timedelta(hours=max(1, min(hours, 24 * 365))))
        rows = AlertSerializer(qs[:20000], many=True).data
        stamp = timezone.now().strftime("%Y%m%d-%H%M")
        if kind == "json":
            resp = HttpResponse(json.dumps(rows, default=str, indent=1), content_type="application/json")
        else:
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(self.EXPORT_COLUMNS)
            for r in rows:
                w.writerow([_cell(r.get(c)) for c in self.EXPORT_COLUMNS])
            resp = HttpResponse("\ufeff" + buf.getvalue(), content_type="text/csv; charset=utf-8")
        resp["Content-Disposition"] = f'attachment; filename="AetherEDR-alerts-{stamp}.{kind}"'
        return resp

    @action(detail=False, methods=["get"], url_path="stream", renderer_classes=[SSERenderer, JSONRenderer])
    def stream(self, request):
        """Server-sent events: `alert` per new alert, `stats` every ~5 s, plus heartbeat comments."""
        last_id = _int(request, "last_id")
        if last_id is None:
            last_id = _int(request, "since_id")
        if last_id is None:
            last_id = int(request.headers.get("Last-Event-ID") or 0) or (
                Alert.objects.order_by("-id").values_list("id", flat=True).first() or 0)
        host = request.query_params.get("host")

        def gen():
            nonlocal last_id
            started = last_stats = last_beat = 0.0
            started = time.time()
            yield "retry: 3000\n\n"
            try:
                # ends after 4 minutes to free the worker thread (the client reconnects), or at once when stopping
                while time.time() - started < 240 and not runtime.state.get("stopping"):
                    qs = Alert.objects.select_related("host").filter(id__gt=last_id)
                    if host:
                        qs = qs.filter(host_id=host)
                    for a in qs.order_by("id")[:100]:
                        last_id = a.id
                        yield f"id: {a.id}\nevent: alert\ndata: {json.dumps(AlertSerializer(a).data)}\n\n"
                        last_beat = time.time()
                    now = time.time()
                    if now - last_stats >= 5:
                        last_stats = now
                        yield f"event: stats\ndata: {json.dumps(_stats())}\n\n"
                        last_beat = now
                    if now - last_beat >= 15:
                        last_beat = now
                        yield ": keep-alive\n\n"
                    time.sleep(1.0)
            finally:
                connection.close()

        resp = StreamingHttpResponse(gen(), content_type="text/event-stream")
        resp["Cache-Control"] = "no-cache"
        resp["X-Accel-Buffering"] = "no"
        return resp

    @action(detail=False, methods=["get"], url_path="stats")
    def stats(self, request):
        return Response(_stats())


def _cell(v) -> str:
    """CSV cell with spreadsheet formula injection neutralised (process names are attacker controlled)."""
    t = "" if v is None else str(v)
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "\r") else t


def _stats() -> dict:
    sev = dict(Alert.objects.filter(status="open").values_list("severity").annotate(n=Count("id")))
    return {
        "open": sum(sev.values()), "critical": sev.get("critical", 0), "high": sev.get("high", 0),
        "medium": sev.get("medium", 0), "low": sev.get("low", 0),
        "processes_alive": Process.objects.filter(ended_at__isnull=True).count(),
        "hosts": Host.objects.count(), "ts": time.time(),
    }


class YaraViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = YaraJobSerializer

    def get_queryset(self):
        qs = YaraJob.objects.select_related("process")
        if self.request.query_params.get("process"):
            qs = qs.filter(process_id=self.request.query_params["process"])
        return qs

    @action(detail=False, methods=["get"], url_path="rules")
    def rules_list(self, request):
        _need_yara()
        return Response(yara_scanner.builtin_rule_names())

    @action(detail=False, methods=["post"], url_path="validate")
    def validate(self, request):
        _need_yara()
        src = request.data.get("rules", "") if isinstance(request.data, dict) else ""
        try:
            compiled = yara_scanner.compile_custom(src)
        except yara_scanner.RuleError as exc:
            return Response({"valid": False, "error": str(exc)})
        return Response({"valid": True, "rules": [r.identifier for r in compiled]})


# ---------------------------------------------------------------------------------------
class OverviewView(APIView):
    def get(self, request):
        now = timezone.now()
        since = now - timedelta(hours=24)
        buckets: dict[str, dict] = {}
        for i in range(24):
            t = (now - timedelta(hours=23 - i)).replace(minute=0, second=0, microsecond=0)
            buckets[t.isoformat()] = {"t": t.isoformat(), "low": 0, "medium": 0, "high": 0, "critical": 0}
        keys = list(buckets)
        for first_seen, sev in Alert.objects.filter(first_seen__gte=since).values_list("first_seen", "severity"):
            k = first_seen.replace(minute=0, second=0, microsecond=0).isoformat()
            if k in buckets:
                buckets[k][sev] += 1
        top = Process.objects.filter(ended_at__isnull=True, risk_score__gt=0).select_related("host").order_by("-risk_score")[:8]
        return Response({
            "stats": _stats(),
            "timeline": [buckets[k] for k in keys],
            "top_processes": ProcessListSerializer(top, many=True).data,
            "agent": runtime.agent_status(),
            "tcp_countries": list(
                Connection.objects.filter(direction="outbound", scope="public", first_seen__gte=since)
                .exclude(country="").values("country").annotate(n=Count("id")).order_by("-n")[:8]),
        })


class GraphView(APIView):
    """Lineage graph. Without `focus` it returns the risky processes and their ancestors."""

    def get(self, request):
        q = request.query_params
        limit = min(_int(request, "limit", 300), 800)
        min_score = _int(request, "min_score", 1)
        qs = Process.objects.select_related("host")
        if q.get("host"):
            qs = qs.filter(host_id=q["host"])
        ids: set[int] = set()
        if q.get("focus"):
            focus = _int(request, "focus")
            if not qs.filter(pk=focus).exists():
                raise NotFound("process not found")
            ids.add(focus)
            frontier = {focus}
            for _ in range(5):                         # descendants
                nxt = set(Process.objects.filter(parent_id__in=frontier).values_list("id", flat=True)[:limit]) - ids
                if not nxt or len(ids) + len(nxt) > limit:
                    ids |= set(list(nxt)[: max(0, limit - len(ids))])
                    break
                ids |= nxt
                frontier = nxt
        else:
            seeds = qs.filter(risk_score__gte=min_score)
            if q.get("alive", "1") in ("1", "true"):
                seeds = seeds.filter(ended_at__isnull=True)
            ids = set(seeds.order_by("-risk_score").values_list("id", flat=True)[:limit])
            if q.get("all") in ("1", "true"):
                ids |= set(qs.filter(ended_at__isnull=True).values_list("id", flat=True)[:limit])
        # ancestors, level by level (bounded)
        frontier = set(ids)
        for _ in range(12):
            parents = set(Process.objects.filter(id__in=frontier, parent__isnull=False).values_list("parent_id", flat=True)) - ids
            if not parents:
                break
            ids |= parents
            frontier = parents
        rows = {p.id: p for p in Process.objects.filter(id__in=ids).select_related("host")}
        nodes = []
        for p in rows.values():
            m = p.mem_summary or {}
            nodes.append({
                "id": p.id, "parent": p.parent_id if p.parent_id in rows else None, "pid": p.pid, "ppid": p.ppid,
                "name": p.basename, "exe": p.exe, "cmdline": p.cmdline[:200], "user": p.username, "risk": p.risk_score,
                "alive": p.ended_at is None, "rwx": m.get("rwx_regions", 0), "unbacked": m.get("unbacked_exec", 0),
                "net_out": p.net_out, "top": p.findings[0]["title"] if p.findings else None,
                "rules": [f["rule_id"] for f in p.findings][:10],
                "host": p.host.hostname, "started_at": p.started_at,
            })
        return Response({"nodes": nodes, "count": len(nodes), "focus": _int(request, "focus")})


class ReportView(APIView):
    def get(self, request):
        from .reporting import builder  # docx and reportlab are slow to import, so load them here

        # not called "format" because DRF uses ?format= to pick a renderer
        fmt = request.query_params.get("type", "pdf").lower()
        if fmt not in ("pdf", "docx"):
            raise ValidationError({"type": "pdf or docx"})
        hours = max(1, min(_int(request, "hours", 24), 24 * 30))
        data = builder.build_report_data(hours=hours, host_id=_int(request, "host"))
        if fmt == "docx":
            body, ctype = builder.render_docx(data), "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        else:
            body, ctype = builder.render_pdf(data), "application/pdf"
        stamp = timezone.now().strftime("%Y%m%d-%H%M")
        resp = HttpResponse(body, content_type=ctype)
        resp["Content-Disposition"] = f'attachment; filename="AetherEDR-Security-Report-{stamp}.{fmt}"'
        return resp


class SuppressionViewSet(mixins.CreateModelMixin, mixins.UpdateModelMixin, mixins.DestroyModelMixin,
                         mixins.ListModelMixin, viewsets.GenericViewSet):
    """Exceptions. Creating one silences matching findings right away, deleting one brings them back."""

    serializer_class = SuppressionSerializer
    queryset = Suppression.objects.all()
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    pagination_class = None

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["silenced"] = dict(Alert.objects.filter(suppression__isnull=False).values_list("suppression")
                               .annotate(n=Count("id")))
        return ctx

    def perform_create(self, serializer):
        obj = serializer.save()
        pipeline.reevaluate_all()
        return obj

    def partial_update(self, request, *args, **kwargs):
        resp = super().partial_update(request, *args, **kwargs)
        obj = self.get_object()
        if not obj.enabled:
            pipeline.reopen_silenced(obj.id)
        pipeline.reevaluate_all()
        return resp

    def perform_destroy(self, instance):
        sid = instance.id
        instance.delete()
        pipeline.reopen_silenced(sid)
        pipeline.reevaluate_all()


class ActionLogViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    serializer_class = ActionLogSerializer
    queryset = ActionLog.objects.all()


class RulesView(APIView):
    """Rule catalogue with alert counts and whether a global exception mutes the rule."""

    def get(self, request):
        counts = {r["rule_id"]: r for r in Alert.objects.values("rule_id").annotate(
            total=Count("id"), open=Count("id", filter=Q(status="open")))}
        global_mutes = [s.rule_id for s in Suppression.objects.filter(enabled=True, exe="", name="").exclude(rule_id="")]

        def tally(rid: str) -> tuple[int, int]:
            if rid == "YARA.*":
                rows = [v for k, v in counts.items() if k.startswith("YARA.")]
            else:
                rows = [counts[rid]] if rid in counts else []
            return sum(r["total"] for r in rows), sum(r["open"] for r in rows)

        def muted(rid: str) -> bool:
            return any(m == rid or (m.endswith("*") and rid.startswith(m[:-1])) for m in global_mutes)

        out = []
        for r in rule_catalog.catalog():
            total, open_ = tally(r["id"])
            out.append(dict(r, alerts_total=total, alerts_open=open_, muted=muted(r["id"])))
        return Response({"rules": out, "alert_threshold": settings.AETHER["ALERT_THRESHOLD"],
                         "min_alert_weight": rules.MIN_ALERT_WEIGHT})


class ShutdownView(APIView):
    """Stop AetherEDR: the collector, the console and the server.

    POST {"confirm": true}. Needs the operator key (the agent key cannot do this). Only works when
    run.py started the program, because that is what provides the way to stop it.
    """

    def post(self, request):
        body = request.data if isinstance(request.data, dict) else {}
        if body.get("confirm") is not True:
            raise ValidationError({"confirm": "Send confirm: true to stop AetherEDR."})
        if not runtime.request_shutdown():
            return Response({"detail": "This copy was not started by run.py, so it cannot stop itself. Stop it from the terminal."},
                            status=status.HTTP_409_CONFLICT)
        log.warning("Stop requested through the API from %s", request.META.get("REMOTE_ADDR", "unknown address"))
        return Response({"stopping": True}, status=status.HTTP_202_ACCEPTED)


class ClearHistoryView(APIView):
    """Delete ended processes and stale alerts, everything or only what is older than N days.

    POST {"older_than_days": 7 | null, "alerts": true, "host": 1, "dry_run": true}
    A dry run only counts. A real run also needs "confirm": true so a stray request cannot wipe the history.
    """

    def post(self, request):
        body = request.data if isinstance(request.data, dict) else {}

        def flag(name: str, default: bool) -> bool:
            v = body.get(name, default)
            if not isinstance(v, bool):
                raise ValidationError({name: "Must be true or false."})
            return v

        days = body.get("older_than_days")
        if days in ("", None):
            days = None
        else:
            if isinstance(days, bool) or not isinstance(days, (int, float, str)):
                raise ValidationError({"older_than_days": "Must be a whole number of days or null."})
            try:
                days = int(days)
            except ValueError:
                raise ValidationError({"older_than_days": "Must be a whole number of days or null."}) from None
            if not 0 <= days <= 3650:
                raise ValidationError({"older_than_days": "Must be between 0 and 3650."})
        host_id = body.get("host")
        if host_id in ("", None):
            host_id = None
        else:
            try:
                host_id = int(host_id)
            except (TypeError, ValueError):
                raise ValidationError({"host": "Must be a host id."}) from None
        alerts = flag("alerts", True)
        dry = flag("dry_run", False)
        if not dry and body.get("confirm") is not True:
            raise ValidationError({"confirm": "Send confirm: true to delete."})

        counts = maintenance.clear_history(days, alerts=alerts, host_id=host_id, dry_run=dry)
        compacted = False
        if not dry and counts["processes"] + counts["alerts"] >= 500:
            compacted = maintenance.compact()
        return Response({"dry_run": dry, "older_than_days": days or None, "counts": counts, "compacted": compacted})


class SystemView(APIView):
    """Data for the System sheet: versions, paths, counters, collector health."""

    def get(self, request):
        from aether import __version__

        db_file = settings.DATABASES["default"]["NAME"]
        size = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                size += os.path.getsize(f"{db_file}{suffix}")
            except OSError:
                pass
        cfg = settings.AETHER
        alive = Process.objects.filter(ended_at__isnull=True)
        blind = dict(alive.exclude(mem_unreadable="").values_list("mem_unreadable").annotate(n=Count("id")))
        readable = alive.filter(mem_unreadable="", mem_scanned_at__isnull=False).count()
        coverage = {"readable": readable, "protected": blind.get("protected", 0), "denied": blind.get("denied", 0),
                    "other": blind.get("other", 0)}
        coverage["pending"] = max(0, alive.count() - readable - coverage["protected"] - coverage["denied"] - coverage["other"])
        return Response({
            "version": __version__, "python": sys.version.split()[0], "platform": platform.platform(),
            "memory_coverage": coverage,
            "data_dir": str(settings.DATA_DIR), "db_bytes": size, "api_key": settings.API_KEY,
            "ingest_key": settings.INGEST_KEY,
            "agent": runtime.agent_status(),
            "counts": {"processes": Process.objects.count(), "alive": Process.objects.filter(ended_at__isnull=True).count(),
                       "ended": Process.objects.filter(ended_at__isnull=False).count(),
                       "alerts": Alert.objects.count(), "connections": Connection.objects.count(),
                       "exceptions": Suppression.objects.filter(enabled=True).count()},
            "settings": {"alert_threshold": cfg["ALERT_THRESHOLD"], "retention_days": cfg["RETENTION_DAYS"],
                         "interval": cfg["COLLECT_INTERVAL"], "reverse_dns": cfg["REVERSE_DNS"],
                         "jit_allow": cfg["JIT_ALLOW"], "shared_region_min": cfg["SHARED_REGION_MIN"], "watch_countries": cfg["WATCH_COUNTRIES"]},
        })

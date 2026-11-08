"""Ingest: collector events become DB rows, then detection runs, then alerts."""
from __future__ import annotations

import logging
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone as dt_tz

from django.conf import settings
from django.db import transaction
from django.db.models import Count
from django.utils import timezone

from edr.models import Alert, Connection, Host, MemoryScan, Process, Suppression, YaraJob

from . import netintel, rules
from .anomaly import engine as anomaly_engine

log = logging.getLogger("aether.pipeline")

MAX_EVENTS = 5000
MAX_CONNS_PER_PROC = 200
KEEP_MEMORY_SCANS = 5
ORDER = {"process_start": 0, "process_exit": 1, "process_stats": 2, "net_connect": 3, "memory_scan": 4,
         "memory_unreadable": 4}
ANCESTOR_SELECT = ["parent", "parent__parent", "parent__parent__parent", "parent__parent__parent__parent"]


def _dt(ts) -> datetime:
    try:
        return datetime.fromtimestamp(float(ts), tz=dt_tz.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return timezone.now()


def _ms(ct) -> int:
    return int(round(float(ct) * 1000))


def _upsert_host(info: dict) -> Host:
    now = timezone.now()
    defaults = {
        "hostname": str(info.get("hostname", ""))[:255],
        "os_name": str(info.get("os_name", ""))[:32],
        "os_version": str(info.get("os_version", ""))[:255],
        "arch": str(info.get("arch", ""))[:32],
        "ip_addresses": [str(i)[:64] for i in (info.get("ip_addresses") or [])][:16],
        "agent_version": str(info.get("agent_version", ""))[:32],
        "is_admin": bool(info.get("is_admin")),
        "capabilities": info.get("capabilities") if isinstance(info.get("capabilities"), dict) else {},
        "last_seen": now,
    }
    host_id = str(info["host_id"])[:32]
    host, created = Host.objects.get_or_create(host_id=host_id, defaults=defaults)
    if not created:
        Host.objects.filter(pk=host.pk).update(**defaults)
        for k, v in defaults.items():
            setattr(host, k, v)
    return host


def _valid(ev) -> bool:
    if not isinstance(ev, dict) or ev.get("type") not in ORDER:
        return False
    try:
        int(ev["pid"])
        float(ev["create_time"])
        float(ev.get("ts", 0))
    except (KeyError, TypeError, ValueError):
        return False
    return True


_PREV_TTL = 60.0
_PREV_CACHE: dict[int, tuple[float, dict]] = {}


def region_prevalence(host: Host) -> dict:
    """Region signature -> (process count, distinct names) over the live, scanned processes of one host.
    Cached for a minute since it is read on every ingest."""
    hit = _PREV_CACHE.get(host.id)
    if hit and time.monotonic() - hit[0] < _PREV_TTL:
        return hit[1]
    procs: dict[tuple, set] = defaultdict(set)
    names: dict[tuple, set] = defaultdict(set)
    rows = Process.objects.filter(host=host, ended_at__isnull=True, mem_scanned_at__isnull=False, is_agent=False)
    for pid, name, regs in rows.values_list("id", "name", "mem_regions").iterator():
        for r in regs or []:
            if r.get("executable") and (r.get("rwx") or r.get("unbacked")):
                sig = rules.region_sig(r)
                procs[sig].add(pid)
                names[sig].add((name or "").lower())
    out = {sig: (len(ids), len(names[sig])) for sig, ids in procs.items() if len(ids) > 1}
    _PREV_CACHE[host.id] = (time.monotonic(), out)
    return out


def _end_vanished(host: Host, live: list, since) -> int:
    """The collector just (re)started and listed what is alive. Close the processes the DB still shows as
    running that are missing from that list. Without this, closing the app or rebooting leaves
    processes 'running' forever, with their old findings."""
    alive_keys = set()
    for item in live:
        try:
            alive_keys.add((int(item[0]), _ms(float(item[1]))))
        except (TypeError, ValueError, IndexError):
            return 0  # malformed list: change nothing
    gone = [pk for pk, pid, cms in Process.objects.filter(host=host, ended_at__isnull=True).values_list("id", "pid", "create_ms")
            if (pid, cms) not in alive_keys]
    when = since or timezone.now()
    for i in range(0, len(gone), 500):
        Process.objects.filter(pk__in=gone[i:i + 500], ended_at__isnull=True).update(ended_at=when)
    return len(gone)


# -------------------------------------------------------------------------------------
def ingest(batch: dict) -> dict:
    """Save a collector batch and run detection. Returns counters."""
    cfg = settings.AETHER
    counters: Counter = Counter()
    events = [e for e in (batch.get("events") or [])[:MAX_EVENTS] if _valid(e)]
    counters["dropped"] = len(batch.get("events") or []) - len(events)
    events.sort(key=lambda e: ORDER[e["type"]])
    to_scan: list[int] = []

    live = batch.get("live")
    with transaction.atomic():
        prev_seen = Host.objects.filter(host_id=str(batch["host"]["host_id"])[:32]).values_list("last_seen", flat=True).first()
        host = _upsert_host(batch["host"])
        if live:
            counters["reconciled"] = _end_vanished(host, live, prev_seen)
        touched: dict[int, dict] = {}          # process id -> flags
        cache: dict[tuple[int, int], Process] = {}

        # -- 1. process creation (bulk) --------------------------------------------------
        starts = [e for e in events if e["type"] == "process_start"]
        if starts:
            existing = {
                (p.pid, p.create_ms): p
                for p in Process.objects.filter(host=host, pid__in={int(e["pid"]) for e in starts})
            }
            new_rows = []
            for e in starts:
                key = (int(e["pid"]), _ms(e["create_time"]))
                if key in existing:
                    continue
                new_rows.append(Process(
                    host=host, pid=key[0], create_ms=key[1], ppid=int(e.get("ppid") or 0),
                    name=str(e.get("name", ""))[:255], exe=str(e.get("exe", ""))[:1024],
                    cmdline=str(e.get("cmdline", ""))[:4096], cwd=str(e.get("cwd", ""))[:1024],
                    username=str(e.get("username", ""))[:255], sha256=str(e.get("sha256", ""))[:64],
                    exe_deleted=bool(e.get("exe_deleted")), is_agent=bool(e.get("agent")),
                    started_at=_dt(e["create_time"]),
                ))
                existing[key] = new_rows[-1]
            if new_rows:
                Process.objects.bulk_create(new_rows, ignore_conflicts=True)
                counters["processes_new"] = len(new_rows)
                fresh = Process.objects.filter(
                    host=host, pid__in={p.pid for p in new_rows}).filter(
                    create_ms__in={p.create_ms for p in new_rows})
                new_keys = {(p.pid, p.create_ms) for p in new_rows}
                new_by_key = {(p.pid, p.create_ms): p for p in fresh if (p.pid, p.create_ms) in new_keys}
                _link_parents(host, list(new_by_key.values()))
                for k, p in new_by_key.items():
                    cache[k] = p
                    touched[p.id] = {"new": True}

        def resolve(e) -> Process | None:
            key = (int(e["pid"]), _ms(e["create_time"]))
            if key in cache:
                return cache[key]
            p = Process.objects.filter(host=host, pid=key[0], create_ms=key[1]).first()
            if p:
                cache[key] = p
            return p

        # -- 2. exits, stats, network, memory ----------------------------------------------
        net_procs: set[int] = set()
        for e in events:
            t = e["type"]
            if t == "process_start":
                continue
            p = resolve(e)
            if p is None:
                counters["orphan_events"] += 1
                continue
            if t == "process_exit":
                if p.ended_at is None:
                    Process.objects.filter(pk=p.pk, ended_at__isnull=True).update(ended_at=_dt(e.get("ts")))
                    p.ended_at = _dt(e.get("ts"))
            elif t == "process_stats":
                Process.objects.filter(pk=p.pk).update(
                    last_cpu=float(e.get("cpu") or 0), last_rss=int(e.get("rss") or 0),
                    last_threads=int(e.get("threads") or 0))
                p.last_cpu, p.last_rss, p.last_threads = float(e.get("cpu") or 0), int(e.get("rss") or 0), int(e.get("threads") or 0)
                touched.setdefault(p.id, {})
            elif t == "net_connect":
                if _store_connection(p, e, cfg):
                    net_procs.add(p.id)
                    touched.setdefault(p.id, {})
                    counters["connections"] += 1
            elif t == "memory_unreadable":
                reason = e.get("reason") if e.get("reason") in ("protected", "denied") else "other"
                Process.objects.filter(pk=p.pk).update(mem_unreadable=reason)
                p.mem_unreadable = reason
                counters["memory_unreadable"] += 1
            elif t == "memory_scan":
                _store_memory(p, e)
                touched.setdefault(p.id, {})["mem"] = True
                counters["memory_scans"] += 1

        if net_procs:
            _refresh_net_counters(net_procs)

        # -- 3. detection ------------------------------------------------------------------
        if touched:
            res = evaluate_processes(host, list(touched))
            counters["alerts_new"] += res["alerts_new"]
            counters["alerts_updated"] += res["alerts_updated"]
            to_scan = res["auto_yara"]

    for pid in to_scan:                                 # outside the transaction
        from .jobs import submit_auto  # noqa: PLC0415

        submit_auto(pid)
    return dict(counters)


def _link_parents(host: Host, procs: list[Process]) -> None:
    ppids = {p.ppid for p in procs if p.ppid}
    if not ppids:
        return
    candidates = defaultdict(list)
    for q in Process.objects.filter(host=host, pid__in=ppids).only("id", "pid", "create_ms"):
        candidates[q.pid].append(q)
    changed = []
    for p in procs:
        best = None
        for q in candidates.get(p.ppid, []):
            if q.create_ms <= p.create_ms and q.id != p.id and (best is None or q.create_ms > best.create_ms):
                best = q
        if best and p.parent_id != best.id:
            p.parent_id = best.id
            changed.append(p)
    if changed:
        Process.objects.bulk_update(changed, ["parent"])


def _store_connection(p: Process, e: dict, cfg: dict) -> bool:
    raddr = str(e.get("raddr", ""))[:64]
    info = netintel.enrich(raddr, cfg["REVERSE_DNS"]) if raddr else {}
    Connection.objects.create(
        process=p, direction=str(e.get("direction", ""))[:8], proto=str(e.get("proto", ""))[:4],
        laddr=str(e.get("laddr", ""))[:64], lport=int(e.get("lport") or 0), raddr=raddr,
        rport=int(e.get("rport") or 0), status=str(e.get("status", ""))[:16], first_seen=_dt(e.get("ts")),
        scope=info.get("scope", ""), country=info.get("country", ""), asn=info.get("asn"),
        as_org=(info.get("as_org") or "")[:128], hostname=(info.get("hostname") or "")[:255],
        entropy=info.get("entropy"),
    )
    return True


def _refresh_net_counters(proc_ids: set[int]) -> None:
    out = dict(Connection.objects.filter(process_id__in=proc_ids, direction="outbound")
               .values_list("process_id").annotate(n=Count("id")))
    lst = dict(Connection.objects.filter(process_id__in=proc_ids, direction="listen")
               .values_list("process_id").annotate(n=Count("id")))
    rem = dict(Connection.objects.filter(process_id__in=proc_ids, direction="outbound")
               .values_list("process_id").annotate(n=Count("raddr", distinct=True)))
    for pid in proc_ids:
        Process.objects.filter(pk=pid).update(net_out=out.get(pid, 0), net_listen=lst.get(pid, 0),
                                              net_remotes=rem.get(pid, 0))


def _store_memory(p: Process, e: dict) -> None:
    summary = e.get("summary") if isinstance(e.get("summary"), dict) else {}
    regions = [r for r in (e.get("regions") or []) if isinstance(r, dict)][:16]
    ts = _dt(e.get("ts"))
    Process.objects.filter(pk=p.pk).update(mem_summary=summary, mem_regions=regions, mem_scanned_at=ts, mem_unreadable="")
    p.mem_summary, p.mem_regions, p.mem_scanned_at, p.mem_unreadable = summary, regions, ts, ""
    if regions:
        MemoryScan.objects.create(process=p, ts=ts, summary=summary, regions=regions)
        old = list(MemoryScan.objects.filter(process=p).order_by("-ts").values_list("id", flat=True)[KEEP_MEMORY_SCANS:])
        if old:
            MemoryScan.objects.filter(id__in=old).delete()


# -------------------------------------------------------------------------------------
def _pdict(p: Process) -> dict:
    return {
        "pid": p.pid, "name": p.name, "exe": p.exe, "cmdline": p.cmdline, "exe_deleted": p.exe_deleted,
        "is_agent": p.is_agent, "yara_hits": p.yara_hits,
    }


def evaluate_processes(host: Host, ids: list[int]) -> dict:
    """Recompute findings and risk for these process ids and sync the alerts."""
    cfg = settings.AETHER
    procs = list(Process.objects.filter(id__in=ids).select_related(*ANCESTOR_SELECT))
    if not procs:
        return {"alerts_new": 0, "alerts_updated": 0, "auto_yara": []}

    conns_by: dict[int, list[dict]] = defaultdict(list)
    for c in Connection.objects.filter(process_id__in=ids).order_by("-first_seen")[: len(ids) * MAX_CONNS_PER_PROC]:
        if len(conns_by[c.process_id]) < MAX_CONNS_PER_PROC:
            conns_by[c.process_id].append({
                "direction": c.direction, "proto": c.proto, "laddr": c.laddr, "lport": c.lport, "raddr": c.raddr,
                "rport": c.rport, "scope": c.scope, "country": c.country, "asn": c.asn, "as_org": c.as_org,
                "hostname": c.hostname, "entropy": c.entropy, "ts": c.first_seen.timestamp(),
            })

    exes = {p.exe for p in procs if p.exe}
    freq = dict(Process.objects.filter(host=host, exe__in=exes).values_list("exe").annotate(n=Count("id"))) if exes else {}

    # anomaly scoring (only for processes with a completed memory scan)
    anomaly: dict[int, float | None] = {}
    if anomaly_engine.ready:
        scorable = [p for p in procs if p.mem_scanned_at and not p.is_agent]
        feats = []
        for p in scorable:
            anc = _ancestors(p)
            feats.append({**_pdict(p), "last_cpu": p.last_cpu, "last_rss": p.last_rss, "last_threads": p.last_threads,
                          "mem_summary": p.mem_summary, "net_out": p.net_out, "net_remotes": p.net_remotes,
                          "net_listen": p.net_listen, "depth": len(anc), "exe_freq": freq.get(p.exe, 1)})
        for p, s in zip(scorable, anomaly_engine.score_many(feats)):
            anomaly[p.id] = s

    alerts_new = alerts_updated = 0
    auto_yara: list[int] = []
    now = timezone.now()
    watch_c, watch_a = tuple(cfg["WATCH_COUNTRIES"]), tuple(str(a) for a in cfg["WATCH_ASNS"])
    updates: list[Process] = []
    sups = list(Suppression.objects.filter(enabled=True))
    shared_min = int(cfg.get("SHARED_REGION_MIN", 0) or 0)
    prevalence = region_prevalence(host) if shared_min else {}

    for p in procs:
        anc = _ancestors(p)
        ctx = rules.Ctx(
            proc=_pdict(p), ancestors=[_pdict(a) for a in anc], os_name=host.os_name,
            mem={"summary": p.mem_summary, "regions": p.mem_regions} if p.mem_scanned_at else None,
            conns=conns_by.get(p.id, []), anomaly=anomaly.get(p.id),
            watch_countries=watch_c, watch_asns=watch_a, jit_extra=tuple(cfg["JIT_ALLOW"]),
            region_prev=prevalence, shared_min=shared_min,
        )
        findings = [] if p.is_agent else rules.evaluate(ctx)
        findings, muted = split_muted(findings, p, sups)
        score = rules.risk_score(findings)
        p.findings = [f.as_dict() for f in findings]
        p.muted = [dict(f.as_dict(), suppression=sid) for f, sid in muted]
        for f, sid in muted:
            silence_alert(host, p, f, sid)
        p.risk_score = score
        p.anomaly = anomaly.get(p.id)
        updates.append(p)

        if score >= cfg["ALERT_THRESHOLD"]:
            for f in findings:
                if f.weight < rules.MIN_ALERT_WEIGHT:
                    continue
                created = _upsert_alert(host, p, f, score, now)
                alerts_new += created
                alerts_updated += (not created)
            if (any(f.memory and f.weight >= 35 for f in findings) and p.ended_at is None and not p.yara_hits
                    and not YaraJob.objects.filter(process=p).exists()):
                auto_yara.append(p.id)

    Process.objects.bulk_update(updates, ["findings", "muted", "risk_score", "anomaly"])
    return {"alerts_new": alerts_new, "alerts_updated": alerts_updated, "auto_yara": auto_yara}


def split_muted(findings: list, p: Process, sups: list[Suppression]) -> tuple[list, list]:
    """Returns (active findings, [(finding, suppression id)]). An exception beats any rule weight."""
    if not sups or not findings:
        return findings, []
    exe, name = p.exe or "", p.basename or ""
    active, muted = [], []
    for f in findings:
        hit = next((s for s in sups if s.matches(f.rule_id, exe, name)), None)
        (muted.append((f, hit.id)) if hit else active.append(f))
    return active, muted


def silence_alert(host: Host, p: Process, f: rules.Finding, suppression_id: int) -> None:
    key = f"{host.host_id}:{p.pid}:{p.create_ms}:{f.rule_id}{f.suffix}"
    Alert.objects.filter(dedupe_key=key, status__in=("open", "ack")).update(status="closed", suppression=suppression_id)


def reevaluate_all(only_with_findings: bool = True) -> int:
    """Re-run detection on stored processes, e.g. after an exception changes."""
    _PREV_CACHE.clear()
    qs = Process.objects.all()
    if only_with_findings:
        qs = qs.exclude(findings=[], muted=[])
    by_host: dict[int, list[int]] = defaultdict(list)
    for pid, hid in qs.values_list("id", "host_id"):
        by_host[hid].append(pid)
    n = 0
    for hid, ids in by_host.items():
        host = Host.objects.get(pk=hid)
        for i in range(0, len(ids), 200):
            evaluate_processes(host, ids[i:i + 200])
        n += len(ids)
    return n


def reopen_silenced(suppression_id: int) -> int:
    """Exception removed or disabled: reopen the alerts it closed."""
    return Alert.objects.filter(suppression=suppression_id, status="closed").update(status="open", suppression=None)


def _ancestors(p: Process) -> list[Process]:
    """Walk the parents select_related() already loaded, no extra queries."""
    out: list[Process] = []
    cur = p
    for _ in range(4):
        cache = cur._state.fields_cache
        if "parent" not in cache:
            break
        cur = cache["parent"]
        if cur is None or cur.id == p.id:
            break
        out.append(cur)
    return out


def _upsert_alert(host: Host, p: Process, f: rules.Finding, score: int, now) -> bool:
    key = f"{host.host_id}:{p.pid}:{p.create_ms}:{f.rule_id}{f.suffix}"
    severity = rules.severity_for(max(score, f.weight))
    fields = {
        "title": f.title[:255], "description": f.description, "score": max(score, f.weight), "weight": f.weight,
        "severity": severity,
        "tactic": f.tactic, "technique": f.technique, "evidence": f.evidence, "last_seen": now,
        "remote_ip": f.remote_ip, "memory_flag": f.memory,
    }
    alert, created = Alert.objects.get_or_create(
        dedupe_key=key,
        defaults={**fields, "host": host, "process": p, "rule_id": f.rule_id[:64], "first_seen": now,
                  "process_name": p.basename[:255], "process_path": p.exe[:1024], "pid": p.pid},
    )
    if not created and alert.status in ("open", "ack"):
        Alert.objects.filter(pk=alert.pk).update(**fields)
    return created


def raise_yara_alerts(job: YaraJob, matches: list[dict]) -> int:
    """Store YARA matches on the process and raise alerts. Called by the scan jobs."""
    p = job.process
    host = p.host
    hits = list(p.yara_hits)
    known = {(h["rule"], h.get("source")) for h in hits}
    now = timezone.now()
    for m in matches:
        if (m["rule"], m["source"]) in known:
            continue
        meta = m.get("meta") or {}
        hits.append({"rule": m["rule"], "severity": meta.get("severity", "medium"), "source": m["source"],
                     "technique": meta.get("technique", ""), "description": meta.get("description", ""), "ts": now.isoformat()})
    Process.objects.filter(pk=p.pk).update(yara_hits=hits)
    p.yara_hits = hits
    res = evaluate_processes(host, [p.id])
    return res["alerts_new"]

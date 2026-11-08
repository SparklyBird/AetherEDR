"""Detection rules. Each one is a function from a Ctx to a list of Findings, no DB access.

Process risk = noisy-OR of finding weights:  100 * (1 - prod(1 - w/100)).
Weights are starting points. Tune them for your machines.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from . import netintel

# ---- name sets ------------------------------------------------------------------------
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe",
          "visio.exe", "mspub.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe", "soffice.bin",
          "soffice", "libreoffice", "evince", "okular"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe",
            "chrome", "chromium", "firefox", "firefox-bin", "msedge", "brave", "opera", "epiphany"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
          "bash", "sh", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "nc", "ncat", "netcat", "socat"}
LOLBINS = {"rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
           "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "wmic.exe", "forfiles.exe",
           "msiexec.exe", "schtasks.exe"}
WEB_SERVERS = {"w3wp.exe", "httpd", "apache2", "nginx", "php-fpm", "php-cgi", "php", "tomcat", "lighttpd",
               "httpd.exe", "nginx.exe", "tomcat9.exe", "gunicorn", "uwsgi"}
INTERPRETERS = {"python", "python3", "perl", "ruby", "node", "php", "lua", "powershell.exe", "pwsh.exe"}
# JIT / dynamic code hosts: RWX or unbacked executable memory is normal for these
JIT_PROCS = {"java", "javaw", "java.exe", "javaw.exe", "node", "node.exe", "dotnet", "dotnet.exe",
             "chrome", "chrome.exe", "msedge", "msedge.exe", "firefox", "firefox.exe", "firefox-bin",
             "brave", "brave.exe", "opera", "opera.exe", "code", "code.exe", "electron", "slack",
             "slack.exe", "teams.exe", "discord", "discord.exe", "spotify", "spotify.exe", "pwsh",
             "pwsh.exe", "powershell.exe", "mono", "mono-sgen", "qemu-system-x86_64", "gnome-shell",
             "plugin-container", "webkitwebprocess", "wpewebprocess", "msedgewebview2.exe", "rust-analyzer",
             "chromium", "chromium-browser", "steam", "steamwebhelper", "bun", "deno", "steam.exe", "steamwebhelper.exe"}
# also matched on the exe file name, since apps rename their processes (prctl)
JIT_EXE_HINTS = ("chrome", "chromium", "firefox", "msedge", "electron", "node", "java", "dotnet", "bun", "deno")
SYSTEM_BINARIES_WIN = {  # name -> allowed lowercase path prefixes
    "svchost.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "lsass.exe": ("c:\\windows\\system32\\",),
    "csrss.exe": ("c:\\windows\\system32\\",),
    "smss.exe": ("c:\\windows\\system32\\",),
    "services.exe": ("c:\\windows\\system32\\",),
    "winlogon.exe": ("c:\\windows\\system32\\",),
    "wininit.exe": ("c:\\windows\\system32\\",),
    "explorer.exe": ("c:\\windows\\explorer.exe",),
    "taskhostw.exe": ("c:\\windows\\system32\\",),
}
EXPECTED_PARENT_WIN = {"svchost.exe": {"services.exe", "mpssvc.exe"}, "lsass.exe": {"wininit.exe"},
                       "services.exe": {"wininit.exe"}, "taskhostw.exe": {"svchost.exe"}}
SUSP_DIRS_POSIX = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/run/shm/")
SUSP_DIRS_WIN = ("\\appdata\\local\\temp\\", "\\users\\public\\", "\\windows\\temp\\", "\\programdata\\temp\\",
                 "\\$recycle.bin\\", "\\perflogs\\")
MIN_ALERT_WEIGHT = 20
_KTHREAD = re.compile(r"^(?:\[.*\]|kworker/|ksoftirqd/|migration/|rcu_\w+|kthreadd|cpuhp/|watchdog/)")


@dataclass
class Finding:
    rule_id: str
    title: str
    weight: int
    tactic: str = ""
    technique: str = ""
    description: str = ""
    evidence: dict = field(default_factory=dict)
    suffix: str = ""          # distinguishes multiple instances (e.g. per destination)
    remote_ip: str = ""
    memory: bool = False

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "title": self.title, "weight": self.weight, "tactic": self.tactic,
            "technique": self.technique, "description": self.description, "evidence": self.evidence,
            "suffix": self.suffix, "remote_ip": self.remote_ip, "memory": self.memory,
        }


@dataclass
class Ctx:
    proc: dict                      # name, exe, cmdline, pid, exe_deleted, is_agent
    ancestors: list[dict]           # [parent, grandparent, ...]
    os_name: str = "Linux"
    mem: dict | None = None         # {"summary": {...}, "regions": [...]}
    conns: list[dict] = field(default_factory=list)  # dicts incl. ts (float epoch)
    anomaly: float | None = None
    watch_countries: tuple = ()
    watch_asns: tuple = ()
    jit_extra: tuple = ()
    region_prev: dict = field(default_factory=dict)  # region signature -> (processes, distinct names) on this host
    shared_min: int = 0                              # processes needed to call a region "shared" (0 = off)


def risk_score(findings: list[Finding]) -> int:
    p = 1.0
    for f in findings:
        p *= 1 - max(0, min(f.weight, 99)) / 100
    return int(round(100 * (1 - p)))


def severity_for(score: int) -> str:
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"


def _base(d: dict) -> str:
    n = (d.get("name") or "").strip()
    if not n:
        n = (d.get("exe") or "").replace("\\", "/").rsplit("/", 1)[-1]
    return n.lower()


def _exe_lower(d: dict) -> str:
    return (d.get("exe") or "").lower()


def _is_windows(ctx: Ctx) -> bool:
    return ctx.os_name.lower().startswith("win")


SWARM_PEERS = 8        # distinct public peers ...
SWARM_PORTS = 5        # ... on this many distinct ports look like a peer-to-peer swarm
SHARED_MIN_NAMES = 3   # a "shared" region must appear in at least this many differently named programs


def region_sig(r: dict) -> tuple:
    """Signature of a flagged region that ignores the address. The same blob allocated by one component
    ends up at a different address in each process."""
    e = r.get("entropy")
    return (r.get("kind"), r.get("protect"), int(r.get("size") or 0), None if e is None else round(float(e), 1))


# ---- lineage ----------------------------------------------------------------------------
def rule_lineage(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    name = _base(ctx.proc)
    parent = ctx.ancestors[0] if ctx.ancestors else None
    pname = _base(parent) if parent else ""
    chain = " > ".join(_base(a) for a in reversed(ctx.ancestors)) + (" > " if ctx.ancestors else "") + name
    ev = {"parent": pname, "chain": chain}

    if pname in OFFICE and (name in SHELLS or name in LOLBINS or name in INTERPRETERS):
        out.append(Finding("LIN-001", "Office/document app spawned a shell or script host", 85, "Execution",
                           "T1204.002", f"{pname} launched {name}. Document-borne payloads typically execute this way.", ev))
    elif pname in BROWSERS and name in SHELLS:
        out.append(Finding("LIN-002", "Browser spawned a shell", 70, "Execution", "T1189",
                           f"{pname} launched {name}; browsers do not normally start command interpreters.", ev))
    elif pname in WEB_SERVERS and (name in SHELLS or name in LOLBINS) and name not in ("php",):
        out.append(Finding("LIN-003", "Web server spawned a shell (possible web shell)", 80, "Persistence",
                           "T1505.003", f"{pname} launched {name}.", ev))

    # one hop up, for office > cmd > powershell chains
    if len(ctx.ancestors) >= 2 and not out:
        gp = _base(ctx.ancestors[1])
        if gp in OFFICE and pname in SHELLS and (name in SHELLS or name in LOLBINS):
            out.append(Finding("LIN-001", "Office/document app started a multi-stage shell chain", 85, "Execution",
                               "T1204.002", f"Chain: {chain}", ev))

    if _is_windows(ctx):
        exe = _exe_lower(ctx.proc)
        allowed = SYSTEM_BINARIES_WIN.get(name)
        if allowed and exe and not exe.startswith(allowed):
            out.append(Finding("LIN-005", f"Possible masquerading: {name} outside system directory", 80,
                               "Defense Evasion", "T1036.005", f"Path: {ctx.proc.get('exe')}", {"exe": ctx.proc.get("exe")}))
        exp = EXPECTED_PARENT_WIN.get(name)
        if exp and pname and pname not in exp:
            out.append(Finding("LIN-004", f"Unexpected parent for {name}", 70, "Defense Evasion", "T1036.009",
                               f"Parent {pname}; expected one of {sorted(exp)}.", ev))
    else:
        first = (ctx.proc.get("cmdline") or "").split(" ", 1)[0]
        if ctx.proc.get("exe") and (_KTHREAD.match(name) or first.startswith("[")):
            out.append(Finding("LIN-006", "User-space process masquerading as a kernel thread", 70, "Defense Evasion",
                               "T1036.004", f"{name!r} has a real executable ({ctx.proc.get('exe')}); kernel threads never do.",
                               {"name": name, "exe": ctx.proc.get("exe")}))
    return out


# ---- execution location / fileless -------------------------------------------------------
def rule_exec_location(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    exe = _exe_lower(ctx.proc)
    if ctx.proc.get("is_agent"):
        return out
    if exe.startswith("/memfd:"):
        out.append(Finding("EXE-003", "Process executing from an anonymous memory file (memfd)", 85, "Defense Evasion",
                           "T1620", "The binary exists only in memory (fileless execution).", {"exe": ctx.proc.get("exe")}, memory=True))
    elif ctx.proc.get("exe_deleted"):
        out.append(Finding("EXE-002", "Running binary was deleted from disk", 60, "Defense Evasion", "T1070.004",
                           "The executable on disk no longer exists.", {"exe": ctx.proc.get("exe")}))
    elif exe:
        susp = (exe.startswith(SUSP_DIRS_POSIX) if not _is_windows(ctx)
                else any(d in exe for d in SUSP_DIRS_WIN))
        if susp:
            out.append(Finding("EXE-001", "Executable launched from a temporary/world-writable directory", 35, "Execution",
                               "T1036.005", f"Path: {ctx.proc.get('exe')}", {"exe": ctx.proc.get("exe")}))
    return out


# ---- command line ------------------------------------------------------------------------
_CMD = [
    ("CMD-001", "Encoded PowerShell command", 70, "Execution", "T1059.001",
     re.compile(r"(?i)powershell\S*\s.*-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}")),
    ("CMD-002", "Hidden, no-profile PowerShell", 50, "Defense Evasion", "T1564.003",
     re.compile(r"(?i)-nop(?:rofile)?\b.*-w(?:indowstyle)?\s+hidden|-w(?:indowstyle)?\s+hidden.*-nop(?:rofile)?\b")),
    ("CMD-003", "PowerShell download cradle", 75, "Execution", "T1059.001",
     re.compile(r"(?i)(?:iex|invoke-expression).{0,200}(?:downloadstring|webclient|invoke-webrequest|\biwr\b|net\.webclient)")),
    ("CMD-004", "certutil used to download or decode", 65, "Command and Control", "T1105",
     re.compile(r"(?i)certutil.*(?:-urlcache|-verifyctl|-decode)")),
    ("CMD-005", "bitsadmin transfer", 55, "Command and Control", "T1197", re.compile(r"(?i)bitsadmin.*/transfer")),
    ("CMD-006", "mshta executing remote or script content", 70, "Defense Evasion", "T1218.005",
     re.compile(r"(?i)mshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:)")),
    ("CMD-007", "regsvr32 scriptlet execution", 75, "Defense Evasion", "T1218.010",
     re.compile(r"(?i)regsvr32.*(?:/i:https?:|scrobj\.dll)")),
    ("CMD-008", "rundll32 script/URL execution", 70, "Defense Evasion", "T1218.011",
     re.compile(r"(?i)rundll32.*(?:javascript:|vbscript:|https?://)")),
    ("CMD-009", "Reverse shell via /dev/tcp", 90, "Execution", "T1059.004", re.compile(r"/dev/tcp/\d")),
    ("CMD-010", "Netcat/socat with command execution", 75, "Execution", "T1059.004",
     re.compile(r"(?i)\b(?:nc|ncat|netcat)\b.*\s-[a-z]*e\s|\bsocat\b.*exec:")),
    ("CMD-011", "Download piped to shell", 75, "Command and Control", "T1105",
     re.compile(r"(?i)\b(?:curl|wget)\b[^|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")),
    ("CMD-012", "Base64 payload piped to shell", 75, "Defense Evasion", "T1140",
     re.compile(r"(?i)base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba|z|da)?sh\b")),
    ("CMD-013", "Python/Perl socket + pty shell", 80, "Execution", "T1059.006",
     re.compile(r"(?i)(?:python[0-9.]*|perl)\s+-[ce]\s.*(?:pty\.spawn|socket.*(?:subprocess|exec|dup2))")),
    ("CMD-014", "Executable staged from /tmp or /dev/shm and made runnable", 45, "Execution", "T1059.004",
     re.compile(r"\bchmod\s+(?:\+x|[0-7]*7[0-7]*)\s+/(?:tmp|dev/shm|var/tmp)/")),
]


def rule_cmdline(ctx: Ctx) -> list[Finding]:
    cmd = ctx.proc.get("cmdline") or ""
    if not cmd or ctx.proc.get("is_agent"):
        return []
    out = []
    for rid, title, weight, tactic, tech, rx in _CMD:
        m = rx.search(cmd)
        if m:
            snippet = cmd[max(0, m.start() - 20): m.end() + 40]
            out.append(Finding(rid, title, weight, tactic, tech, "Matched command-line pattern.", {"match": snippet[:300]}))
    return out


# ---- memory ------------------------------------------------------------------------------
def rule_memory(ctx: Ctx) -> list[Finding]:
    if not ctx.mem or ctx.proc.get("is_agent"):
        return []
    s = ctx.mem.get("summary", {})
    regions = ctx.mem.get("regions", [])
    exe_name = _exe_lower(ctx.proc).replace("\\", "/").rsplit("/", 1)[-1]
    runtimes = list(s.get("runtimes") or [])
    jit = (_base(ctx.proc) in JIT_PROCS or _base(ctx.proc) in ctx.jit_extra or exe_name in JIT_PROCS
           or exe_name in ctx.jit_extra or any(h in exe_name for h in JIT_EXE_HINTS) or bool(runtimes))
    why = f" Process is a known JIT host{' (' + ', '.join(runtimes[:3]) + ' loaded)' if runtimes else ''}." if jit else ""

    def shared(r: dict) -> int:
        """How many processes on this host hold an identical region, 0 if it is not widespread."""
        n = ctx.region_prev.get(region_sig(r)) if ctx.shared_min else None
        return n[0] if n and n[0] >= ctx.shared_min and n[1] >= SHARED_MIN_NAMES else 0

    def split(regs: list[dict]) -> tuple[list[dict], list[dict], str]:
        own = [r for r in regs if not shared(r)]
        common = [r for r in regs if shared(r)]
        note = (f" {len(common)} of these match regions found in {max(shared(r) for r in common)} processes on this host "
                "(a system-wide component, not targeted injection)." if common else "")
        return own, common, note

    out: list[Finding] = []
    hdr = [r for r in regions if r.get("header") and r.get("unbacked")]
    if hdr:
        r = hdr[0]
        out.append(Finding("MEM-002", "Executable image mapped in unbacked memory (reflective load / injection)", 90,
                           "Defense Evasion", "T1055.001",
                           f"{r['header']} header found in a private executable region at {int(r['start']):#x} "
                           f"({r.get('protect') or r['perms']}).",
                           {"regions": [_rg(x) for x in hdr[:3]]}, memory=True))
    rwx = [r for r in regions if r.get("rwx")]
    if rwx:
        own, common, note = split(rwx)
        base = 8 if jit else 40
        out.append(Finding("MEM-001", "Writable + executable memory region (RWX)", base if own else min(base, 8),
                           "Defense Evasion", "T1055", f"{s.get('rwx_regions', len(rwx))} RWX region(s)." + why + note,
                           {"regions": [_rg(x) for x in (own + common)[:4]], "shared_regions": len(common)}, memory=True))
    unb = [r for r in regions if r.get("unbacked") and not r.get("rwx") and not r.get("header")]
    if unb:
        own, common, note = split(unb)
        base = 5 if jit else 35
        out.append(Finding("MEM-003", "Executable memory not backed by any file", base if own else min(base, 5),
                           "Defense Evasion", "T1055", f"{s.get('unbacked_exec', len(unb))} unbacked executable region(s) "
                                    "(consistent with RW->RX shellcode staging)." + note,
                           {"regions": [_rg(x) for x in (own + common)[:4]], "shared_regions": len(common)}, memory=True))
    sp = [r for r in regions if r.get("susp_path") and not r.get("unbacked")]
    if sp:
        out.append(Finding("MEM-004", "Executable mapping from a temporary or deleted file", 45, "Defense Evasion", "T1574",
                           f"Mapped from {sp[0].get('path') or '?'}.", {"regions": [_rg(x) for x in sp[:3]]}, memory=True))
    hi = [r for r in regions if r.get("unbacked") and (r.get("entropy") or 0) >= 7.2]
    if hi and not jit:
        out.append(Finding("MEM-005", "High-entropy executable memory (packed/encrypted code)", 50, "Defense Evasion",
                           "T1027", f"Entropy {hi[0]['entropy']} in a {hi[0]['size']}-byte unbacked region.",
                           {"regions": [_rg(x) for x in hi[:3]]}, memory=True))
    return out


def _rg(r: dict) -> dict:
    return {k: r.get(k) for k in ("start", "size", "perms", "protect", "kind", "path", "header", "entropy")}


# ---- network -----------------------------------------------------------------------------
def rule_network(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    if ctx.proc.get("is_agent"):
        return out
    name = _base(ctx.proc)
    exe = _exe_lower(ctx.proc)
    in_susp = exe.startswith(SUSP_DIRS_POSIX) or any(d in exe for d in SUSP_DIRS_WIN) or exe.startswith("/memfd:") \
        or bool(ctx.proc.get("exe_deleted"))
    outbound = [c for c in ctx.conns if c["direction"] == "outbound" and c.get("scope") == "public"]
    ancestry_bad = any(_base(a) in OFFICE or _base(a) in WEB_SERVERS for a in ctx.ancestors[:2])

    if name in SHELLS and outbound:
        c = outbound[0]
        out.append(Finding("NET-001", "Shell/script host with an outbound internet connection", 65, "Command and Control",
                           "T1071", f"{name} -> {c['raddr']}:{c['rport']} (possible reverse shell).",
                           {"conn": _cn(c)}, suffix=f":{c['raddr']}:{c['rport']}", remote_ip=c["raddr"]))
    if in_susp and outbound and name not in SHELLS:
        c = outbound[0]
        out.append(Finding("NET-003", "Process from temp/deleted/memfd binary talking to the internet", 50,
                           "Command and Control", "T1071", f"{c['raddr']}:{c['rport']}", {"conn": _cn(c)},
                           suffix=f":{c['raddr']}:{c['rport']}", remote_ip=c["raddr"]))
    if ancestry_bad and outbound and name not in SHELLS:
        c = outbound[0]
        out.append(Finding("NET-002", "Child of office/web-server process connecting outbound", 55, "Command and Control",
                           "T1071", f"{c['raddr']}:{c['rport']}", {"conn": _cn(c)},
                           suffix=f":{c['raddr']}:{c['rport']}", remote_ip=c["raddr"]))

    # lots of public peers on lots of different ports is a p2p swarm. C2 talks to a few fixed
    # destinations and a scanner hits one port on many hosts, so neither looks like this
    peers = {c["raddr"] for c in outbound}
    ports = {c["rport"] for c in outbound}
    swarm = len(peers) >= SWARM_PEERS and len(ports) >= SWARM_PORTS
    odd = [c for c in outbound if c["rport"] not in netintel.COMMON_PORTS and c["rport"] >= 1024]
    if odd and name not in BROWSERS:
        dests = list(dict.fromkeys(f"{c['raddr']}:{c['rport']}" for c in odd))
        c = odd[0]
        more = f" and {len(dests) - 3} more" if len(dests) > 3 else ""
        note = (f" {len(peers)} peers on {len(ports)} ports: the pattern of a peer-to-peer swarm, not command and control."
                if swarm else "")
        out.append(Finding("NET-004", "Outbound connections to uncommon ports" if len(dests) > 1 else
                           f"Outbound connection to uncommon port {c['rport']}", 8 if swarm else 20, "Command and Control",
                           "T1571", ", ".join(dests[:3]) + more + "." + note,
                           {"conn": _cn(c), "destinations": dests[:12], "peers": len(peers), "ports": len(ports)},
                           remote_ip=c["raddr"]))  # one finding per process, not one alert per peer
    for c in outbound:
        if (c.get("country") and c["country"] in ctx.watch_countries) or (c.get("asn") and str(c["asn"]) in ctx.watch_asns):
            out.append(Finding("NET-006", "Connection to a watch-listed country/ASN", 35, "Command and Control", "T1071",
                               f"{c['raddr']} ({c.get('country')}, AS{c.get('asn')})", {"conn": _cn(c)},
                               suffix=f":{c['raddr']}", remote_ip=c["raddr"]))
            break
    for c in outbound:
        h = c.get("hostname") or ""
        if h and netintel.looks_dga(h):
            out.append(Finding("NET-007", "Destination hostname looks algorithmically generated", 40, "Command and Control",
                               "T1568.002", f"{h} (entropy {c.get('entropy')})", {"conn": _cn(c)},
                               suffix=f":{h}", remote_ip=c["raddr"]))
            break

    # beaconing: same destination, near-constant interval
    by_dest: dict[tuple, list[float]] = {}
    for c in outbound:
        by_dest.setdefault((c["raddr"], c["rport"]), []).append(c["ts"])
    for (ip, port), stamps in by_dest.items():
        st = netintel.beacon_stats(stamps)
        if st and st["cv"] < 0.2 and 5 <= st["mean"] <= 3600:
            out.append(Finding("NET-005", "Periodic beaconing to the same destination", 15 if swarm else 55,
                               "Command and Control", "T1071",
                               f"{ip}:{port} every ~{st['mean']}s (cv={st['cv']}, n={st['count']})."
                               + (" One peer among a swarm that reconnects on a timer; low confidence." if swarm else ""),
                               {"beacon": st, "dest": f"{ip}:{port}"}, suffix=f":{ip}:{port}", remote_ip=ip))
            break

    listen = [c for c in ctx.conns if c["direction"] == "listen" and c.get("laddr") in ("0.0.0.0", "::", "")]
    if listen and (name in SHELLS or in_susp or name in INTERPRETERS and in_susp):
        c = listen[0]
        out.append(Finding("NET-008", "Unexpected listener on all interfaces", 55, "Command and Control", "T1571",
                           f"{name} listening on {c['laddr'] or '*'}:{c['lport']} (possible bind shell).",
                           {"conn": _cn(c)}, suffix=f":{c['lport']}"))
    return out


def _cn(c: dict) -> dict:
    return {k: c.get(k) for k in ("proto", "laddr", "lport", "raddr", "rport", "country", "asn", "as_org", "hostname")}


# ---- anomaly -----------------------------------------------------------------------------
def rule_anomaly(ctx: Ctx) -> list[Finding]:
    a = ctx.anomaly
    if a is None or a < 0.6 or ctx.proc.get("is_agent"):
        return []
    return [Finding("ANOM-001", "Behavioural outlier versus host baseline (Isolation Forest)", int(round(10 + 20 * a)),
                    "Discovery", "", f"Anomaly score {a:.2f} (0 normal .. 1 extreme). Supporting evidence: "
                    "large or busy programs are outliers by nature, so this never raises an alert on its own.",
                    {"anomaly": round(a, 3)})]


_YARA_WEIGHT = {"low": 30, "medium": 50, "high": 75, "critical": 90}


def rule_yara(ctx: Ctx) -> list[Finding]:
    out = []
    for h in ctx.proc.get("yara_hits") or []:
        w = _YARA_WEIGHT.get(h.get("severity", "medium"), 50)
        out.append(Finding("YARA." + h["rule"], f"YARA match: {h['rule']}", w, "Execution", h.get("technique", ""),
                           h.get("description", "Signature matched process memory or binary."),
                           {"rule": h["rule"], "source": h.get("source")}, memory=h.get("source") == "memory"))
    return out


RULES = (rule_lineage, rule_exec_location, rule_cmdline, rule_memory, rule_network, rule_anomaly, rule_yara)


def evaluate(ctx: Ctx) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(ctx))
    findings.sort(key=lambda f: -f.weight)
    return findings

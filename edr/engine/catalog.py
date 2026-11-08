"""Catalogue of every detection rule, shown on the Rules sheet.

Weights are the starting weight a finding contributes to the process risk score (0-100,
combined as a noisy-OR). A range means the weight depends on context, e.g. known JIT hosts.
"""
from __future__ import annotations

from . import rules

# id -> (category, title, weight, tactic, technique, what it means)
_STATIC: dict[str, tuple[str, str, str, str, str, str]] = {
    "LIN-001": ("Lineage", "Office/document app spawned a shell or script host", "85", "Execution", "T1204.002",
                "A document reader or Office app started cmd, PowerShell, a script host or a LOLBin. Malicious documents run their payload this way."),
    "LIN-002": ("Lineage", "Browser spawned a shell", "70", "Execution", "T1189",
                "A browser started a command interpreter. Browsers do not normally do that; drive-by exploits do."),
    "LIN-003": ("Lineage", "Web server spawned a shell (possible web shell)", "80", "Persistence", "T1505.003",
                "A web server process started a shell or LOLBin, which is how web shells run commands."),
    "LIN-004": ("Lineage", "Unexpected parent for a system process", "70", "Defense Evasion", "T1036.009",
                "A core Windows process such as svchost or lsass has a parent other than the one Windows gives it."),
    "LIN-005": ("Lineage", "Possible masquerading outside the system directory", "80", "Defense Evasion", "T1036.005",
                "A process named like a Windows system binary runs from somewhere other than its system folder."),
    "LIN-006": ("Lineage", "User-space process masquerading as a kernel thread", "70", "Defense Evasion", "T1036.004",
                "On Linux a process is named like a kernel thread but has a real executable; real kernel threads never do."),
    "EXE-001": ("Location", "Executable launched from a temporary/world-writable directory", "35", "Execution", "T1036.005",
                "The program runs from Temp, Public, the Recycle Bin or /tmp, places where malware commonly drops itself."),
    "EXE-002": ("Location", "Running binary was deleted from disk", "60", "Defense Evasion", "T1070.004",
                "The executable file behind a live process no longer exists."),
    "EXE-003": ("Location", "Process executing from an anonymous memory file (memfd)", "85", "Defense Evasion", "T1620",
                "Linux fileless execution: the program exists only in memory."),
    "MEM-001": ("Memory", "Writable + executable memory region (RWX)", "8-40", "Defense Evasion", "T1055",
                "A memory page that is both writable and executable. Injected code needs this; so do JIT compilers, which is why known JIT hosts score low. A region identical in many differently named programs on the host (a system-wide component) also scores low, but stays listed."),
    "MEM-002": ("Memory", "Executable image mapped in unbacked memory", "90", "Defense Evasion", "T1055.001",
                "A PE or ELF header sits in private executable memory: a reflectively loaded or injected module."),
    "MEM-003": ("Memory", "Executable memory not backed by any file", "5-35", "Defense Evasion", "T1055",
                "Executable pages with no file behind them, typical of staged shellcode. JIT hosts do this legitimately, and so does a component injected into most programs on the host; both score low."),
    "MEM-004": ("Memory", "Executable mapping from a temporary or deleted file", "45", "Defense Evasion", "T1574",
                "Code mapped from a file in Temp or a deleted file, such as a DLL dropped and loaded from a user-writable folder."),
    "MEM-005": ("Memory", "High-entropy executable memory (packed/encrypted code)", "50", "Defense Evasion", "T1027",
                "Unbacked executable memory whose bytes look random, which suggests packed or encrypted code."),
    "NET-001": ("Network", "Shell/script host with an outbound internet connection", "65", "Command and Control", "T1071",
                "A command interpreter is talking to the internet, the shape of a reverse shell."),
    "NET-002": ("Network", "Child of office/web-server process connecting outbound", "55", "Command and Control", "T1071",
                "A process started by an Office app or web server is connecting out."),
    "NET-003": ("Network", "Process from temp/deleted/memfd binary talking to the internet", "50", "Command and Control", "T1071",
                "A binary from a drop location is making internet connections."),
    "NET-004": ("Network", "Outbound connection to uncommon port", "8-20", "Command and Control", "T1571",
                "A non-browser process connects to a high port that is not in the common-services list. One finding per process. Many peers on many ports looks like a peer-to-peer swarm and scores low."),
    "NET-005": ("Network", "Periodic beaconing to the same destination", "15-55", "Command and Control", "T1071",
                "Connections to one address at suspiciously regular intervals, like a command-and-control check-in."),
    "NET-006": ("Network", "Connection to a watch-listed country/ASN", "35", "Command and Control", "T1071",
                "The destination is in a country or network you listed in AETHER_WATCH_COUNTRIES or AETHER_WATCH_ASNS."),
    "NET-007": ("Network", "Destination hostname looks algorithmically generated", "40", "Command and Control", "T1568.002",
                "A high-entropy hostname, typical of domain-generation algorithms. Needs reverse DNS enabled."),
    "NET-008": ("Network", "Unexpected listener on all interfaces", "55", "Command and Control", "T1571",
                "A process is listening on every network interface on an unusual port."),
    "ANOM-001": ("Behaviour", "Behavioural outlier versus host baseline", "22-30", "Discovery", "",
                 "The Isolation Forest baseline learned from this host scores the process as unusual. Supporting evidence only: it cannot raise an alert by itself."),
}


def catalog() -> list[dict]:
    out = [
        {"id": rid, "category": cat, "title": title, "weight": w, "tactic": tactic, "technique": tech, "summary": text}
        for rid, (cat, title, w, tactic, tech, text) in _STATIC.items()
    ]
    for rid, title, weight, tactic, tech, _rx in rules._CMD:  # noqa: SLF001
        out.append({"id": rid, "category": "Command line", "title": title, "weight": str(weight), "tactic": tactic,
                    "technique": tech, "summary": "Matches a known-bad command-line pattern."})
    out.append({"id": "YARA.*", "category": "Signature", "title": "YARA signature match", "weight": "30-90",
                "tactic": "Execution", "technique": "", "summary": "A YARA rule matched this process's memory or file. Weight follows the rule's severity."})
    out.sort(key=lambda r: r["id"])
    return out

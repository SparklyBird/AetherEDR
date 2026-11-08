"""YARA scanning of live process memory with yara-python."""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable

from django.conf import settings

try:
    import yara

    AVAILABLE = True
except ImportError:  # no wheel for this Python version, or no build tools
    yara = None
    AVAILABLE = False

from edr.collector import memory

log = logging.getLogger("aether.yara")
RULES_DIR = Path(__file__).resolve().parent.parent / "yara_rules"
CHUNK = 4 * 1024 * 1024
OVERLAP = 4096
MAX_CUSTOM_RULE_BYTES = 256 * 1024
MAX_INSTANCES = 8


# `scan_source` is "memory" or "file" at match time, so a rule can restrict itself (an ELF header at
# offset 0 is meaningful in a memory chunk but matches every Linux binary on disk).
EXTERNALS = {"scan_source": ""}


UNAVAILABLE_MSG = (
    "YARA is not installed. Run: pip install -r requirements-yara.txt "
    "(Windows needs Python 3.12 or 3.13 for a prebuilt wheel, or the Microsoft C++ Build Tools)."
)


class RuleError(ValueError):
    pass


def require() -> None:
    if not AVAILABLE:
        raise RuleError(UNAVAILABLE_MSG)


_builtin: yara.Rules | None = None
_builtin_lock = threading.Lock()


def builtin_rules() -> yara.Rules:
    require()
    global _builtin
    with _builtin_lock:
        if _builtin is None:
            files = {p.stem: str(p) for p in sorted(RULES_DIR.glob("*.yar"))}
            if not files:
                raise RuleError(f"no built-in rules found in {RULES_DIR}")
            _builtin = yara.compile(filepaths=files, includes=False, externals=EXTERNALS)
        return _builtin


def compile_custom(source: str) -> yara.Rules:
    require()
    if len(source.encode()) > MAX_CUSTOM_RULE_BYTES:
        raise RuleError("custom rule set too large")
    try:
        # includes=False so a rule file cannot pull in other files from disk
        return yara.compile(source=source, includes=False, externals=EXTERNALS)
    except yara.SyntaxError as exc:
        raise RuleError(f"syntax error: {exc}") from exc
    except yara.Error as exc:
        raise RuleError(str(exc)) from exc


def builtin_rule_names() -> list[dict]:
    out = []
    for r in builtin_rules():
        out.append({"rule": r.identifier, "namespace": r.namespace, "tags": list(r.tags), "meta": dict(r.meta)})
    return out


def _fmt_match(m: yara.Match, base: int, region: dict | None, source: str) -> dict:
    strings = []
    for s in m.strings:
        for inst in s.instances[:MAX_INSTANCES]:
            strings.append({
                "id": s.identifier,
                "address": f"{base + inst.offset:#x}" if source == "memory" else inst.offset,
                "data": inst.matched_data[:32].hex(),
            })
    return {
        "rule": m.rule, "namespace": m.namespace, "tags": list(m.tags), "meta": dict(m.meta),
        "source": source, "strings": strings[:24],
        "region": ({k: region.get(k) for k in ("start", "size", "perms", "protect", "kind", "path")}
                   if region else None),
    }


def _select(regions: list[memory.Region], scope: str) -> list[memory.Region]:
    if scope == "all":
        sel = [r for r in regions if r.readable]
    elif scope == "executable":
        sel = [r for r in regions if r.executable and r.readable]
    else:
        sel = [r for r in regions if memory.is_flagged(r) and r.readable]
    # suspicious regions first, so the byte budget goes there
    sel.sort(key=lambda r: (not r.rwx, not r.unbacked, not r.executable, -r.size))
    return sel


def scan_process(
    pid: int,
    rules: list[yara.Rules],
    scope: str = "flagged",
    exe_path: str = "",
    include_file: bool = True,
    progress: Callable[[int, int], None] | None = None,
) -> dict:
    require()
    cfg = settings.AETHER
    max_region, max_total = cfg["YARA_MAX_REGION"], cfg["YARA_MAX_TOTAL"]
    matches: list[dict] = []
    seen: set[tuple] = set()
    regions_scanned = bytes_scanned = 0
    skipped = 0

    if include_file and exe_path:
        try:
            for rs in rules:
                for m in rs.match(filepath=exe_path, timeout=30, externals={"scan_source": "file"}):
                    key = (m.namespace, m.rule, "file")
                    if key not in seen:
                        seen.add(key)
                        matches.append(_fmt_match(m, 0, None, "file"))
        except (yara.Error, OSError) as exc:
            log.debug("file scan skipped %s: %s", exe_path, exc)

    selected = _select(memory.enumerate_regions(pid), scope)
    for r in selected:
        if bytes_scanned >= max_total:
            skipped += 1
            continue
        want = min(r.size, max_region)
        got_any = False
        off = 0
        while off < want:
            n = min(CHUNK + OVERLAP, want - off)
            try:
                data = memory.read_memory(pid, r.start + off, n)
            except memory.MemoryAccessError:
                break
            if not data:
                break
            got_any = True
            bytes_scanned += len(data)
            for rs in rules:
                try:
                    found = rs.match(data=data, timeout=30, externals={"scan_source": "memory"})
                except yara.TimeoutError:
                    continue
                for m in found:
                    key = (m.namespace, m.rule, r.start)
                    if key in seen:
                        continue
                    seen.add(key)
                    matches.append(_fmt_match(m, r.start + off, r.as_dict(), "memory"))
            off += CHUNK
        if got_any:
            regions_scanned += 1
        if progress:
            progress(regions_scanned, bytes_scanned)
    return {"matches": matches, "regions_scanned": regions_scanned, "bytes_scanned": bytes_scanned,
            "regions_skipped": skipped, "regions_selected": len(selected)}

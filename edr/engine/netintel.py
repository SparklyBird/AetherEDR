"""Offline network helpers: IP scope, GeoIP/ASN lookup, name entropy.

No network calls are made (reverse DNS is opt-in via AETHER_REVERSE_DNS=1).

GeoIP/ASN data
    A tiny built-in seed table covers a handful of well-known anycast ranges. For real
    coverage drop a dataset at  data/geo_asn.csv  - supported layouts (auto-detected):
      * iptoasn.com TSV   : range_start  range_end  asn  country  description
      * CIDR CSV          : cidr,country,asn,org
      * range CSV         : start_ip,end_ip,country            (DB-IP / IP2Location style)
"""
from __future__ import annotations

import bisect
import csv
import ipaddress
import logging
import math
import socket
import statistics
from collections import Counter
from functools import lru_cache
from pathlib import Path

log = logging.getLogger("aether.netintel")

# (cidr, country, asn, org). Anycast/global services: country is the registrant's.
SEED = [
    ("1.1.1.0/24", "AU", 13335, "Cloudflare"),
    ("1.0.0.0/24", "AU", 13335, "Cloudflare"),
    ("104.16.0.0/13", "US", 13335, "Cloudflare"),
    ("8.8.8.0/24", "US", 15169, "Google"),
    ("8.8.4.0/24", "US", 15169, "Google"),
    ("9.9.9.0/24", "US", 19281, "Quad9"),
    ("208.67.222.0/24", "US", 36692, "Cisco OpenDNS"),
    ("208.67.220.0/24", "US", 36692, "Cisco OpenDNS"),
]

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def classify_ip(ip: str) -> str:
    """public, private, loopback, link-local, multicast, cgnat, reserved or invalid"""
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "invalid"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link-local"
    if a.is_multicast:
        return "multicast"
    if a.version == 4 and a in _CGNAT:
        return "cgnat"
    if a.is_private:
        return "private"
    if a.is_unspecified or a.is_reserved:
        return "reserved"
    return "public"


class GeoAsn:
    def __init__(self, extra_path: Path | None = None) -> None:
        self._v4: list[tuple[int, int, str, int, str]] = []
        self._v6: list[tuple[int, int, str, int, str]] = []
        self._starts4: list[int] = []
        self._starts6: list[int] = []
        for cidr, cc, asn, org in SEED:
            self._add(ipaddress.ip_network(cidr)[0], ipaddress.ip_network(cidr)[-1], cc, asn, org)
        self.loaded_extra = 0
        if extra_path and Path(extra_path).exists():
            try:
                self.loaded_extra = self._load_file(Path(extra_path))
                log.info("loaded %d GeoIP/ASN ranges from %s", self.loaded_extra, extra_path)
            except Exception as exc:  # noqa: BLE001
                log.warning("could not load %s: %s", extra_path, exc)
        self._v4.sort(key=lambda r: (r[0], -(r[1] - r[0])))
        self._v6.sort(key=lambda r: (r[0], -(r[1] - r[0])))
        self._starts4 = [r[0] for r in self._v4]
        self._starts6 = [r[0] for r in self._v6]

    def _add(self, start, end, cc: str, asn: int, org: str) -> None:
        s, e = int(start), int(end)
        (self._v6 if start.version == 6 else self._v4).append((s, e, cc, asn, org))

    def _load_file(self, path: Path) -> int:
        n = 0
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            sample = fh.readline()
            fh.seek(0)
            delim = "\t" if sample.count("\t") >= 3 else ","
            for row in csv.reader(fh, delimiter=delim):
                if not row or row[0].startswith("#"):
                    continue
                try:
                    if "/" in row[0]:
                        net = ipaddress.ip_network(row[0], strict=False)
                        cc = row[1] if len(row) > 1 else ""
                        asn = int(row[2]) if len(row) > 2 and row[2].isdigit() else 0
                        org = row[3] if len(row) > 3 else ""
                        self._add(net[0], net[-1], cc, asn, org)
                    else:
                        a, b = ipaddress.ip_address(row[0]), ipaddress.ip_address(row[1])
                        if len(row) >= 5 and row[2].isdigit():  # iptoasn: start end asn cc desc
                            asn, cc, org = int(row[2]), row[3], row[4]
                        else:                                   # start,end,country
                            asn, cc, org = 0, row[2] if len(row) > 2 else "", ""
                        if cc in ("None", "ZZ") and asn == 0:
                            continue
                        self._add(a, b, cc, asn, org)
                    n += 1
                except (ValueError, IndexError):
                    continue
        return n

    def lookup(self, ip: str) -> dict:
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return {}
        table, starts = (self._v6, self._starts6) if a.version == 6 else (self._v4, self._starts4)
        x = int(a)
        i = bisect.bisect_right(starts, x) - 1
        best = None
        for j in range(i, max(i - 8, -1), -1):  # walk back over nested ranges
            s, e, cc, asn, org = table[j]
            if s <= x <= e and (best is None or e - s < best[1] - best[0]):
                best = (s, e, cc, asn, org)
        if not best:
            return {}
        return {"country": best[2], "asn": best[3] or None, "as_org": best[4]}


# --- entropy heuristics ------------------------------------------------------------
def shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def name_entropy(hostname: str) -> float:
    """Entropy of the second-level domain label. Generated (DGA) names score high."""
    parts = [p for p in hostname.lower().strip(".").split(".") if p]
    if len(parts) < 2:
        return shannon(parts[0]) if parts else 0.0
    sld = parts[-2] if len(parts[-1]) <= 3 or len(parts) == 2 else parts[-2]
    return shannon(sld)


def looks_dga(hostname: str) -> bool:
    parts = [p for p in hostname.lower().strip(".").split(".") if p]
    if len(parts) < 2:
        return False
    sld = parts[-2]
    if len(sld) < 10:
        return False
    digits = sum(ch.isdigit() for ch in sld) / len(sld)
    vowels = sum(ch in "aeiou" for ch in sld) / len(sld)
    return shannon(sld) >= 3.5 and (digits >= 0.3 or vowels <= 0.2)


def beacon_stats(timestamps: list[float]) -> dict | None:
    """Looks for connections at regular intervals. Returns mean and cv, or None with too few samples."""
    if len(timestamps) < 6:
        return None
    ts = sorted(timestamps)
    deltas = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.5]
    if len(deltas) < 5:
        return None
    mean = statistics.fmean(deltas)
    if mean <= 0:
        return None
    cv = statistics.pstdev(deltas) / mean
    return {"mean": round(mean, 2), "cv": round(cv, 3), "count": len(ts)}


COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 636, 993, 995,
                1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 9418}


@lru_cache(maxsize=4096)
def reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""
    finally:
        socket.setdefaulttimeout(None)


_geo: GeoAsn | None = None


def geo() -> GeoAsn:
    global _geo
    if _geo is None:
        from django.conf import settings  # noqa: PLC0415

        _geo = GeoAsn(settings.AETHER.get("GEO_DB"))
    return _geo


@lru_cache(maxsize=8192)
def enrich(ip: str, do_rdns: bool = False) -> dict:
    scope = classify_ip(ip)
    out = {"scope": scope, "country": "", "asn": None, "as_org": "", "hostname": "", "entropy": None}
    if scope == "public":
        out.update({k: v for k, v in geo().lookup(ip).items() if v})
        if do_rdns:
            host = reverse_dns(ip)
            if host:
                out["hostname"] = host
                out["entropy"] = round(name_entropy(host), 3)
    return out

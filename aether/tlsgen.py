"""Self-signed certificate for the built-in HTTPS option, using only the standard library.

The standard library can load certificates but cannot create them, and the zero-dependency rule rules out
the cryptography package. So this builds the small subset it needs by hand: an RSA-2048 key (Miller-Rabin
primes from the secrets module), a v3 X.509 certificate with the usual server extensions, and a
PKCS#1 v1.5 / SHA-256 signature. It is meant for a certificate you generate once for your own machine,
not as a general crypto library.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import math
import secrets

_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]
_E = 65537


# -- RSA -----------------------------------------------------------------------------------------
def _probably_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1   # top two bits set so p*q has full length
        if math.gcd(c - 1, _E) == 1 and _probably_prime(c):
            return c


def generate_rsa(bits: int = 2048) -> dict:
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        if n.bit_length() != bits:
            continue
        d = pow(_E, -1, math.lcm(p - 1, q - 1))
        return {"n": n, "e": _E, "d": d, "p": p, "q": q,
                "dp": d % (p - 1), "dq": d % (q - 1), "qinv": pow(q, -1, p)}


# -- DER -----------------------------------------------------------------------------------------
def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        head = bytes([tag, n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(raw)]) + raw
    return head + body


def _int(v: int) -> bytes:
    raw = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")   # the extra bit keeps it positive
    return _tlv(0x02, raw)


def _oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for v in parts[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        body.extend(reversed(chunk))
    return _tlv(0x06, bytes(body))


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(items))


def _utc(t: dt.datetime) -> bytes:
    return _tlv(0x17, t.strftime("%y%m%d%H%M%SZ").encode())


def _name(cn: str) -> bytes:
    return _seq(_set(_seq(_oid("2.5.4.3"), _tlv(0x0C, cn.encode()))))


def _ext(oid: str, value: bytes, critical: bool = False) -> bytes:
    parts = [_oid(oid)]
    if critical:
        parts.append(_tlv(0x01, b"\xff"))
    parts.append(_tlv(0x04, value))
    return _seq(*parts)


_NULL = b"\x05\x00"
_SHA256_RSA = _seq(_oid("1.2.840.113549.1.1.11"), _NULL)
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _san(names: list[str]) -> bytes:
    out = []
    for n in names:
        try:
            out.append(_tlv(0x87, ipaddress.ip_address(n).packed))
        except ValueError:
            out.append(_tlv(0x82, n.encode("idna")))
    return _seq(*out)


def _pem(label: str, der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


# -- certificate -----------------------------------------------------------------------------------
def make_self_signed(names: list[str], days: int = 825, common_name: str = "AetherEDR") -> tuple[str, str, dict]:
    """Returns (certificate PEM, private key PEM, info). `names` become the subject alternative names
    (DNS names or IP addresses); clients check the server address against them."""
    names = list(dict.fromkeys(n.strip() for n in names if n and n.strip())) or ["localhost"]
    key = generate_rsa()
    pub = _seq(_int(key["n"]), _int(key["e"]))
    spki = _seq(_seq(_oid("1.2.840.113549.1.1.1"), _NULL), _tlv(0x03, b"\x00" + pub))
    key_id = hashlib.sha1(pub).digest()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    start, end = now - dt.timedelta(days=1), now + dt.timedelta(days=days)
    subject = _name(common_name)
    extensions = _tlv(0xA3, _seq(
        _ext("2.5.29.19", _seq(), critical=True),                                        # not a CA
        _ext("2.5.29.15", b"\x03\x02\x05\xa0", critical=True),                           # digitalSignature, keyEncipherment
        _ext("2.5.29.37", _seq(_oid("1.3.6.1.5.5.7.3.1"))),                              # server auth
        _ext("2.5.29.17", _san(names)),
        _ext("2.5.29.14", _tlv(0x04, key_id)),                                           # subject key id
        _ext("2.5.29.35", _seq(_tlv(0x80, key_id))),                                     # authority key id (itself)
    ))
    tbs = _seq(
        _tlv(0xA0, _int(2)),                                                             # v3
        _int(secrets.randbits(159) | 1),
        _SHA256_RSA, subject, _seq(_utc(start), _utc(end)), subject, spki, extensions,
    )
    k = (key["n"].bit_length() + 7) // 8
    digest_info = _SHA256_PREFIX + hashlib.sha256(tbs).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(em, "big"), key["d"], key["n"]).to_bytes(k, "big")
    cert = _seq(tbs, _SHA256_RSA, _tlv(0x03, b"\x00" + signature))

    priv = _seq(_int(0), *(_int(key[x]) for x in ("n", "e", "d", "p", "q", "dp", "dq", "qinv")))
    info = {"names": names, "not_after": end.isoformat(), "sha256": hashlib.sha256(cert).hexdigest()}
    return _pem("CERTIFICATE", cert), _pem("RSA PRIVATE KEY", priv), info

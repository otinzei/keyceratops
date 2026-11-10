"""Cryptographic inventory and post-quantum migration priorities.

The audit's findings answer "is anything already broken?". The inventory
answers the planning questions that follow: which algorithms are deployed,
how strong each is today, which fall to a quantum computer, and in what order
to replace them.

Priorities (each key or endpoint is counted once, at its most urgent level):

1. ``broken``: keys involved in a finding of HIGH or CRITICAL severity.
2. ``weak``: classically below 112-bit strength, or a certificate signed
   with SHA-1 / MD5 (self-signed roots excepted: their signature is not used).
3. ``long-lived``: quantum-vulnerable keys in certificates valid past the
   NIST IR 8547 deprecation date (end of 2030).
4. ``harvest``: servers whose key exchange is not post-quantum, so traffic
   recorded today can be decrypted once a quantum computer exists.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from dataclasses import dataclass, field

from . import pqc
from .model import Finding, KeyRecord, Severity

WEAK_SIG_OIDS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10040.4.3": "dsa-with-sha1",
}
PRIORITIES = ("broken", "weak", "long-lived", "harvest")


@dataclass
class AlgorithmRow:
    info: pqc.AlgInfo
    keys: int  # distinct keys
    certificates: int

    def to_dict(self) -> dict:
        return {"algorithm": self.info.name, "family": self.info.family, "keys": self.keys,
                "certificates": self.certificates, "classical_bits": self.info.classical_bits,
                "nist_pq_level": self.info.nist_level, "quantum_safe": self.info.quantum_safe,
                "oid": self.info.oid}


@dataclass
class Priority:
    name: str
    count: int
    examples: list[str] = field(default_factory=list)  # sources / endpoint labels

    def to_dict(self) -> dict:
        return {"priority": self.name, "count": self.count, "examples": self.examples}


@dataclass
class CryptoInventory:
    algorithms: list[AlgorithmRow]
    keys: int
    quantum_safe_keys: int
    certificates: int
    endpoints: int
    pq_endpoints: int
    priorities: list[Priority]
    endpoint_detail: dict[str, dict]

    def to_dict(self) -> dict:
        return {
            "keys": self.keys, "quantum_safe_keys": self.quantum_safe_keys,
            "certificates": self.certificates, "endpoints": self.endpoints,
            "pq_endpoints": self.pq_endpoints,
            "algorithms": [a.to_dict() for a in self.algorithms],
            "priorities": [p.to_dict() for p in self.priorities],
            "deadlines": {"deprecated_after": pqc.DEPRECATED_AFTER.date().isoformat(),
                          "disallowed_after": pqc.DISALLOWED_AFTER.date().isoformat(),
                          "source": "NIST IR 8547"},
        }


def _not_after(k: KeyRecord) -> dt.datetime | None:
    if not k.cert_not_after:
        return None
    try:
        return dt.datetime.fromisoformat(k.cert_not_after)
    except ValueError:
        return None


def _weak_signature(k: KeyRecord) -> bool:
    return (k.cert_sig_oid in WEAK_SIG_OIDS
            and k.cert_subject is not None and k.cert_subject != k.cert_issuer)


def build(keys: list[KeyRecord], findings: list[Finding], endpoints: dict[str, dict],
          examples: int = 3) -> CryptoInventory:
    by_fp: dict[str, list[KeyRecord]] = defaultdict(list)
    for k in keys:
        by_fp[k.fingerprint].append(k)

    rows: dict[str, list] = {}
    for fp, ks in by_fp.items():
        info = pqc.classify(ks[0])
        row = rows.setdefault(info.name, [info, 0, set()])
        row[1] += 1
        row[2].update(k.cert_fingerprint for k in ks if k.cert_fingerprint)
    algorithms = [AlgorithmRow(info, n, len(certs)) for info, n, certs in rows.values()]
    algorithms.sort(key=lambda r: (r.info.quantum_safe, -r.keys, r.info.name))

    severe = {fp for f in findings if f.severity >= Severity.HIGH for fp in f.fingerprints}
    buckets: dict[str, list[str]] = {p: [] for p in PRIORITIES}
    for fp, ks in sorted(by_fp.items(), key=lambda kv: kv[1][0].source):
        info = pqc.classify(ks[0])
        src = ks[0].source
        if fp in severe:
            buckets["broken"].append(src)
        elif (info.classical_bits is not None and info.classical_bits < 112) or any(
                _weak_signature(k) for k in ks):
            buckets["weak"].append(src)
        elif not info.quantum_safe and any(
                (na := _not_after(k)) is not None and na > pqc.DEPRECATED_AFTER for k in ks):
            buckets["long-lived"].append(src)
    for label, e in sorted(endpoints.items()):
        if e.get("pq_kex") is False:
            buckets["harvest"].append(label)

    priorities = [Priority(p, len(buckets[p]), buckets[p][:examples]) for p in PRIORITIES]
    return CryptoInventory(
        algorithms=algorithms,
        keys=len(by_fp),
        quantum_safe_keys=sum(1 for ks in by_fp.values() if pqc.classify(ks[0]).quantum_safe),
        certificates=len({k.cert_fingerprint for k in keys if k.cert_fingerprint}),
        endpoints=len(endpoints),
        pq_endpoints=sum(1 for e in endpoints.values() if e.get("pq_kex")),
        priorities=priorities,
        endpoint_detail=dict(endpoints),
    )

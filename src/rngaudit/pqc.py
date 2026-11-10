"""Post-quantum readiness: what each key is, how strong, and what breaks it.

Classical strength follows NIST SP 800-57 Part 1 (RSA/DSA by modulus size,
elliptic curves at half the order size). Every RSA, DSA, ECDSA and EdDSA key
falls to Shor's algorithm on a large quantum computer; ML-DSA, SLH-DSA and
ML-KEM (FIPS 203/204/205) carry a NIST post-quantum security category.

The migration deadlines used for planning come from NIST IR 8547: the
quantum-vulnerable algorithms are deprecated after 2030 and disallowed after
2035.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .model import KeyRecord

DEPRECATED_AFTER = dt.datetime(2030, 12, 31, 23, 59, 59, tzinfo=dt.timezone.utc)
DISALLOWED_AFTER = dt.datetime(2035, 12, 31, 23, 59, 59, tzinfo=dt.timezone.utc)

# --------------------------------------------------------------------------
# minimal DER reading (for keys the cryptography package cannot load yet)
# --------------------------------------------------------------------------


def _tlv(der: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, start of value, end of value) of the element at ``pos``."""
    if pos + 2 > len(der):
        raise ValueError("truncated DER")
    tag = der[pos]
    first = der[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(der):
            raise ValueError("bad DER length")
        length = int.from_bytes(der[pos : pos + n], "big")
        pos += n
    if pos + length > len(der):
        raise ValueError("truncated DER")
    return tag, pos, pos + length


def _oid(value: bytes) -> str:
    if not value:
        raise ValueError("empty OID")
    first = value[0]
    arcs = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(n)
            n = 0
    return ".".join(map(str, arcs))


def spki_algorithm_oid(spki: bytes) -> str:
    """Algorithm OID of a DER SubjectPublicKeyInfo."""
    tag, start, _end = _tlv(spki, 0)
    if tag != 0x30:
        raise ValueError("SPKI is not a SEQUENCE")
    tag, a_start, _a_end = _tlv(spki, start)
    if tag != 0x30:
        raise ValueError("AlgorithmIdentifier is not a SEQUENCE")
    tag, o_start, o_end = _tlv(spki, a_start)
    if tag != 0x06:
        raise ValueError("expected an OID")
    return _oid(spki[o_start:o_end])


def cert_spki(cert_der: bytes) -> bytes:
    """The SubjectPublicKeyInfo element of a DER certificate."""
    _tag, c_start, _ = _tlv(cert_der, 0)
    tag, pos, tbs_end = _tlv(cert_der, c_start)  # tbsCertificate
    if tag != 0x30:
        raise ValueError("tbsCertificate is not a SEQUENCE")
    tag, _s, end = _tlv(cert_der, pos)
    if tag == 0xA0:  # [0] version
        pos = end
    # serial, signature, issuer, validity, subject
    for _ in range(5):
        _tag, _s, pos = _tlv(cert_der, pos)
    tag, _s, end = _tlv(cert_der, pos)
    if tag != 0x30 or end > tbs_end:
        raise ValueError("no SubjectPublicKeyInfo")
    return cert_der[pos:end]


# --------------------------------------------------------------------------
# algorithm classification
# --------------------------------------------------------------------------

# OID -> (family, parameter set, NIST PQ category, classical bits)
PQ_OIDS: dict[str, tuple[str, str, int, int]] = {
    "2.16.840.1.101.3.4.3.17": ("ml-dsa", "ML-DSA-44", 2, 128),
    "2.16.840.1.101.3.4.3.18": ("ml-dsa", "ML-DSA-65", 3, 192),
    "2.16.840.1.101.3.4.3.19": ("ml-dsa", "ML-DSA-87", 5, 256),
    "2.16.840.1.101.3.4.4.1": ("ml-kem", "ML-KEM-512", 1, 128),
    "2.16.840.1.101.3.4.4.2": ("ml-kem", "ML-KEM-768", 3, 192),
    "2.16.840.1.101.3.4.4.3": ("ml-kem", "ML-KEM-1024", 5, 256),
}
for _i, (_hash, _lvl) in enumerate(
    [("SHA2-128s", 1), ("SHA2-128f", 1), ("SHA2-192s", 3), ("SHA2-192f", 3),
     ("SHA2-256s", 5), ("SHA2-256f", 5), ("SHAKE-128s", 1), ("SHAKE-128f", 1),
     ("SHAKE-192s", 3), ("SHAKE-192f", 3), ("SHAKE-256s", 5), ("SHAKE-256f", 5)]
):
    PQ_OIDS[f"2.16.840.1.101.3.4.3.{20 + _i}"] = (
        "slh-dsa", f"SLH-DSA-{_hash}", _lvl, {1: 128, 3: 192, 5: 256}[_lvl])

CLASSICAL_OIDS = {
    "1.2.840.113549.1.1.1": "rsa",
    "1.2.840.113549.1.1.10": "rsa",  # RSASSA-PSS key
    "1.2.840.10045.2.1": "ec",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
    "1.2.840.10040.4.1": "dsa",
}

_CURVE_BITS = {
    "secp224r1": 112, "secp256r1": 128, "secp256k1": 128, "secp384r1": 192,
    "secp521r1": 256, "brainpoolP256r1": 128, "brainpoolP384r1": 192,
    "brainpoolP512r1": 256,
}
_CURVE_NAME = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521",
               "secp224r1": "P-224"}


def rsa_strength(bits: int) -> int:
    """SP 800-57 comparable strength, rounded down to the table."""
    for size, strength in ((15360, 256), (7680, 192), (3072, 128), (2048, 112), (1024, 80)):
        if bits >= size - 8:  # 2047-bit moduli are 2048-bit keys
            return strength
    return 0


@dataclass(frozen=True)
class AlgInfo:
    name: str  # display name, e.g. "RSA-2048", "ECDSA P-256", "ML-DSA-65"
    family: str  # rsa | ec | ed25519 | ed448 | dsa | ml-dsa | slh-dsa | ml-kem | other
    classical_bits: int | None
    nist_level: int  # 0 = broken by a quantum computer
    primitive: str  # CycloneDX primitive: signature | kem | other
    oid: str | None

    @property
    def quantum_safe(self) -> bool:
        return self.nist_level > 0


def classify(k: KeyRecord) -> AlgInfo:
    fam = k.algorithm
    if fam == "rsa":
        bits = k.bits or 0
        return AlgInfo(f"RSA-{_round_rsa(bits)}", "rsa", rsa_strength(bits), 0, "signature",
                       "1.2.840.113549.1.1.1")
    if fam == "dsa":
        bits = k.bits or 0
        return AlgInfo(f"DSA-{bits}", "dsa", rsa_strength(bits), 0, "signature", "1.2.840.10040.4.1")
    if fam == "ec":
        curve = k.curve or "unknown"
        return AlgInfo(f"ECDSA {_CURVE_NAME.get(curve, curve)}", "ec", _CURVE_BITS.get(curve), 0,
                       "signature", "1.2.840.10045.2.1")
    if fam == "ed25519":
        return AlgInfo("Ed25519", fam, 128, 0, "signature", "1.3.101.112")
    if fam == "ed448":
        return AlgInfo("Ed448", fam, 224, 0, "signature", "1.3.101.113")
    if k.key_oid in PQ_OIDS:
        family, param, level, classical = PQ_OIDS[k.key_oid]
        return AlgInfo(param, family, classical, level,
                       "kem" if family == "ml-kem" else "signature", k.key_oid)
    return AlgInfo(f"unknown ({k.key_oid or '?'})", "other", None, 0, "other", k.key_oid)


def _round_rsa(bits: int) -> int:
    """2047 -> 2048: moduli are often a bit short of their nominal size."""
    for nominal in (1024, 1536, 2048, 3072, 4096, 7680, 8192, 15360):
        if nominal - 8 <= bits <= nominal:
            return nominal
    return bits


def family_for_oid(oid: str) -> tuple[str, str | None]:
    """(algorithm family, parameter-set name) for an SPKI algorithm OID."""
    if oid in PQ_OIDS:
        family, param, _lvl, _bits = PQ_OIDS[oid]
        return family, param
    return CLASSICAL_OIDS.get(oid, "other"), None


# --------------------------------------------------------------------------
# key exchange (protects recorded traffic against later decryption)
# --------------------------------------------------------------------------

PQ_SSH_KEX_MARKERS = ("mlkem", "sntrup")
# Hybrid groups registered for TLS 1.3 (draft-ietf-tls-ecdhe-mlkem)
TLS_PQ_GROUPS = {0x11EC: "X25519MLKEM768", 0x11EB: "SecP256r1MLKEM768"}


def is_pq_ssh_kex(name: str) -> bool:
    return any(m in name for m in PQ_SSH_KEX_MARKERS)

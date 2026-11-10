"""The audit checks.

Every check looks only at *public* data and returns ``Finding`` objects. The
guiding rule: a finding says what is wrong and how to confirm it, but never
contains material that would let a reader exploit it (no recovered primes,
no recovered private keys).
"""

from __future__ import annotations

import datetime as dt
import re
import statistics
import warnings
from collections import defaultdict
from dataclasses import dataclass
from functools import reduce
from operator import or_
from pathlib import PurePath

from . import numtheory as nt
from .model import Finding, KeyRecord, Severity, SignatureRecord

# Bit length of the group order for the curves ECDSA is commonly used with.
CURVE_ORDER_BITS = {
    "secp224r1": 224,
    "secp256r1": 256,
    "secp256k1": 256,
    "secp384r1": 384,
    "secp521r1": 521,
    "brainpoolP256r1": 256,
    "brainpoolP384r1": 384,
    "brainpoolP512r1": 512,
}


PURE_PYTHON_WARN_AT = 1000


@dataclass
class AuditConfig:
    fermat_iterations: int = 1024
    min_rsa_bits: int = 2048
    # A key's "holder" is the file (or labelled host entry) it was read from;
    # "dir" groups all files of one directory, for host/<files...> layouts.
    holder_mode: str = "file"
    # Serial-number statistics need a population to mean anything.
    serial_min_samples: int = 30
    # Cap on sources/fingerprints listed per finding (counts stay exact).
    max_list: int = 50
    small_prime_limit: int = 1 << 16
    # A file holding at least this many distinct certificates is treated as a
    # bundle (like ca-certificates.crt): it repeats certificates that also
    # exist as files of their own, which must not count as a second holder.
    bundle_min_certs: int = 5
    # Serials clearly shorter than this are always reported ...
    serial_floor_bits: int = 40
    # ... and an issuer whose >= serial_issuer_min certificates never exceed
    # 63 bits is reported as a whole (random 64-bit serials do not behave so).
    serial_issuer_min: int = 16


# CA/Browser Forum Ballot 164: from this date serials must be > 0 and carry
# at least 64 bits from a CSPRNG. Older certificates predate the rule.
SERIAL_RULE_START = dt.datetime(2016, 9, 30, tzinfo=dt.timezone.utc)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

_LOC_SUFFIX = re.compile(r"(#\d+|:\d+)( \[.*\])?$")
_HOST_LABEL = re.compile(r"\[(.+)\]$")


def file_of(source: str) -> str:
    """The file part of a record's source label."""
    return _LOC_SUFFIX.sub("", source)


def holder(key: KeyRecord, mode: str = "file") -> str:
    """Identify the device/host a key was observed on."""
    m = _HOST_LABEL.search(key.source)
    if m:
        return "host:" + m.group(1)
    path = file_of(key.source)
    if mode == "dir":
        return "dir:" + str(PurePath(path).parent)
    return "file:" + path


def bundle_files(keys: list[KeyRecord], cfg: AuditConfig) -> set[str]:
    """Files that hold many distinct certificates (trust-store bundles)."""
    certs_per_file: dict[str, set[str]] = defaultdict(set)
    for k in keys:
        if k.cert_fingerprint:
            certs_per_file[file_of(k.source)].add(k.cert_fingerprint)
    return {f for f, c in certs_per_file.items() if len(c) >= cfg.bundle_min_certs}


def _cap(items, cfg: AuditConfig):
    items = sorted(set(items))
    return items[: cfg.max_list]


# --------------------------------------------------------------------------
# 1. identical keys on different holders
# --------------------------------------------------------------------------


def check_duplicate_keys(keys: list[KeyRecord], cfg: AuditConfig) -> list[Finding]:
    groups: dict[str, list[KeyRecord]] = defaultdict(list)
    for k in keys:
        groups[k.fingerprint].append(k)

    bundles = bundle_files(keys, cfg)

    findings: list[Finding] = []
    for fp, ks in groups.items():
        # A bundle file merely repeats certificates that also exist on their
        # own; drop its copies so the same certificate is not counted twice.
        standalone = {
            k.cert_fingerprint
            for k in ks
            if k.cert_fingerprint and file_of(k.source) not in bundles
        }
        kept = [
            k
            for k in ks
            if not (file_of(k.source) in bundles and k.cert_fingerprint in standalone)
        ]
        holders = {holder(k, cfg.holder_mode) for k in kept}
        if len(holders) < 2:
            continue
        ks = kept
        hosts_only = all(h.startswith("host:") for h in holders)
        if hosts_only and all(k.cert_fingerprint for k in ks) and len(
            {k.cert_fingerprint for k in ks}
        ) == 1:
            # One certificate served under several host names (a SAN or
            # wildcard certificate behind several names): shared by design,
            # not a sign of a generator producing the same key twice.
            continue
        if hosts_only:
            # known_hosts cannot tell one server under two names (hostname and
            # IP) from two cloned machines.
            sev = Severity.HIGH if len(holders) >= 3 else Severity.MEDIUM
        else:
            sev = Severity.CRITICAL if len(holders) >= 10 else Severity.HIGH
        first = ks[0]
        findings.append(
            Finding(
                check="duplicate-key",
                severity=sev,
                title=f"One {first.algorithm.upper()} key is used by {len(holders)} holders",
                detail=(
                    "The same public key appears on several distinct holders, so they "
                    "share one private key. On devices this is the signature of a "
                    "factory-default key or of a generator that produced identical "
                    "output on every unit (same entropy at first boot). Anyone who "
                    "extracts the key from one unit can impersonate all of them."
                ),
                sources=_cap((k.source for k in ks), cfg),
                fingerprints=[fp],
                data={
                    "holders": len(holders),
                    "algorithm": first.algorithm,
                    "bits": first.bits,
                    **({"note": "alias_or_clone"} if hosts_only else {}),
                },
            )
        )

    # RSA: same modulus under different public exponents.
    by_mod: dict[int, set[str]] = defaultdict(set)
    srcs: dict[int, list[str]] = defaultdict(list)
    for k in keys:
        if k.algorithm == "rsa" and k.modulus is not None:
            by_mod[k.modulus].add(k.fingerprint)
            srcs[k.modulus].append(k.source)
    for n, fps in by_mod.items():
        if len(fps) > 1:
            findings.append(
                Finding(
                    check="common-modulus",
                    severity=Severity.HIGH,
                    title="RSA modulus reused with different public exponents",
                    detail=(
                        "Two or more keys share a modulus but differ in exponent. "
                        "Whoever holds one key pair can derive the private exponent "
                        "of the others (common-modulus attack)."
                    ),
                    sources=_cap(srcs[n], cfg),
                    fingerprints=sorted(fps)[: cfg.max_list],
                    data={"bits": n.bit_length(), "keys": len(fps)},
                )
            )
    return findings


# --------------------------------------------------------------------------
# 2. structurally broken RSA keys
# --------------------------------------------------------------------------


def check_rsa_structure(
    keys: list[KeyRecord], cfg: AuditConfig
) -> tuple[list[Finding], set[int]]:
    """Per-key RSA structure checks.

    Returns the findings plus the set of moduli that should be left out of the
    batch-GCD step (they are already reported and would only add noise there).
    """
    by_mod: dict[int, list[KeyRecord]] = defaultdict(list)
    for k in keys:
        if k.algorithm == "rsa" and k.modulus is not None:
            by_mod[k.modulus].append(k)

    classes: dict[str, list[KeyRecord]] = defaultdict(list)
    excluded: set[int] = set()
    fermat_dist: dict[int, int] = {}

    for n, ks in by_mod.items():
        if n % 2 == 0:
            classes["even"].extend(ks)
            excluded.add(n)
            continue
        if nt.has_small_factor(n, cfg.small_prime_limit):
            classes["small-factor"].extend(ks)
            excluded.add(n)
            continue
        if nt.is_perfect_square(n):
            classes["square"].extend(ks)
            excluded.add(n)
            continue
        fac = nt.fermat_factor(n, cfg.fermat_iterations)
        if fac is not None:
            classes["close-primes"].extend(ks)
            fermat_dist[n] = (fac[1] - fac[0]).bit_length()
        if n.bit_length() < 1024:
            classes["tiny"].extend(ks)
        elif n.bit_length() < cfg.min_rsa_bits - 8:
            classes["short"].extend(ks)

    for k in keys:
        if k.algorithm != "rsa" or k.exponent is None:
            continue
        if k.exponent < 3 or k.exponent % 2 == 0:
            classes["bad-exponent"].append(k)
        elif k.exponent < 65537:
            classes["low-exponent"].append(k)

    spec = {
        "even": (
            Severity.CRITICAL,
            "RSA modulus is even",
            "The modulus is divisible by 2, so it is trivially factored. "
            "This is a generation bug, not a weak-but-valid key.",
        ),
        "small-factor": (
            Severity.CRITICAL,
            "RSA modulus has a small prime factor",
            f"The modulus has a prime factor below 2^{cfg.small_prime_limit.bit_length() - 1}"
            ", so it is trivially factored. A healthy generator never emits this.",
        ),
        "square": (
            Severity.CRITICAL,
            "RSA modulus is a perfect square (p = q)",
            "Both primes are identical. The generator drew the same value twice, "
            "which points to a stuck or exhausted random source.",
        ),
        "close-primes": (
            Severity.CRITICAL,
            "RSA primes are close together (Fermat-factorable)",
            "The modulus was factored by Fermat's method within a small bounded "
            "search. The two primes share most of their leading bits, which is what "
            "happens when the second prime is derived from the first or both come "
            "from a poor random source. The private key is recoverable by anyone.",
        ),
        "tiny": (
            Severity.CRITICAL,
            "RSA key shorter than 1024 bits",
            "Keys this short can be factored with modest resources.",
        ),
        "short": (
            Severity.HIGH,
            f"RSA key shorter than {cfg.min_rsa_bits} bits",
            "Below current minimum-strength recommendations.",
        ),
        "bad-exponent": (
            Severity.HIGH,
            "Invalid RSA public exponent (even or < 3)",
            "A valid RSA exponent must be odd and at least 3.",
        ),
        "low-exponent": (
            Severity.LOW,
            "Low RSA public exponent (< 65537)",
            "Legal, but 65537 is the standard choice; small exponents tend to "
            "indicate legacy or hand-rolled key generation.",
        ),
    }

    findings: list[Finding] = []
    for cls, ks in classes.items():
        sev, title, detail = spec[cls]
        uniq = {k.fingerprint for k in ks}
        data: dict = {"count": len(uniq)}
        if cls == "close-primes":
            dists = [fermat_dist[k.modulus] for k in ks if k.modulus in fermat_dist]
            data["log2_prime_distance_max"] = max(dists)
        findings.append(
            Finding(
                check=f"rsa-{cls}",
                severity=sev,
                title=f"{title} ({len(uniq)} key{'s' if len(uniq) != 1 else ''})",
                detail=detail,
                sources=_cap((k.source for k in ks), cfg),
                fingerprints=_cap(uniq, cfg),
                data=data,
            )
        )
    return findings, excluded


def check_roca(keys: list[KeyRecord], cfg: AuditConfig) -> list[Finding]:
    """Keys generated by Infineon RSALib (ROCA, CVE-2017-15361).

    Unlike the other RSA checks this one names a cause: the fingerprint is
    specific to one library, used in Infineon TPMs, smart cards and security
    tokens (for example YubiKey 4 before firmware 4.3.5) manufactured before
    the 2017 fix.
    """
    hits: dict[str, list[KeyRecord]] = defaultdict(list)
    seen: dict[int, bool] = {}
    for k in keys:
        if k.algorithm != "rsa" or k.modulus is None:
            continue
        if k.modulus not in seen:
            seen[k.modulus] = nt.roca_fingerprint(k.modulus)
        if seen[k.modulus]:
            hits[k.fingerprint].append(k)
    if not hits:
        return []
    ks = [k for group in hits.values() for k in group]
    max_bits = max(k.bits or 0 for k in ks)
    # Factoring cost (paper): 512-bit minutes, 1024-bit CPU-days, 2048-bit
    # tens of CPU-years: practical for a motivated attacker at every size.
    sev = Severity.CRITICAL if max_bits <= 1024 else Severity.HIGH
    return [
        Finding(
            check="rsa-roca",
            severity=sev,
            title=f"RSA key(s) generated by Infineon RSALib (ROCA) ({len(hits)} key(s))",
            detail=(
                "The modulus has the residue structure of primes made by the "
                "Infineon RSALib (CVE-2017-15361). Such keys can be factored with "
                "Coppersmith's method at a cost far below a normal key of the same size."
            ),
            sources=_cap((k.source for k in ks), cfg),
            fingerprints=_cap(hits, cfg),
            data={"count": len(hits), "bits_max": max_bits,
                  "cause": "Infineon RSALib (CVE-2017-15361)"},
        )
    ]


# --------------------------------------------------------------------------
# 3. shared prime factors across the fleet (batch GCD)
# --------------------------------------------------------------------------


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def check_shared_factors(
    keys: list[KeyRecord], cfg: AuditConfig, excluded: set[int]
) -> list[Finding]:
    by_mod: dict[int, list[KeyRecord]] = defaultdict(list)
    for k in keys:
        if k.algorithm == "rsa" and k.modulus is not None and k.modulus not in excluded:
            by_mod[k.modulus].append(k)
    moduli = sorted(by_mod)  # distinct, deterministic order
    if len(moduli) < 2:
        return []
    if not nt.HAVE_GMPY2 and len(moduli) > PURE_PYTHON_WARN_AT:
        warnings.warn(
            f"{len(moduli)} RSA moduli without gmpy2: the shared-prime step will be "
            "extremely slow (measured: ~6 minutes for 5,000 moduli, growing "
            "quadratically). Install gmpy2 (pip install gmpy2).",
            RuntimeWarning,
            stacklevel=2,
        )

    g = nt.batch_gcd(moduli)
    flagged = [i for i, x in enumerate(g) if x > 1]
    if not flagged:
        return []

    uf = _UnionFind(len(moduli))
    # g < N: for a two-prime modulus g is exactly the one shared prime.
    prime_groups: dict[int, list[int]] = defaultdict(list)
    full: list[int] = []
    for i in flagged:
        if g[i] < moduli[i]:
            prime_groups[g[i]].append(i)
        else:
            full.append(i)  # both factors shared (possibly with different peers)
    for idxs in prime_groups.values():
        for j in idxs[1:]:
            uf.union(idxs[0], j)
    for i in full:
        for p, idxs in prime_groups.items():
            if moduli[i] % p == 0:
                uf.union(i, idxs[0])
    for a in range(len(full)):
        for b in range(a + 1, len(full)):
            if nt.gcd(moduli[full[a]], moduli[full[b]]) > 1:
                uf.union(full[a], full[b])

    clusters: dict[int, list[int]] = defaultdict(list)
    for i in flagged:
        clusters[uf.find(i)].append(i)

    findings: list[Finding] = []
    for members in sorted(clusters.values(), key=len, reverse=True):
        ks = [k for i in members for k in by_mod[moduli[i]]]
        fps = {k.fingerprint for k in ks}
        findings.append(
            Finding(
                check="shared-prime",
                severity=Severity.CRITICAL,
                title=f"{len(members)} RSA keys share prime factors",
                detail=(
                    "These moduli have a nontrivial common divisor, so every one of "
                    "them can be factored from public data alone with a gcd "
                    "computation. Independent keys never do this unless their random "
                    "source repeated its state while generating the primes (typically "
                    "low entropy at first boot). Treat every key in this group as "
                    "compromised and re-issue after fixing the entropy source."
                ),
                sources=_cap((k.source for k in ks), cfg),
                fingerprints=_cap(fps, cfg),
                data={
                    "moduli": len(members),
                    "keys": len(fps),
                    "bits": max(moduli[i].bit_length() for i in members),
                },
            )
        )
    return findings


# --------------------------------------------------------------------------
# 4. ECDSA nonce failures
# --------------------------------------------------------------------------


def check_ecdsa(sigs: list[SignatureRecord], cfg: AuditConfig) -> list[Finding]:
    findings: list[Finding] = []

    # Distinct (signer, r, s) triples only: the same certificate seen twice is
    # one signature, not a repeated nonce.
    uniq: dict[tuple[str, int, int], SignatureRecord] = {}
    for s in sigs:
        uniq.setdefault((s.pub_fingerprint, s.r, s.s), s)
    sigs_u = list(uniq.values())

    by_signer_r: dict[tuple[str, int], list[SignatureRecord]] = defaultdict(list)
    by_r: dict[int, list[SignatureRecord]] = defaultdict(list)
    for s in sigs_u:
        by_signer_r[(s.pub_fingerprint, s.r)].append(s)
        by_r[s.r].append(s)

    same_key: dict[str, list[SignatureRecord]] = defaultdict(list)
    for (signer, _r), group in by_signer_r.items():
        if len(group) > 1:
            same_key[signer].extend(group)
    for signer, group in same_key.items():
        findings.append(
            Finding(
                check="ecdsa-nonce-reuse",
                severity=Severity.CRITICAL,
                title="ECDSA nonce reused under one key",
                detail=(
                    "Two different signatures by the same key carry the same r, so "
                    "they used the same per-signature nonce k. From two such "
                    "signatures and their message hashes the private key follows by "
                    "simple algebra. Treat this key as compromised."
                ),
                sources=_cap((s.source for s in group), cfg),
                fingerprints=[signer],
                data={"signatures": len(group)},
            )
        )

    cross: list[tuple[int, list[SignatureRecord]]] = []
    for r, group in by_r.items():
        signers = {s.pub_fingerprint for s in group}
        if len(signers) > 1:
            cross.append((r, group))
    if cross:
        involved = [s for _r, grp in cross for s in grp]
        findings.append(
            Finding(
                check="ecdsa-shared-r",
                severity=Severity.HIGH,
                title=f"{len(cross)} ECDSA r value(s) repeated across different keys",
                detail=(
                    "Signatures made by different keys have the same r. A random "
                    "nonce collides with probability about 2^-256, so this means the "
                    "devices drew the same nonce: their random generators were in the "
                    "same state. This does not by itself reveal a key, but it shows "
                    "the generators are not independent, and any device whose own "
                    "signatures also repeat a nonce becomes fully exposed."
                ),
                sources=_cap((s.source for s in involved), cfg),
                fingerprints=_cap({s.pub_fingerprint for s in involved}, cfg),
                data={"repeated_r": len(cross)},
            )
        )

    # Biased nonces: r far below the group order has probability 2^-32 by chance.
    biased: dict[str, list[SignatureRecord]] = defaultdict(list)
    for s in sigs_u:
        order_bits = CURVE_ORDER_BITS.get(s.curve or "")
        if order_bits and s.r.bit_length() <= order_bits - 32:
            biased[s.pub_fingerprint].append(s)
    for signer, group in biased.items():
        findings.append(
            Finding(
                check="ecdsa-biased-nonce",
                severity=Severity.HIGH,
                title="ECDSA signature with implausibly small r",
                detail=(
                    "r is at least 32 bits shorter than the group order, which "
                    "happens by chance with probability 2^-32 per signature. Biased "
                    "nonces can be exploited with lattice methods given enough "
                    "signatures. Check the nonce generator."
                ),
                sources=_cap((s.source for s in group), cfg),
                fingerprints=[signer],
                data={"signatures": len(group)},
            )
        )
    return findings


# --------------------------------------------------------------------------
# 5. certificate serial numbers
# --------------------------------------------------------------------------


def _after_rule(c: KeyRecord) -> bool:
    """True if the certificate was issued under the 64-bit serial rule."""
    if not c.cert_not_before:
        return True
    try:
        return dt.datetime.fromisoformat(c.cert_not_before) >= SERIAL_RULE_START
    except ValueError:
        return True


def check_serials(keys: list[KeyRecord], cfg: AuditConfig) -> list[Finding]:
    certs: dict[str, KeyRecord] = {}
    for k in keys:
        if k.cert_fingerprint and k.cert_serial is not None:
            certs.setdefault(k.cert_fingerprint, k)

    by_issuer: dict[str, list[KeyRecord]] = defaultdict(list)
    for c in certs.values():
        by_issuer[c.cert_issuer or ""].append(c)

    findings: list[Finding] = []
    short: dict[str, KeyRecord] = {}
    invalid: list[KeyRecord] = []
    exempt_old = 0

    for issuer, cs in by_issuer.items():
        # Same (issuer, serial) on different certificates.
        by_serial: dict[int, list[KeyRecord]] = defaultdict(list)
        for c in cs:
            by_serial[c.cert_serial].append(c)  # type: ignore[index]
        for serial, group in by_serial.items():
            if len(group) < 2:
                continue
            nkeys = len({c.fingerprint for c in group})
            strong = serial.bit_length() >= 64 and nkeys >= 2
            findings.append(
                Finding(
                    check="serial-collision",
                    severity=Severity.HIGH if strong else Severity.MEDIUM,
                    title=f"Serial reused by {len(group)} certificates of one issuer",
                    detail=(
                        "Certificate serials must be unique per issuer. A collision "
                        "among long serials is overwhelmingly a repeated random "
                        "state, not chance."
                        if strong
                        else "Certificate serials must be unique per issuer; short or "
                        "constant serials usually mean a template or counter reset."
                    ),
                    sources=_cap((c.source for c in group), cfg),
                    fingerprints=_cap({c.fingerprint for c in group}, cfg),
                    data={
                        "issuer": issuer,
                        "serial_bits": serial.bit_length(),
                        "certificates": len(group),
                        "distinct_keys": nkeys,
                    },
                )
            )

        positive = [c for c in cs if c.cert_serial > 0]  # type: ignore[operator]
        invalid.extend(c for c in cs if c.cert_serial <= 0)  # type: ignore[operator]
        modern = [c for c in positive if _after_rule(c)]
        exempt_old += sum(
            1 for c in positive if not _after_rule(c) and c.cert_serial.bit_length() < 64  # type: ignore[union-attr]
        )

        # Clearly too short, whatever the issuer does elsewhere.
        for c in modern:
            if c.cert_serial.bit_length() < cfg.serial_floor_bits:  # type: ignore[union-attr]
                short[c.cert_fingerprint] = c  # type: ignore[index]
        # An issuer whose serials never exceed 63 bits over many certificates:
        # random 64-bit serials would show a 64-bit one about every other time.
        if (
            len(modern) >= cfg.serial_issuer_min
            and max(c.cert_serial.bit_length() for c in modern) <= 63  # type: ignore[union-attr]
        ):
            for c in modern:
                short[c.cert_fingerprint] = c  # type: ignore[index]

        # Population statistics for issuers with enough certificates.
        serials = sorted({c.cert_serial for c in positive})  # type: ignore[misc]
        if len(serials) >= cfg.serial_min_samples:
            free_bits = bin(reduce(or_, (s ^ serials[0] for s in serials))).count("1")
            gaps = [b - a for a, b in zip(serials, serials[1:])]
            sequential = statistics.median(gaps) < 2**32
            if free_bits < 64 or sequential:
                findings.append(
                    Finding(
                        check="serial-predictable",
                        severity=Severity.LOW,
                        title=f"Predictable serials from one issuer ({len(serials)} certs)",
                        detail=(
                            "Serials are "
                            + ("sequential" if sequential else "low-variability")
                            + ". Acceptable for a private CA that wants counters; "
                            "for publicly trusted TLS certificates the CA/Browser "
                            "Forum requires at least 64 bits of CSPRNG output."
                        ),
                        sources=_cap((c.source for c in cs), cfg),
                        data={
                            "issuer": issuer,
                            "certificates": len(serials),
                            "varying_bits": free_bits,
                            "sequential": sequential,
                            "median_gap_bits": int(statistics.median(gaps)).bit_length(),
                        },
                    )
                )

    if short:
        findings.append(
            Finding(
                check="serial-short",
                severity=Severity.MEDIUM,
                title=f"{len(short)} certificate(s) with serial shorter than 64 bits",
                detail=(
                    "Short serials leave little room for unpredictability. Since "
                    "2016-09-30 the CA/Browser Forum baseline requires at least 64 "
                    "bits of CSPRNG output for publicly trusted TLS certificates. "
                    "Certificates issued before that date are not judged."
                ),
                sources=_cap((c.source for c in short.values()), cfg),
                data={"count": len(short), "exempt_before_2016_09_30": exempt_old},
            )
        )

    if invalid:
        modern_invalid = [c for c in invalid if _after_rule(c)]
        findings.append(
            Finding(
                check="serial-invalid",
                severity=Severity.LOW if modern_invalid else Severity.INFO,
                title=f"{len(invalid)} certificate(s) with a serial that is not a positive integer",
                detail=(
                    "RFC 5280 requires the serial number to be a positive integer. "
                    "Old trust-store roots sometimes violate this; it is harmless "
                    "there but a defect in a recently issued certificate."
                ),
                sources=_cap((c.source for c in invalid), cfg),
                data={"count": len(invalid), "issued_after_2016_09_30": len(modern_invalid)},
            )
        )
    return findings

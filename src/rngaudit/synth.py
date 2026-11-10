"""Synthetic fleets with *known, planted* randomness failures.

Used by the test-suite and by ``rngaudit demo`` so that every claim the tool
makes can be checked against ground truth. Everything here is deterministic
given a seed and **not secure**: it uses ``random.Random`` and a textbook
ECDSA with caller-chosen nonces. Never use it to generate real keys.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import random
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from . import numtheory as nt

# --------------------------------------------------------------------------
# P-256 arithmetic with chosen nonces (for planting nonce failures)
# --------------------------------------------------------------------------

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_A = _P - 3
_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _mul(k: int, point=_G):
    result, addend = None, point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def ecdsa_sign_p256(d: int, message: bytes, k: int) -> tuple[int, int]:
    """Textbook ECDSA over P-256/SHA-256 with a caller-chosen nonce ``k``."""
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    r = _mul(k)[0] % _N
    s = pow(k, -1, _N) * (z + r * d) % _N
    return r, s


# --------------------------------------------------------------------------
# DER surgery: re-sign a certificate with a chosen nonce
# --------------------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv_header(der: bytes, pos: int) -> tuple[int, int]:
    """Return (header length, content length) of the TLV at ``pos``."""
    first = der[pos + 1]
    if first < 0x80:
        return 2, first
    nb = first & 0x7F
    return 2 + nb, int.from_bytes(der[pos + 2 : pos + 2 + nb], "big")


def resign_with_nonce(cert: x509.Certificate, d: int, k: int) -> x509.Certificate:
    """Replace the signature of a P-256/SHA-256 certificate with one made by
    private scalar ``d`` using nonce ``k``."""
    der = cert.public_bytes(serialization.Encoding.DER)
    tbs = cert.tbs_certificate_bytes
    hdr, _ = _tlv_header(der, 0)
    assert der[hdr : hdr + len(tbs)] == tbs
    pos = hdr + len(tbs)
    h2, l2 = _tlv_header(der, pos)
    sigalg = der[pos : pos + h2 + l2]
    r, s = ecdsa_sign_p256(d, tbs, k)
    sig = encode_dss_signature(r, s)
    bits = b"\x03" + _der_len(len(sig) + 1) + b"\x00" + sig
    body = tbs + sigalg + bits
    return x509.load_der_x509_certificate(b"\x30" + _der_len(len(body)) + body)


# --------------------------------------------------------------------------
# primes and RSA public keys
# --------------------------------------------------------------------------

_SMALL = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67]


def _is_probable_prime(n: int, rng: random.Random, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for p in _SMALL + [2]:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n: int, rng: random.Random) -> int:
    """Smallest probable prime >= n."""
    n |= 1
    if nt.HAVE_GMPY2:
        import gmpy2

        return int(gmpy2.next_prime(n - 1))
    while not _is_probable_prime(n, rng):
        n += 2
    return n


def rand_prime(bits: int, rng: random.Random) -> int:
    while True:
        cand = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        p = next_prime(cand, rng)
        if p.bit_length() == bits:
            return p


def rsa_public_pem(n: int, e: int = 65537) -> bytes:
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    return pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


# --------------------------------------------------------------------------
# certificates
# --------------------------------------------------------------------------

_T0 = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(
    subject_cn: str,
    public_key,
    signer,
    issuer_cn: str | None = None,
    serial: int | None = None,
) -> x509.Certificate:
    """A certificate for ``public_key`` signed by ``signer`` (a real private key).

    ``issuer_cn=None`` produces a self-signed certificate (issuer == subject).
    """
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(_name(issuer_cn or subject_cn))
        .public_key(public_key)
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(_T0)
        .not_valid_after(_T0 + dt.timedelta(days=3650))
    )
    return builder.sign(signer, hashes.SHA256())


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


# --------------------------------------------------------------------------
# fleet
# --------------------------------------------------------------------------


def build_fleet(
    out: str | Path,
    seed: int = 1,
    healthy: int = 16,
    rsa_bits: int = 2048,
) -> dict:
    """Write a fleet with planted failures; return the ground-truth manifest.

    The manifest maps each planted failure to the files that carry it.
    """
    rng = random.Random(seed)
    out = Path(out)
    half = rsa_bits // 2
    ca = ec.generate_private_key(ec.SECP256R1())
    manifest: dict[str, list[str]] = {}

    def put(rel: str, data: bytes) -> str:
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return rel

    def rsa_device(rel: str, n: int, cn: str, **kw) -> str:
        pub = rsa.RSAPublicNumbers(65537, n).public_key()
        return put(rel, _pem(make_cert(cn, pub, ca, issuer_cn="Fleet CA", **kw)))

    # ---- healthy devices ------------------------------------------------
    for i in range(healthy):
        n = rand_prime(half, rng) * rand_prime(half, rng)
        rsa_device(f"healthy/rsa-{i:03d}.pem", n, f"rsa-{i:03d}")
    for i in range(healthy // 2):
        key = ec.generate_private_key(ec.SECP256R1())
        put(f"healthy/ec-{i:03d}.pem", _pem(make_cert(f"ec-{i:03d}", key.public_key(), key)))
    hosts = []
    for i in range(healthy // 2):
        pub = ed25519.Ed25519PrivateKey.generate().public_key()
        line = pub.public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        ).decode()
        hosts.append(f"host-{i:03d}.example {line}")
    put("healthy/known_hosts", ("\n".join(hosts) + "\n").encode())

    # ---- A. shared primes (low boot entropy) ------------------------------
    p_shared = rand_prime(half, rng)
    names = []
    for i in range(3):
        names.append(rsa_device(f"flawed/sharedprime-{i}.pem",
                                p_shared * rand_prime(half, rng), f"sp-{i}"))
    # a pair that share *both* primes with different peers (the g == N case)
    pa, pb, pc, pd = (rand_prime(half, rng) for _ in range(4))
    names.append(rsa_device("flawed/sharedprime-x.pem", pa * pb, "sp-x"))
    names.append(rsa_device("flawed/sharedprime-y.pem", pa * pc, "sp-y"))
    names.append(rsa_device("flawed/sharedprime-z.pem", pb * pc, "sp-z"))
    manifest["shared-prime"] = names

    # ---- B. one factory-default key on many devices -----------------------
    default_key = ec.generate_private_key(ec.SECP256R1())
    default_cert = _pem(make_cert("localhost", default_key.public_key(), default_key))
    manifest["duplicate-key"] = [
        put(f"flawed/default-{i:02d}.pem", default_cert) for i in range(12)
    ]

    # ---- C. structurally broken RSA --------------------------------------
    pe = rand_prime(half, rng)
    manifest["rsa-even"] = [rsa_device("flawed/even.pem", 2 * rand_prime(rsa_bits - 1, rng), "even")]
    manifest["rsa-small-factor"] = [
        rsa_device("flawed/smallfactor.pem", 65521 * rand_prime(rsa_bits - 16, rng), "smallfactor")
    ]
    manifest["rsa-square"] = [rsa_device("flawed/square.pem", pe * pe, "square")]
    p0 = rand_prime(half, rng)
    q0 = next_prime(p0 + (1 << 40), rng)
    manifest["rsa-close-primes"] = [rsa_device("flawed/closeprimes.pem", p0 * q0, "close")]
    manifest["rsa-short"] = [
        rsa_device("flawed/short1024.pem", rand_prime(512, rng) * rand_prime(512, rng), "short")
    ]

    # ---- D. ECDSA nonce failures inside certificates ----------------------
    shared_k = rng.randrange(2, _N)
    d_names = []
    for i in range(2):  # two *different* devices, same nonce
        key = ec.generate_private_key(ec.SECP256R1())
        cert = make_cert(f"samek-{i}", key.public_key(), key)
        d = key.private_numbers().private_value
        d_names.append(put(f"flawed/samenonce-{i}.pem", _pem(resign_with_nonce(cert, d, shared_k))))
    manifest["ecdsa-shared-r"] = d_names

    key = ec.generate_private_key(ec.SECP256R1())
    d = key.private_numbers().private_value
    k = rng.randrange(2, _N)
    bundle = b""
    for _ in range(2):  # one device, two certificates in one file, same nonce
        cert = make_cert("reuse", key.public_key(), key, serial=rng.getrandbits(100))
        bundle += _pem(resign_with_nonce(cert, d, k))
    manifest["ecdsa-nonce-reuse"] = [put("flawed/nonce-reuse.pem", bundle)]

    # ---- E. certificate serials ------------------------------------------
    ks = [ec.generate_private_key(ec.SECP256R1()).public_key() for _ in range(3)]
    manifest["serial-short"] = [
        put(f"flawed/legacy-{i}.pem", _pem(make_cert(f"legacy-{i}", ks[i], ca, "Legacy CA", serial=7)))
        for i in range(3)
    ]
    long_serial = rng.getrandbits(127) | (1 << 126)
    ks2 = [ec.generate_private_key(ec.SECP256R1()).public_key() for _ in range(2)]
    manifest["serial-collision"] = [
        put(f"flawed/prov-{i}.pem", _pem(make_cert(f"prov-{i}", ks2[i], ca, "Provisioning CA", serial=long_serial)))
        for i in range(2)
    ]

    # ---- F. raw ECDSA signatures (JSON Lines) ------------------------------
    lines = []
    for dev in range(5):
        dd = rng.randrange(2, _N)
        for m in range(4):
            msg = f"dev{dev}-msg{m}".encode()
            r, s = ecdsa_sign_p256(dd, msg, rng.randrange(2, _N))
            lines.append({"key_id": f"sigdev-{dev}", "r": hex(r), "s": hex(s),
                          "z": hex(int.from_bytes(hashlib.sha256(msg).digest(), "big"))})
    dd = rng.randrange(2, _N)
    kk = rng.randrange(2, _N)
    for m in range(2):
        msg = f"leaky-{m}".encode()
        r, s = ecdsa_sign_p256(dd, msg, kk)
        lines.append({"key_id": "sigdev-leaky", "r": hex(r), "s": hex(s),
                      "z": hex(int.from_bytes(hashlib.sha256(msg).digest(), "big"))})
    put("signatures.jsonl", ("\n".join(json.dumps(x) for x in lines) + "\n").encode())
    manifest["ecdsa-nonce-reuse-jsonl"] = ["signatures.jsonl"]

    return manifest

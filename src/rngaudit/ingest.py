"""Reading keys, certificates and signatures from files.

Supported inputs
----------------
* PEM files / bundles: certificates, public keys, CSRs (private keys are
  deliberately skipped: an audit tool must not need them).
* DER files: certificates or SubjectPublicKeyInfo.
* OpenSSH public keys (``authorized_keys`` / ``known_hosts`` style lines).
* JSON Lines of ECDSA signatures (``--sigs``).
* Snapshots written by ``rngaudit collect`` (keys, certificates and
  signatures gathered from TLS / SSH servers, labelled with the host).

ECDSA signatures embedded in certificates are harvested too: two devices that
signed with the same nonce is the classic fingerprint of an identical RNG
state, and certificates are the most widely available source of signatures.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import SignatureAlgorithmOID

from . import pqc
from .model import KeyRecord, SignatureRecord

_PEM_BLOCK = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL
)
_SSH_PREFIXES = ("ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-")

_ECDSA_SIG_OIDS = {
    SignatureAlgorithmOID.ECDSA_WITH_SHA1,
    SignatureAlgorithmOID.ECDSA_WITH_SHA224,
    SignatureAlgorithmOID.ECDSA_WITH_SHA256,
    SignatureAlgorithmOID.ECDSA_WITH_SHA384,
    SignatureAlgorithmOID.ECDSA_WITH_SHA512,
}


@dataclass
class Corpus:
    """Everything read from the inputs."""

    keys: list[KeyRecord] = field(default_factory=list)
    signatures: list[SignatureRecord] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    files_read: int = 0
    # Paths skipped because they resolve to a file that was already read
    # (symlinks, e.g. the hash-named links in /etc/ssl/certs).
    files_skipped: int = 0
    # Labels per holder id ("host:<name>"), e.g. the SSH software version.
    host_info: dict[str, dict[str, str]] = field(default_factory=dict)
    # Network endpoints seen by ``collect``: "ssh://host:22" -> what they offer.
    endpoints: dict[str, dict] = field(default_factory=dict)

    def extend(self, other: "Corpus") -> None:
        self.keys.extend(other.keys)
        self.signatures.extend(other.signatures)
        self.errors.extend(other.errors)
        self.files_read += other.files_read
        self.files_skipped += other.files_skipped
        for h, info in other.host_info.items():
            self.host_info.setdefault(h, {}).update(info)
        for e, info in other.endpoints.items():
            self.endpoints.setdefault(e, {}).update(info)


@contextmanager
def _quiet():
    """Old trust-store certificates trigger cryptography deprecation warnings
    (for example serial numbers that are not positive). They are reported as
    findings instead, so the raw warning is noise."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        yield


# --------------------------------------------------------------------------
# Key conversion
# --------------------------------------------------------------------------


def spki_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def _cert_ctx(cert: x509.Certificate) -> dict:
    with _quiet():
        return {
            "cert_serial": cert.serial_number,
            "cert_issuer": cert.issuer.rfc4514_string(),
            "cert_subject": cert.subject.rfc4514_string(),
            "cert_not_before": cert.not_valid_before_utc.isoformat(),
            "cert_not_after": cert.not_valid_after_utc.isoformat(),
            "cert_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            "cert_sig_oid": cert.signature_algorithm_oid.dotted_string,
        }


def spki_record(spki_der: bytes, source: str, cert: x509.Certificate | None = None) -> KeyRecord:
    """A record for a key known only by its DER SubjectPublicKeyInfo.

    Used for algorithms the ``cryptography`` package cannot load (SLH-DSA, or
    ML-DSA on older versions): such keys still belong in the inventory and in
    the duplicate-key check.
    """
    oid = pqc.spki_algorithm_oid(spki_der)
    family, param = pqc.family_for_oid(oid)
    return KeyRecord(
        source=source, algorithm=family, fingerprint=hashlib.sha256(spki_der).hexdigest(),
        key_oid=oid, param=param, **(_cert_ctx(cert) if cert is not None else {}),
    )


def key_record(
    public_key,
    source: str,
    cert: x509.Certificate | None = None,
) -> KeyRecord:
    """Convert a ``cryptography`` public key (plus optional cert) to a record."""
    fp = spki_fingerprint(public_key)
    ctx: dict = _cert_ctx(cert) if cert is not None else {}

    if isinstance(public_key, rsa.RSAPublicKey):
        nums = public_key.public_numbers()
        return KeyRecord(
            source=source,
            algorithm="rsa",
            fingerprint=fp,
            bits=nums.n.bit_length(),
            modulus=nums.n,
            exponent=nums.e,
            **ctx,
        )
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return KeyRecord(
            source=source,
            algorithm="ec",
            fingerprint=fp,
            bits=public_key.curve.key_size,
            curve=public_key.curve.name,
            **ctx,
        )
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return KeyRecord(source=source, algorithm="ed25519", fingerprint=fp, bits=256, **ctx)
    if isinstance(public_key, ed448.Ed448PublicKey):
        return KeyRecord(source=source, algorithm="ed448", fingerprint=fp, bits=448, **ctx)
    if isinstance(public_key, dsa.DSAPublicKey):
        return KeyRecord(
            source=source,
            algorithm="dsa",
            fingerprint=fp,
            bits=public_key.key_size,
            **ctx,
        )
    spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    oid = pqc.spki_algorithm_oid(spki)
    family, param = pqc.family_for_oid(oid)
    return KeyRecord(source=source, algorithm=family, fingerprint=fp, key_oid=oid,
                     param=param, **ctx)


def _cert_signature(cert: x509.Certificate, source: str) -> SignatureRecord | None:
    """Harvest the ECDSA signature of a certificate, if it has one."""
    if cert.signature_algorithm_oid not in _ECDSA_SIG_OIDS:
        return None
    try:
        r, s = decode_dss_signature(cert.signature)
    except ValueError:
        return None
    curve = None
    if cert.issuer == cert.subject:
        # Self-signed (by convention): the signer is the certified key itself.
        pub = cert.public_key()
        signer = spki_fingerprint(pub)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            curve = pub.curve.name
    else:
        signer = "issuer:" + cert.issuer.rfc4514_string()
    return SignatureRecord(
        source=source, pub_fingerprint=signer, r=r, s=s, curve=curve
    )


def _add_cert(corpus: Corpus, cert: x509.Certificate, source: str) -> None:
    try:
        pub = cert.public_key()
    except Exception as exc:  # unsupported key type, malformed key ...
        try:
            corpus.keys.append(spki_record(
                pqc.cert_spki(cert.public_bytes(serialization.Encoding.DER)), source, cert))
        except Exception:
            corpus.errors.append((source, f"certificate public key: {exc}"))
            return
    else:
        corpus.keys.append(key_record(pub, source, cert))
    sig = _cert_signature(cert, source)
    if sig is not None:
        corpus.signatures.append(sig)


# --------------------------------------------------------------------------
# File parsers
# --------------------------------------------------------------------------


def _parse_pem(data: bytes, path: str, corpus: Corpus) -> None:
    for idx, match in enumerate(_PEM_BLOCK.finditer(data)):
        label = match.group(1).decode()
        block = match.group(0)
        source = f"{path}#{idx}"
        try:
            if label in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
                with _quiet():
                    cert = x509.load_pem_x509_certificate(block)
                    _add_cert(corpus, cert, source)
            elif label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
                try:
                    pub = serialization.load_pem_public_key(block)
                except Exception:
                    if label != "PUBLIC KEY":
                        raise
                    import base64

                    der = base64.b64decode(b"".join(match.group(2).split()))
                    corpus.keys.append(spki_record(der, source))
                else:
                    corpus.keys.append(key_record(pub, source))
            elif label == "CERTIFICATE REQUEST" or label == "NEW CERTIFICATE REQUEST":
                csr = x509.load_pem_x509_csr(block)
                corpus.keys.append(key_record(csr.public_key(), source))
            elif "PRIVATE KEY" in label:
                corpus.errors.append((source, "private key skipped (never read)"))
            # Anything else (DH PARAMETERS, ...) is silently irrelevant.
        except Exception as exc:
            corpus.errors.append((source, f"{label}: {exc}"))


def _parse_ssh_lines(text: str, path: str, corpus: Corpus) -> bool:
    found = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        idx = next(
            (i for i, t in enumerate(tokens) if t.startswith(_SSH_PREFIXES)), None
        )
        if idx is None or idx + 1 >= len(tokens):
            continue
        found = True
        host = tokens[0] if idx == 1 else None
        source = f"{path}:{lineno}" + (f" [{host}]" if host else "")
        try:
            pub = serialization.load_ssh_public_key(
                f"{tokens[idx]} {tokens[idx + 1]}".encode()
            )
            corpus.keys.append(key_record(pub, source))
        except Exception as exc:
            corpus.errors.append((source, f"ssh key: {exc}"))
    return found


def _parse_der(data: bytes, path: str, corpus: Corpus) -> bool:
    try:
        with _quiet():
            _add_cert(corpus, x509.load_der_x509_certificate(data), path)
        return True
    except Exception:
        pass
    try:
        corpus.keys.append(key_record(serialization.load_der_public_key(data), path))
        return True
    except Exception:
        return False


def load_file(path: Path) -> Corpus:
    corpus = Corpus(files_read=1)
    name = str(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        corpus.errors.append((name, f"unreadable: {exc}"))
        corpus.files_read = 0
        return corpus

    if data[:1] == b"{" and is_snapshot_header(data.split(b"\n", 1)[0]):
        _parse_snapshot(data, name, corpus)
        return corpus

    if b"-----BEGIN" in data:
        _parse_pem(data, name, corpus)
        return corpus

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None and _parse_ssh_lines(text, name, corpus):
        return corpus

    if not _parse_der(data, name, corpus) and path.suffix.lower() in (
        ".der",
        ".crt",
        ".cer",
        ".pem",
        ".pub",
    ):
        corpus.errors.append((name, "no key or certificate recognised"))
    return corpus


def iter_files(paths: Iterable[str | Path]) -> Iterator[Path]:
    for p in map(Path, paths):
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file():
                    yield child
        else:
            yield p


# OpenSSL "c_rehash" links are named <8 hex digits>.<n>
_HASH_LINK = re.compile(r"^[0-9a-f]{8}\.\d+$")


def unique_files(paths: Iterable[str | Path]) -> tuple[list[Path], int]:
    """Collapse paths that resolve to the same file.

    ``/etc/ssl/certs`` holds every certificate twice or more (a hash-named
    link plus a named link, both pointing at one file). Counting each path as a
    separate device would flag every CA key as "shared". Of several aliases the
    most readable one is kept: not a hash link, then the shortest path.
    Returns the files and the number of aliases dropped.
    """
    groups: dict[str, list[Path]] = {}
    for f in iter_files(paths):
        try:
            real = os.path.realpath(f)
        except OSError:
            real = str(f)
        groups.setdefault(real, []).append(f)

    def preference(p: Path):
        return (bool(_HASH_LINK.match(p.name)), len(str(p)), str(p))

    chosen = [min(aliases, key=preference) for aliases in groups.values()]
    skipped = sum(len(a) for a in groups.values()) - len(chosen)
    chosen.sort(key=lambda p: str(p))
    return chosen, skipped


def load_paths(paths: Iterable[str | Path]) -> Corpus:
    corpus = Corpus()
    files, skipped = unique_files(paths)
    for f in files:
        corpus.extend(load_file(f))
    corpus.files_skipped = skipped
    return corpus


# --------------------------------------------------------------------------
# Signature JSONL
# --------------------------------------------------------------------------


def _int(value) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    return int(text, 16) if text.startswith("0x") else int(text, 16)


def _signer_id(obj: dict) -> str:
    if "pub" in obj:
        pub = str(obj["pub"])
        if pub.lstrip().startswith("-----BEGIN"):
            return spki_fingerprint(serialization.load_pem_public_key(pub.encode()))
        try:
            return hashlib.sha256(bytes.fromhex(pub)).hexdigest()  # hex SPKI DER
        except ValueError:
            return pub
    if "key_id" in obj:
        return str(obj["key_id"])
    raise ValueError("record needs 'pub' or 'key_id'")


def load_signatures(path: str | Path) -> Corpus:
    """Load ECDSA signatures from JSON Lines.

    Each line: ``{"key_id"|"pub": ..., "r": hex, "s": hex}`` or
    ``{"key_id"|"pub": ..., "sig": "<DER hex>"}``; optional ``z`` and ``source``.
    """
    corpus = Corpus(files_read=1)
    p = Path(path)
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        corpus.errors.append((str(p), f"unreadable: {exc}"))
        corpus.files_read = 0
        return corpus
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            continue
        source = f"{p}:{lineno}"
        try:
            obj = json.loads(line)
            if "sig" in obj:
                r, s = decode_dss_signature(bytes.fromhex(obj["sig"]))
            else:
                r, s = _int(obj["r"]), _int(obj["s"])
            z = _int(obj["z"]) if "z" in obj else None
            corpus.signatures.append(
                SignatureRecord(
                    source=obj.get("source", source),
                    pub_fingerprint=_signer_id(obj),
                    r=r,
                    s=s,
                    z=z,
                    curve=obj.get("curve"),
                )
            )
        except Exception as exc:
            corpus.errors.append((source, f"signature record: {exc}"))
    return corpus


# --------------------------------------------------------------------------
# Snapshots from ``rngaudit collect``
# --------------------------------------------------------------------------


def is_snapshot_header(first_line: bytes) -> bool:
    try:
        obj = json.loads(first_line)
    except ValueError:
        return False
    return isinstance(obj, dict) and obj.get("kind") == "meta" and obj.get("tool") == "rngaudit"


def _endpoint(proto: str, host: str, port) -> str:
    return f"{proto}://[{host}]:{port}" if ":" in host else f"{proto}://{host}:{port}"


def _parse_snapshot(data: bytes, path: str, corpus: Corpus) -> None:
    """Records carry the host they came from as a ``[host]`` label, so the
    host (not the snapshot file) is the holder of a leaf certificate or SSH
    host key. Chain certificates are stored once per snapshot and stay
    unlabelled: a CA certificate served by many hosts is not a shared key."""
    import base64

    for lineno, raw in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if lineno == 1 or not raw.strip():
            continue
        loc = f"{path}:{lineno}"
        try:
            obj = json.loads(raw)
            kind = obj.get("kind")
            host = obj.get("host")
            labelled = f"{loc} [{host}]" if host else loc
            if kind == "cert":
                with _quiet():
                    cert = x509.load_der_x509_certificate(base64.b64decode(obj["der"]))
                    _add_cert(corpus, cert, labelled if obj.get("role") == "leaf" else loc)
            elif kind == "sshkey":
                pub = serialization.load_ssh_public_key(obj["key"].encode())
                corpus.keys.append(key_record(pub, labelled))
            elif kind == "sig":
                corpus.signatures.append(
                    SignatureRecord(
                        source=labelled,
                        pub_fingerprint=str(obj["key_id"]),
                        r=_int(obj["r"]),
                        s=_int(obj["s"]),
                        z=_int(obj["z"]) if obj.get("z") else None,
                        curve=obj.get("curve"),
                    )
                )
            elif kind == "software" and host and obj.get("banner"):
                from .attribute import parse_ssh_banner

                corpus.host_info.setdefault("host:" + host, {}).update(
                    parse_ssh_banner(obj["banner"]))
                if "kex" in obj:
                    kex = [str(x) for x in obj["kex"]]
                    corpus.endpoints[_endpoint("ssh", host, obj.get("port", 22))] = {
                        "proto": "ssh", "host": host, "kex": kex,
                        "pq_kex": any(pqc.is_pq_ssh_kex(x) for x in kex)}
            elif kind == "tls-groups" and host:
                groups = {str(k): bool(v) for k, v in obj.get("groups", {}).items()}
                corpus.endpoints[_endpoint("tls", host, obj.get("port", 443))] = {
                    "proto": "tls", "host": host, "groups": groups,
                    "pq_kex": any(groups.values())}
            # "error" records describe the collection run, not the fleet.
        except Exception as exc:
            corpus.errors.append((loc, f"snapshot record: {exc}"))

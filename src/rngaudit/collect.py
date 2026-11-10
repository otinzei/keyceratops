"""``rngaudit collect``: gather keys, certificates and signatures from servers.

The result is a *snapshot*: JSON Lines that ``rngaudit scan`` reads like any
other input. Snapshots can be appended to over time; more signatures per
server make the nonce checks stronger.

Snapshot records (one JSON object per line)::

    {"kind": "meta", "tool": "rngaudit", "format": 1, ...}       first line
    {"kind": "cert", "host": H, "port": P, "proto": "tls", "role": "leaf"|"chain", "der": b64}
    {"kind": "sshkey", "host": H, "port": P, "key": "<type> <base64>"}
    {"kind": "sig", "host": H, "port": P, "proto": "tls12-ske"|"ssh-kex",
     "key_id": <SPKI SHA-256>, "r": hex, "s": hex, "z": hex|null, "curve": name}
    {"kind": "error", "host": H, "port": P, "proto": ..., "msg": text}

Only targets named explicitly are contacted: there is no address-range
expansion. Scan only systems you own or are authorised to test.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import __version__, net_ssh, net_tls
from .ingest import is_snapshot_header, spki_fingerprint

SNAPSHOT_FORMAT = 1
MAX_SAMPLES = 1000


@dataclass
class Target:
    proto: str  # "tls" | "ssh"
    host: str
    port: int
    sni: str | None = None

    @property
    def label(self) -> str:
        return f"{self.proto}://{_host_port(self.host, self.port)}"


def _host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def parse_target(spec: str) -> Target:
    """``tls://host[:port]``, ``ssh://host[:port]`` or ``host[:port]``.

    A bare ``host`` means both TLS (443) and SSH (22); see :func:`expand`.
    IPv6 literals go in brackets: ``ssh://[2001:db8::1]:2222``.
    """
    proto = "any"
    rest = spec.strip()
    if "://" in rest:
        proto, rest = rest.split("://", 1)
        proto = proto.lower()
        if proto not in ("tls", "https", "ssh"):
            raise ValueError(f"unknown scheme {proto!r} in {spec!r} (use tls:// or ssh://)")
        proto = "tls" if proto == "https" else proto
    rest = rest.rstrip("/")
    port: int | None = None
    if rest.startswith("["):
        end = rest.find("]")
        if end < 0:
            raise ValueError(f"bad IPv6 literal in {spec!r}")
        host, tail = rest[1:end], rest[end + 1 :]
        if tail.startswith(":"):
            port = int(tail[1:])
    elif rest.count(":") == 1:
        host, p = rest.split(":")
        port = int(p)
    else:
        host = rest
    if not host or any(c in host for c in "/ \t*"):
        raise ValueError(f"bad host in {spec!r}")
    if port is not None and not 0 < port < 65536:
        raise ValueError(f"bad port in {spec!r}")
    default = {"tls": 443, "ssh": 22}
    return Target(proto, host, port if port is not None else default.get(proto, 0))


def expand(specs: list[str]) -> list[Target]:
    out: list[Target] = []
    for spec in specs:
        t = parse_target(spec)
        if t.proto == "any":
            if t.port:
                raise ValueError(f"{spec!r}: give a scheme with a port (tls:// or ssh://)")
            out += [Target("tls", t.host, 443), Target("ssh", t.host, 22)]
        else:
            out.append(t)
    return out


def read_targets_file(path: str) -> list[str]:
    specs = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            specs.append(line)
    return specs


# --------------------------------------------------------------------------


@dataclass
class Summary:
    targets: int = 0
    reached: int = 0  # targets that answered with at least a key
    certs: int = 0
    ssh_keys: int = 0
    signatures: int = 0
    unverified: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)


class SnapshotWriter:
    """Appends records to a snapshot, never writing one certificate twice."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.seen_chain: set[str] = set()
        self.seen_leaf: set[tuple[str, str]] = set()
        self.seen_ssh: set[tuple[str, str]] = set()
        new = not path.exists() or path.stat().st_size == 0
        if not new:
            self._load_seen()
        self.fh = path.open("a", encoding="utf-8")
        if new:
            self.write({
                "kind": "meta", "tool": "rngaudit", "format": SNAPSHOT_FORMAT,
                "version": __version__,
                "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            })

    def _load_seen(self) -> None:
        with self.path.open(encoding="utf-8") as fh:
            first = fh.readline()
            if not is_snapshot_header(first.encode()):
                raise ValueError(f"{self.path} exists and is not an rngaudit snapshot")
            for line in fh:
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if obj.get("kind") == "cert":
                    fp = _der_fp(obj["der"])
                    if obj.get("role") == "leaf":
                        self.seen_leaf.add((obj["host"], fp))
                    else:
                        self.seen_chain.add(fp)
                elif obj.get("kind") == "sshkey":
                    self.seen_ssh.add((obj["host"], obj["key"]))

    def write(self, obj: dict) -> None:
        self.fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
        self.fh.flush()

    def cert(self, t: Target, der: bytes, leaf: bool) -> bool:
        b64 = base64.b64encode(der).decode()
        fp = _der_fp(b64)
        if leaf:
            if (t.host, fp) in self.seen_leaf:
                return False
            self.seen_leaf.add((t.host, fp))
        else:
            if fp in self.seen_chain:
                return False
            self.seen_chain.add(fp)
        self.write({"kind": "cert", "host": t.host, "port": t.port, "proto": "tls",
                    "role": "leaf" if leaf else "chain", "der": b64, "time": _now()})
        return True

    def ssh_key(self, t: Target, line: str) -> bool:
        if (t.host, line) in self.seen_ssh:
            return False
        self.seen_ssh.add((t.host, line))
        self.write({"kind": "sshkey", "host": t.host, "port": t.port, "key": line,
                    "time": _now()})
        return True

    def close(self) -> None:
        self.fh.close()


def _der_fp(b64: str) -> str:
    return hashlib.sha256(base64.b64decode(b64)).hexdigest()


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------


def _sig_record(t: Target, proto: str, key_id: str, r: int, s: int, z: int | None,
                curve: str) -> dict:
    return {"kind": "sig", "host": t.host, "port": t.port, "proto": proto,
            "key_id": key_id, "r": hex(r), "s": hex(s),
            "z": hex(z) if z is not None else None, "curve": curve, "time": _now()}


def collect_tls(t: Target, w: SnapshotWriter, sm: Summary, samples: int,
                timeout: float, delay: float) -> None:
    try:
        chain = net_tls.fetch_chain(t.host, t.port, timeout, t.sni)
        for i, der in enumerate(chain):
            sm.certs += w.cert(t, der, leaf=(i == 0))
        sm.reached += bool(chain)
    except OSError as exc:  # ssl.SSLError is an OSError
        _err(w, sm, t, "tls", f"handshake failed: {exc}")
        return

    for n in range(samples):
        if n:
            time.sleep(delay)
        try:
            res = net_tls.probe_ske(t.host, t.port, timeout, t.sni)
        except net_tls.ProbeError as exc:
            if n == 0:  # a TLS 1.3-only or RSA-only server: not an error worth repeating
                _err(w, sm, t, "tls12-ske", f"no ECDSA signature: {exc}")
            break
        except OSError as exc:
            _err(w, sm, t, "tls12-ske", str(exc))
            break
        for i, der in enumerate(res.chain):
            sm.certs += w.cert(t, der, leaf=(i == 0))
        sig = res.signature
        key_id = spki_fingerprint(x509.load_der_x509_certificate(res.chain[0]).public_key())
        w.write(_sig_record(t, "tls12-ske", key_id, sig.r, sig.s, sig.z, sig.curve))
        sm.signatures += 1
        sm.unverified += not sig.verified


def collect_ssh(t: Target, w: SnapshotWriter, sm: Summary, samples: int,
                timeout: float, delay: float) -> None:
    try:
        _ver, _kex, server_hk = net_ssh.server_hostkey_algs(t.host, t.port, timeout)
    except (OSError, net_ssh.ProbeError) as exc:
        _err(w, sm, t, "ssh", str(exc))
        return
    signing = set(net_ssh.signing_algs(server_hk))
    got_key = False
    for alg in net_ssh.distinct_hostkey_algs(server_hk):
        rounds = samples if alg in signing else 1
        for n in range(rounds):
            time.sleep(delay)
            try:
                res = net_ssh.key_exchange(t.host, t.port, alg, timeout)
            except (OSError, net_ssh.ProbeError) as exc:
                _err(w, sm, t, f"ssh:{alg}", str(exc))
                break
            sm.ssh_keys += w.ssh_key(t, res.key_line)
            got_key = True
            if res.r is not None:
                pub = serialization.load_ssh_public_key(res.key_line.encode())
                w.write(_sig_record(t, "ssh-kex", spki_fingerprint(pub),
                                    res.r, res.s, res.z, res.curve))
                sm.signatures += 1
                sm.unverified += not res.verified
    sm.reached += got_key


def _err(w: SnapshotWriter, sm: Summary, t: Target, proto: str, msg: str) -> None:
    sm.errors.append((t.label, msg))
    w.write({"kind": "error", "host": t.host, "port": t.port, "proto": proto,
             "msg": msg, "time": _now()})


def collect(targets: list[Target], out: Path, samples: int = 1, timeout: float = 10.0,
            delay: float = 0.5,
            progress: Callable[[Target], None] | None = None) -> Summary:
    if not 1 <= samples <= MAX_SAMPLES:
        raise ValueError(f"samples must be between 1 and {MAX_SAMPLES}")
    sm = Summary()
    w = SnapshotWriter(out)
    try:
        for t in targets:
            if progress:
                progress(t)
            sm.targets += 1
            try:
                socket.getaddrinfo(t.host, t.port)
            except OSError as exc:
                _err(w, sm, t, t.proto, f"cannot resolve: {exc}")
                continue
            if t.proto == "tls":
                collect_tls(t, w, sm, samples, timeout, delay)
            else:
                collect_ssh(t, w, sm, samples, timeout, delay)
    finally:
        w.close()
    return sm

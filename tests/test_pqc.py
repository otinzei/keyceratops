"""Post-quantum inventory, migration priorities, PQ key-exchange probes, CBOM."""

import datetime as dt
import json
import shutil
import socket
import subprocess
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from conftest import scan
from keyceratops import collect, cryptoinv, pqc, synth
from keyceratops.cli import main
from keyceratops.ingest import load_paths
from keyceratops.model import Finding, KeyRecord, Severity
from keyceratops.report import render_markdown, render_text
from test_collect import FakeSSH

PEM, DER = serialization.Encoding.PEM, serialization.Encoding.DER


def cert(key, cn, issuer_key=None, issuer_cn=None, not_after=dt.datetime(2027, 1, 1),
         alg=hashes.SHA256, org=None):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    subject = x509.Name(attrs)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime(2025, 1, 1)).not_valid_after(not_after)
            .sign(issuer_key or key, alg() if alg else None))


# sha256WithRSAEncryption -> sha1WithRSAEncryption: same length, last arc 11 -> 5
_SHA256_RSA = bytes.fromhex("06092a864886f70d01010b")
_SHA1_RSA = bytes.fromhex("06092a864886f70d010105")


def as_sha1(c):
    """The certificate relabelled as SHA-1-signed. cryptography refuses to make
    SHA-1 signatures; the audit reads the algorithm, not the signature."""
    der = c.public_bytes(DER)
    assert der.count(_SHA256_RSA) == 2  # tbsCertificate.signature and signatureAlgorithm
    return x509.load_der_x509_certificate(der.replace(_SHA256_RSA, _SHA1_RSA))


def _openssl_has(alg):
    if shutil.which("openssl") is None:
        return False
    out = subprocess.run(["openssl", "list", "-signature-algorithms"],
                         capture_output=True, text=True).stdout
    return alg.lower() in out.lower()


# ---- DER and classification ---------------------------------------------------


@pytest.mark.parametrize("key, oid", [
    (rsa.generate_private_key(65537, 1024), "1.2.840.113549.1.1.1"),
    (ec.generate_private_key(ec.SECP384R1()), "1.2.840.10045.2.1"),
    (ed25519.Ed25519PrivateKey.generate(), "1.3.101.112"),
])
def test_der_walker_matches_cryptography(key, oid):
    c = cert(key, "x", alg=None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256)
    spki = key.public_key().public_bytes(DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert pqc.cert_spki(c.public_bytes(DER)) == spki
    assert pqc.spki_algorithm_oid(spki) == oid


@pytest.mark.parametrize("bad", [b"", b"\x30", b"\x30\x05\x30\x03\x06\x01", b"\x02\x01\x00"])
def test_der_walker_rejects_garbage(bad):
    with pytest.raises(ValueError):
        pqc.spki_algorithm_oid(bad)


@pytest.mark.parametrize("bits, name, strength", [
    (1024, "RSA-1024", 80), (2047, "RSA-2048", 112), (2048, "RSA-2048", 112),
    (3072, "RSA-3072", 128), (4096, "RSA-4096", 128), (512, "RSA-512", 0),
])
def test_rsa_classification(bits, name, strength):
    info = pqc.classify(KeyRecord("s", "rsa", "fp", bits=bits, modulus=3, exponent=65537))
    assert (info.name, info.classical_bits, info.quantum_safe) == (name, strength, False)


def test_pq_oid_table():
    k = KeyRecord("s", "ml-dsa", "fp", key_oid="2.16.840.1.101.3.4.3.18", param="ML-DSA-65")
    info = pqc.classify(k)
    assert (info.name, info.nist_level, info.quantum_safe, info.primitive) == (
        "ML-DSA-65", 3, True, "signature")
    assert pqc.classify(KeyRecord("s", "ml-kem", "fp", key_oid="2.16.840.1.101.3.4.4.2")).primitive == "kem"
    assert pqc.family_for_oid("2.16.840.1.101.3.4.3.25") == ("slh-dsa", "SLH-DSA-SHA2-256f")
    assert pqc.classify(KeyRecord("s", "other", "fp", key_oid="1.2.3")).quantum_safe is False


@pytest.mark.skipif(not _openssl_has("ML-DSA-65") or not _openssl_has("SLH-DSA-SHA2-128s"),
                    reason="openssl without ML-DSA / SLH-DSA")
def test_post_quantum_certificates_from_openssl(tmp_path):
    for alg in ("ML-DSA-65", "SLH-DSA-SHA2-128s"):
        subprocess.run(["openssl", "req", "-x509", "-newkey", alg, "-nodes", "-subj", f"/CN={alg}",
                        "-days", "30", "-keyout", str(tmp_path / f"{alg}.key"),
                        "-out", str(tmp_path / f"{alg}.crt")], check=True, capture_output=True)
        (tmp_path / f"{alg}.key").unlink()  # the audit never needs it
    corpus = load_paths([tmp_path])
    assert corpus.errors == []
    got = sorted((k.algorithm, k.param) for k in corpus.keys)
    assert got == [("ml-dsa", "ML-DSA-65"), ("slh-dsa", "SLH-DSA-SHA2-128s")]
    report = scan([tmp_path])
    assert report.crypto.quantum_safe_keys == 2 and report.findings == []


# ---- priorities -----------------------------------------------------------------


def _write(path, c):
    path.write_bytes(c.public_bytes(PEM))


def test_priorities(tmp_path):
    ca = rsa.generate_private_key(65537, 2048)
    # weak today: a SHA-1-signed leaf (not self-signed)
    _write(tmp_path / "sha1.pem", as_sha1(cert(ec.generate_private_key(ec.SECP256R1()), "old",
                                               issuer_key=ca, issuer_cn="CA")))
    # weak today: RSA-1024
    _write(tmp_path / "rsa1024.pem", cert(rsa.generate_private_key(65537, 1024), "tiny"))
    # long-lived: valid until 2033
    _write(tmp_path / "long.pem", cert(ec.generate_private_key(ec.SECP256R1()), "long",
                                       not_after=dt.datetime(2033, 1, 1)))
    # fine for now: expires 2027
    _write(tmp_path / "ok.pem", cert(ec.generate_private_key(ec.SECP256R1()), "ok"))
    # self-signed SHA-1 root: its own signature does not matter
    _write(tmp_path / "root.pem", as_sha1(cert(rsa.generate_private_key(65537, 2048), "root")))
    report = scan([tmp_path])
    pr = {p.name: p for p in report.crypto.priorities}
    assert pr["broken"].count == 1  # RSA-1024 is a CRITICAL rsa-tiny finding ...
    assert pr["weak"].count == 1 and "sha1.pem" in pr["weak"].examples[0]  # ... so only SHA-1 here
    assert pr["long-lived"].count == 1 and "long.pem" in pr["long-lived"].examples[0]
    assert pr["harvest"].count == 0
    assert report.crypto.keys == 5 and report.crypto.quantum_safe_keys == 0


def test_build_counts_each_key_once():
    k1 = KeyRecord("a.pem#0", "rsa", "fp1", bits=1024, modulus=3, exponent=65537)
    k2 = KeyRecord("b.pem#0", "rsa", "fp1", bits=1024, modulus=3, exponent=65537)
    f = Finding("duplicate-key", Severity.HIGH, "t", "d", fingerprints=["fp1"])
    inv = cryptoinv.build([k1, k2], [f], {"ssh://h:22": {"proto": "ssh", "pq_kex": False},
                                          "tls://h:443": {"proto": "tls", "pq_kex": True}})
    pr = {p.name: p.count for p in inv.priorities}
    assert pr == {"broken": 1, "weak": 0, "long-lived": 0, "harvest": 1}
    assert inv.keys == 1 and inv.endpoints == 2 and inv.pq_endpoints == 1


# ---- key exchange probes ---------------------------------------------------------


@pytest.fixture
def openssl_tls(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl not installed")
    key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "k.pem").write_bytes(key.private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    _write(tmp_path / "c.pem", synth.make_cert("localhost", key.public_key(), key))
    procs = []

    def start(*extra):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        proc = subprocess.Popen(
            ["openssl", "s_server", "-quiet", "-accept", f"127.0.0.1:{port}", "-www",
             "-cert", str(tmp_path / "c.pem"), "-key", str(tmp_path / "k.pem"), *extra],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(proc)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return port
            except OSError:
                time.sleep(0.05)
        pytest.skip("openssl s_server did not start")

    yield start
    for p in procs:
        p.kill()
        p.wait()
    (tmp_path / "k.pem").unlink(missing_ok=True)  # leave no private key behind


def test_tls_post_quantum_group_detection(tmp_path, openssl_tls):
    if not _openssl_has("ML-DSA-65"):  # proxy for an OpenSSL with ML-KEM (3.5+)
        pytest.skip("openssl without ML-KEM")
    pq = openssl_tls("-groups", "X25519MLKEM768:X25519")
    classic = openssl_tls("-groups", "X25519")
    old = openssl_tls("-tls1_2")
    snap = tmp_path / "s.jsonl"
    targets = [collect.Target("tls", "127.0.0.1", p) for p in (pq, classic, old)]
    collect.collect(targets, snap, samples=1, timeout=5, delay=0)
    recs = [json.loads(x) for x in snap.read_text().splitlines()]
    groups = {r["port"]: r["groups"] for r in recs if r["kind"] == "tls-groups"}
    assert groups[pq] == {"X25519MLKEM768": True, "SecP256r1MLKEM768": False}
    assert groups[classic] == {"X25519MLKEM768": False, "SecP256r1MLKEM768": False}
    assert not any(groups[old].values())

    report = scan([snap])
    inv = report.crypto
    assert (inv.endpoints, inv.pq_endpoints) == (3, 1)
    harvest = [p for p in inv.priorities if p.name == "harvest"][0]
    assert harvest.count == 2 and all("127.0.0.1" in x for x in harvest.examples)


class PqFakeSSH(FakeSSH):
    KEX = ["mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256"]


def test_ssh_post_quantum_kex_is_recorded(tmp_path):
    d = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
    servers = [FakeSSH(d, 7), PqFakeSSH(d + 1, 11)]
    try:
        snap = tmp_path / "s.jsonl"
        collect.collect([collect.Target("ssh", "127.0.0.1", s.port) for s in servers], snap,
                        samples=1, timeout=5, delay=0)
    finally:
        for s in servers:
            s.close()
    corpus = load_paths([snap])
    pq = {e["kex"][0]: e["pq_kex"] for e in corpus.endpoints.values()}
    assert pq == {"curve25519-sha256": False, "mlkem768x25519-sha256": True}


# ---- reports -----------------------------------------------------------------------


def test_text_and_markdown(tmp_path):
    _write(tmp_path / "long.pem", cert(ec.generate_private_key(ec.SECP256R1()), "long",
                                       not_after=dt.datetime(2033, 1, 1)))
    report = scan([tmp_path])
    short = render_text(report, lang="en")
    assert "post-quantum inventory: 1 key(s), 0 quantum-safe" in short
    assert "Migration priorities" not in short
    full = render_text(report, lang="ja", pqc=True)
    assert "量子耐性の棚卸し" in full and "ECDSA P-256: 1個 / 128ビット相当 / 破られる" in full
    assert "2030年末より後まで有効" in full and "NIST IR 8547" in full
    md = render_markdown(report, lang="en", pqc=True)
    assert "## Post-quantum inventory" in md


def test_cbom(tmp_path):
    rng_key = rsa.generate_private_key(65537, 1024)
    _write(tmp_path / "a.pem", cert(rng_key, "a"))
    _write(tmp_path / "b.pem", cert(rng_key, "b"))  # same key in two places: a finding
    _write(tmp_path / "c.pem", cert(ec.generate_private_key(ec.SECP384R1()), "c"))
    out = tmp_path / "bom.json"
    assert main(["scan", str(tmp_path), "-f", "cbom", "-o", str(out), "--fail-on", "never"]) == 0
    bom = json.loads(out.read_text())
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    comps = bom["components"]
    by_type = {}
    for c in comps:
        assert c["type"] == "cryptographic-asset"
        by_type.setdefault(c["cryptoProperties"]["assetType"], []).append(c)
    assert {c["name"] for c in by_type["algorithm"]} == {"RSA-1024", "ECDSA P-384"}
    rsa_alg = [c for c in by_type["algorithm"] if c["name"] == "RSA-1024"][0]
    assert rsa_alg["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert rsa_alg["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] == 80
    assert len(by_type["related-crypto-material"]) == 2  # two distinct keys
    shared = [c for c in by_type["related-crypto-material"] if len(c["evidence"]["occurrences"]) == 2]
    assert len(shared) == 1
    assert len(by_type["certificate"]) == 3

    refs = {c["bom-ref"] for c in comps}
    for c in comps:
        props = c["cryptoProperties"]
        ref = (props.get("relatedCryptoMaterialProperties", {}).get("algorithmRef")
               or props.get("certificateProperties", {}).get("subjectPublicKeyRef"))
        assert ref is None or ref in refs
    vulns = bom["vulnerabilities"]
    assert {v["ratings"][0]["severity"] for v in vulns} <= {
        "critical", "high", "medium", "low", "info", "none", "unknown"}
    assert all(a["ref"] in refs for v in vulns for a in v.get("affects", []))
    assert any(v["id"] == "keyceratops:duplicate-key" for v in vulns)
    # fingerprints only: no key material in the BOM
    n_hex = format(rng_key.public_key().public_numbers().n, "x")
    assert n_hex[:40] not in out.read_text()


def _one_shot_server(reply: bytes):
    import threading

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)

    def serve():
        conn, _ = sock.accept()
        conn.recv(65536)
        conn.sendall(reply)
        time.sleep(0.1)
        conn.close()
        sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def _hrr(group: int, version: int = 0x0304, random_: bytes | None = None) -> bytes:
    from keyceratops.net_tls import HRR_RANDOM

    exts = (bytes.fromhex("002b0002") + version.to_bytes(2, "big")
            + bytes.fromhex("00330002") + group.to_bytes(2, "big"))
    body = (b"\x03\x03" + (random_ or HRR_RANDOM) + b"\x00" + b"\x13\x01" + b"\x00"
            + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def test_group_probe_reads_the_retry_request():
    from keyceratops.net_tls import ProbeError, probe_group

    assert probe_group("127.0.0.1", _one_shot_server(_hrr(0x11EC)), 0x11EC, 5) is True
    # a retry request for some other group is not support for ours
    assert probe_group("127.0.0.1", _one_shot_server(_hrr(0x001D)), 0x11EC, 5) is False
    with pytest.raises(ProbeError):  # a normal ServerHello cannot answer an empty key_share
        probe_group("127.0.0.1", _one_shot_server(_hrr(0x11EC, random_=b"\x01" * 32)), 0x11EC, 5)
    with pytest.raises(ProbeError):
        probe_group("127.0.0.1", _one_shot_server(_hrr(0x11EC, version=0x0303)), 0x11EC, 5)

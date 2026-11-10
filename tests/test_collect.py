"""Collection from live servers, without touching the network.

* SSH: an in-process fake server whose ECDSA host key signs with a fixed nonce.
  Its exchange hash is computed here independently of ``net_ssh``, so the
  client's signature verification checks the client's own H.
* TLS: a real ``openssl s_server`` on localhost (skipped if openssl is missing).
"""

import base64
import hashlib
import json
import shutil
import socket
import struct
import subprocess
import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519

from conftest import scan
from rngaudit import collect, synth
from rngaudit.cli import main
from rngaudit.ingest import load_paths

# ---- target parsing -------------------------------------------------------


@pytest.mark.parametrize(
    "spec, want",
    [
        ("tls://example.org", ("tls", "example.org", 443)),
        ("https://example.org:8443/", ("tls", "example.org", 8443)),
        ("ssh://10.0.0.1:2222", ("ssh", "10.0.0.1", 2222)),
        ("ssh://[2001:db8::1]:2222", ("ssh", "2001:db8::1", 2222)),
        ("ssh://[2001:db8::1]", ("ssh", "2001:db8::1", 22)),
    ],
)
def test_parse_target(spec, want):
    t = collect.parse_target(spec)
    assert (t.proto, t.host, t.port) == want


def test_bare_host_means_tls_and_ssh():
    assert [(t.proto, t.port) for t in collect.expand(["box.lan"])] == [
        ("tls", 443), ("ssh", 22)]


@pytest.mark.parametrize("spec", ["ftp://x", "box.lan:22", "tls://x:0", "tls://a b",
                                  "ssh://10.0.0.0/24", "tls://*.example.org"])
def test_bad_targets_rejected(spec):
    with pytest.raises(ValueError):
        collect.expand([spec])


def test_targets_file(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# lab\nssh://a:2222  # comment\n\ntls://b\n")
    assert collect.read_targets_file(str(f)) == ["ssh://a:2222", "tls://b"]


# ---- a fake SSH server -----------------------------------------------------


def _s(b):
    return struct.pack("!I", len(b)) + b


def _mp(n):
    raw = n.to_bytes((n.bit_length() + 8) // 8, "big") if n else b""
    return _s(raw)


def _names(xs):
    return _s(",".join(xs).encode())


class FakeSSH:
    """Speaks just enough SSH: KEXINIT, ECDH, KEX_ECDH_REPLY, then hangs up.

    The ECDSA host key signs with ``nonce`` (fixed: the planted RNG failure).
    """

    VERSION = b"SSH-2.0-FakeSSH_1.0"
    KEX = ["curve25519-sha256", "ecdh-sha2-nistp256"]

    def __init__(self, ecdsa_d: int, nonce: int, ed_key=None):
        self.d = ecdsa_d
        self.nonce = nonce
        self.ed = ed_key or ed25519.Ed25519PrivateKey.generate()
        pub = ec.derive_private_key(ecdsa_d, ec.SECP256R1()).public_key()
        point = pub.public_bytes(serialization.Encoding.X962,
                                 serialization.PublicFormat.UncompressedPoint)
        self.ecdsa_blob = _s(b"ecdsa-sha2-nistp256") + _s(b"nistp256") + _s(point)
        ed_raw = self.ed.public_key().public_bytes(serialization.Encoding.Raw,
                                                   serialization.PublicFormat.Raw)
        self.ed_blob = _s(b"ssh-ed25519") + _s(ed_raw)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def key_lines(self):
        return {f"ecdsa-sha2-nistp256 {base64.b64encode(self.ecdsa_blob).decode()}",
                f"ssh-ed25519 {base64.b64encode(self.ed_blob).decode()}"}

    def close(self):
        self.stop = True
        self.sock.close()

    def _serve(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                self._handle(conn)
            except Exception:
                pass
            finally:
                conn.close()

    @staticmethod
    def _send(conn, payload):
        pad = 8 - (len(payload) + 5) % 8
        pad += 8 if pad < 4 else 0
        conn.sendall(struct.pack("!IB", len(payload) + pad + 1, pad) + payload + b"\0" * pad)

    @staticmethod
    def _more(conn):
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("client hung up")
        return chunk

    def _recv(self, conn, buf):
        while len(buf) < 5:
            buf += self._more(conn)
        length, pad = struct.unpack("!IB", buf[:5])
        while len(buf) < 4 + length:
            buf += self._more(conn)
        return buf[5:4 + length - pad], buf[4 + length:]

    def _handle(self, conn):
        conn.sendall(self.VERSION + b"\r\n")
        i_s = (b"\x14" + b"\x11" * 16
               + _names(self.KEX)
               + _names(["ecdsa-sha2-nistp256", "ssh-ed25519"])
               + _names(["aes128-ctr"]) * 2 + _names(["hmac-sha2-256"]) * 2
               + _names(["none"]) * 2 + _names([]) * 2 + b"\0" + b"\0" * 4)
        self._send(conn, i_s)
        buf = b""
        while b"\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        v_c, buf = buf.split(b"\r\n", 1)
        i_c, buf = self._recv(conn, buf)
        init, buf = self._recv(conn, buf)
        # client's choices: the first name of each of its lists
        pos = 17
        kex_len = struct.unpack("!I", i_c[pos:pos + 4])[0]
        kex = i_c[pos + 4:pos + 4 + kex_len].decode().split(",")[0]
        pos += 4 + kex_len
        hk_len = struct.unpack("!I", i_c[pos:pos + 4])[0]
        hk = i_c[pos + 4:pos + 4 + hk_len].decode().split(",")[0]
        q_c = init[5:5 + struct.unpack("!I", init[1:5])[0]]

        if kex == "curve25519-sha256":
            eph = x25519.X25519PrivateKey.generate()
            q_s = eph.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)
            k = int.from_bytes(eph.exchange(x25519.X25519PublicKey.from_public_bytes(q_c)), "big")
        else:
            eph = ec.generate_private_key(ec.SECP256R1())
            q_s = eph.public_key().public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.UncompressedPoint)
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), q_c)
            k = int.from_bytes(eph.exchange(ec.ECDH(), peer), "big")

        k_s = self.ecdsa_blob if hk == "ecdsa-sha2-nistp256" else self.ed_blob
        h = hashlib.sha256(_s(v_c) + _s(self.VERSION) + _s(i_c) + _s(i_s) + _s(k_s)
                           + _s(q_c) + _s(q_s) + _mp(k)).digest()
        if hk == "ecdsa-sha2-nistp256":
            r, s = synth.ecdsa_sign_p256(self.d, h, self.nonce)
            sig = _s(b"ecdsa-sha2-nistp256") + _s(_mp(r) + _mp(s))
        else:
            sig = _s(b"ssh-ed25519") + _s(self.ed.sign(h))
        self._send(conn, b"\x1f" + _s(k_s) + _s(q_s) + _s(sig))
        time.sleep(0.05)


@pytest.fixture
def fake_ssh():
    servers = []

    def make(nonce=0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCD):
        d = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
        srv = FakeSSH(d, nonce)
        servers.append(srv)
        return srv

    yield make
    for srv in servers:
        srv.close()


def _records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_ssh_collect_finds_planted_nonce_reuse(tmp_path, fake_ssh):
    srv = fake_ssh()
    snap = tmp_path / "snap.jsonl"
    t = collect.Target("ssh", "127.0.0.1", srv.port)
    sm = collect.collect([t], snap, samples=3, timeout=5, delay=0)

    assert sm.errors == [] and sm.reached == 1
    assert sm.signatures == 3 and sm.unverified == 0  # our H matches the server's
    recs = _records(snap)
    assert recs[0]["kind"] == "meta"
    assert {r["key"] for r in recs if r["kind"] == "sshkey"} == srv.key_lines()
    sigs = [r for r in recs if r["kind"] == "sig"]
    assert all(r["z"] for r in sigs) and len({r["r"] for r in sigs}) == 1

    report = scan([snap])
    reuse = [f for f in report.findings if f.check == "ecdsa-nonce-reuse"]
    assert len(reuse) == 1 and reuse[0].severity.name == "CRITICAL"
    # the safety rule: nothing secret in the report
    blob = json.dumps([f.to_dict() for f in report.findings])
    assert str(srv.d) not in blob and hex(srv.d)[2:] not in blob


def test_ssh_healthy_server_is_clean(tmp_path, monkeypatch, fake_ssh):
    srv = fake_ssh()
    counter = iter(range(1, 10**6))
    # a fresh nonce per signature, as a correct implementation would do
    monkeypatch.setattr(srv, "nonce", None)
    orig = synth.ecdsa_sign_p256
    monkeypatch.setattr(
        synth, "ecdsa_sign_p256",
        lambda d, m, k: orig(d, m, k if k is not None else
                             int.from_bytes(hashlib.sha256(bytes([next(counter)])).digest(), "big")),
    )
    snap = tmp_path / "snap.jsonl"
    collect.collect([collect.Target("ssh", "127.0.0.1", srv.port)], snap, samples=3,
                    timeout=5, delay=0)
    assert [f.check for f in scan([snap]).findings] == []


def test_same_ssh_key_on_two_hosts_is_reported(tmp_path, fake_ssh):
    srv = fake_ssh()
    snap = tmp_path / "snap.jsonl"
    targets = [collect.Target("ssh", "127.0.0.1", srv.port),
               collect.Target("ssh", "localhost", srv.port)]
    collect.collect(targets, snap, samples=1, timeout=5, delay=0)
    dup = [f for f in scan([snap]).findings if f.check == "duplicate-key"]
    assert len(dup) == 2  # the ECDSA and the Ed25519 host key
    assert all(f.data.get("note") == "alias_or_clone" for f in dup)


def test_append_does_not_duplicate_keys(tmp_path, fake_ssh):
    srv = fake_ssh()
    snap = tmp_path / "snap.jsonl"
    t = collect.Target("ssh", "127.0.0.1", srv.port)
    first = collect.collect([t], snap, samples=1, timeout=5, delay=0)
    second = collect.collect([t], snap, samples=1, timeout=5, delay=0)
    assert first.ssh_keys == 2 and second.ssh_keys == 0
    assert second.signatures == 1  # signatures always accumulate
    assert sum(r["kind"] == "meta" for r in _records(snap)) == 1


def test_refuses_to_append_to_a_foreign_file(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("my notes\n")
    with pytest.raises(ValueError):
        collect.collect([collect.Target("ssh", "127.0.0.1", 1)], f)
    assert f.read_text() == "my notes\n"


def test_cli_collect_unreachable_and_usage(tmp_path, capsys):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens there now
    snap = tmp_path / "s.jsonl"
    assert main(["collect", f"ssh://127.0.0.1:{port}", "-o", str(snap), "--lang", "en",
                 "--timeout", "2"]) == 2
    assert "not collected" in capsys.readouterr().out
    assert main(["collect", "-o", str(snap)]) == 2
    assert main(["collect", "ftp://x", "-o", str(snap)]) == 2
    assert main(["collect", "ssh://x", "-n", "0", "-o", str(snap)]) == 2


def test_cli_collect_then_scan(tmp_path, capsys, fake_ssh):
    srv = fake_ssh()
    snap = tmp_path / "s.jsonl"
    assert main(["collect", f"ssh://127.0.0.1:{srv.port}", "-n", "2", "--delay", "0",
                 "-o", str(snap), "--lang", "en", "-q"]) == 0
    assert "rngaudit scan" in capsys.readouterr().out
    assert main(["scan", str(snap), "-f", "json"]) == 1  # CRITICAL >= default high


# ---- snapshot ingest -------------------------------------------------------


def _snapshot(path, records):
    lines = [{"kind": "meta", "tool": "rngaudit", "format": 1}] + records
    path.write_text("".join(json.dumps(r) + "\n" for r in lines))


def _cert_rec(host, cert, role="leaf"):
    der = cert.public_bytes(serialization.Encoding.DER)
    return {"kind": "cert", "host": host, "port": 443, "proto": "tls", "role": role,
            "der": base64.b64encode(der).decode()}


def test_one_certificate_on_many_names_is_not_a_finding(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = synth.make_cert("www.example", key.public_key(), key)
    _snapshot(tmp_path / "s.jsonl",
              [_cert_rec(h, cert) for h in ("www.example", "api.example", "example")])
    assert [f.check for f in scan([tmp_path]).findings
            if f.check == "duplicate-key"] == []


def test_one_key_in_different_certificates_on_two_hosts(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    a = synth.make_cert("cam-1", key.public_key(), key)
    b = synth.make_cert("cam-2", key.public_key(), key)
    _snapshot(tmp_path / "s.jsonl", [_cert_rec("10.0.0.1", a), _cert_rec("10.0.0.2", b)])
    dup = [f for f in scan([tmp_path]).findings if f.check == "duplicate-key"]
    assert len(dup) == 1 and dup[0].data["holders"] == 2


def test_chain_certificates_are_not_attributed_to_hosts(tmp_path):
    ca = ec.generate_private_key(ec.SECP256R1())
    ca_cert = synth.make_cert("Example CA", ca.public_key(), ca)
    _snapshot(tmp_path / "s.jsonl", [_cert_rec("a", ca_cert, "chain")])
    corpus = load_paths([tmp_path])
    assert corpus.errors == [] and "[" not in corpus.keys[0].source


def test_bad_snapshot_record_is_an_error_not_a_crash(tmp_path):
    _snapshot(tmp_path / "s.jsonl", [{"kind": "sshkey", "host": "h", "key": "garbage"},
                                     {"kind": "error", "host": "h", "msg": "x"}])
    corpus = load_paths([tmp_path])
    assert corpus.keys == [] and len(corpus.errors) == 1


# ---- TLS against a real openssl s_server -----------------------------------


@pytest.fixture
def openssl_server(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl not installed")
    key = ec.generate_private_key(ec.SECP256R1())
    cert = synth.make_cert("localhost", key.public_key(), key)
    (tmp_path / "k.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    proc = subprocess.Popen(
        ["openssl", "s_server", "-quiet", "-accept", f"127.0.0.1:{port}",
         "-cert", str(tmp_path / "c.pem"), "-key", str(tmp_path / "k.pem"), "-www"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        proc.kill()
        pytest.skip("openssl s_server did not start")
    yield port
    proc.kill()
    proc.wait()
    (tmp_path / "k.pem").unlink()  # pytest keeps recent tmp dirs; leave no private key


def test_tls_collect_against_openssl(tmp_path, openssl_server):
    snap = tmp_path / "snap.jsonl"
    sm = collect.collect([collect.Target("tls", "127.0.0.1", openssl_server)], snap,
                         samples=3, timeout=5, delay=0)
    assert sm.errors == [] and sm.certs == 1
    assert sm.signatures == 3 and sm.unverified == 0
    sigs = [r for r in _records(snap) if r["kind"] == "sig"]
    assert {r["proto"] for r in sigs} == {"tls12-ske"} and len({r["r"] for r in sigs}) == 3
    report = scan([snap])
    assert not [f for f in report.findings if f.check.startswith("ecdsa")]
    assert report.stats["signatures"] == 4  # 3 handshakes + the self-signed certificate


def test_message_hash_truncates_to_the_order():
    from cryptography.hazmat.primitives import hashes
    from rngaudit.net_tls import message_hash

    full = int.from_bytes(hashlib.sha384(b"m").digest(), "big")
    assert message_hash(b"m", hashes.SHA384(), 256) == full >> 128
    assert message_hash(b"m", hashes.SHA256(), 521) == int.from_bytes(
        hashlib.sha256(b"m").digest(), "big")

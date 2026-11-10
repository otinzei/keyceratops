"""Collecting host keys and ECDSA signatures from SSH servers.

An SSH key exchange ends with the server signing the exchange hash ``H``
with its host key (RFC 4253 section 8, RFC 5656, RFC 8731). Because we are the
client, we know every input of ``H`` and therefore the message the server
signed. Each connection yields a fresh signature (``H`` depends on both
ephemeral keys), so repeated connections collect the samples that the
nonce-reuse and nonce-bias checks need.

The probe stops after KEX_ECDH_REPLY: no NEWKEYS is sent, no authentication
is attempted. To learn every host key a server has, one connection is made per
host-key algorithm the server advertises.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .net_tls import ProbeError, message_hash

CLIENT_VERSION = b"SSH-2.0-keyceratops"
MAX_PACKET = 1 << 18

# Key exchange methods we can complete far enough to compute H.
_KEX = {
    "curve25519-sha256": ("x25519", hashes.SHA256),
    "curve25519-sha256@libssh.org": ("x25519", hashes.SHA256),
    "ecdh-sha2-nistp256": (ec.SECP256R1, hashes.SHA256),
    "ecdh-sha2-nistp384": (ec.SECP384R1, hashes.SHA384),
    "ecdh-sha2-nistp521": (ec.SECP521R1, hashes.SHA512),
}

# Host-key algorithms, most interesting first. Several names map to one key.
HOSTKEY_ALGS = (
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-dss",
)
_KEY_TYPE = {  # host-key algorithm -> key blob type (one key per type)
    "rsa-sha2-512": "ssh-rsa",
    "rsa-sha2-256": "ssh-rsa",
}
_ECDSA_HASH = {
    "ecdsa-sha2-nistp256": hashes.SHA256,
    "ecdsa-sha2-nistp384": hashes.SHA384,
    "ecdsa-sha2-nistp521": hashes.SHA512,
}


@dataclass
class KexResult:
    hostkey_alg: str
    key_line: str  # "<type> <base64>", OpenSSH public key format
    server_version: str
    # ECDSA host keys only:
    r: int | None = None
    s: int | None = None
    z: int | None = None
    curve: str | None = None
    verified: bool = False


# --------------------------------------------------------------------------
# wire encoding (RFC 4251 section 5)
# --------------------------------------------------------------------------


def sstring(b: bytes) -> bytes:
    return struct.pack("!I", len(b)) + b


def mpint(n: int) -> bytes:
    if n == 0:
        return sstring(b"")
    raw = n.to_bytes((n.bit_length() + 8) // 8, "big")  # keeps a 0x00 sign byte
    return sstring(raw)


def namelist(names) -> bytes:
    return sstring(",".join(names).encode())


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.d, self.i = data, 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise ProbeError("truncated SSH message")
        out = self.d[self.i : self.i + n]
        self.i += n
        return out

    def u32(self) -> int:
        return struct.unpack("!I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def mpint(self) -> int:
        return int.from_bytes(self.string(), "big", signed=True)

    def names(self) -> list[str]:
        s = self.string().decode("ascii", "replace")
        return s.split(",") if s else []


# --------------------------------------------------------------------------
# transport (unencrypted phase only)
# --------------------------------------------------------------------------


class _Conn:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""

    def _fill(self, n: int) -> None:
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ProbeError("connection closed by server")
            self.buf += chunk

    def read_version(self) -> bytes:
        """Server identification line (lines before it may be banners)."""
        for _ in range(64):
            while b"\n" not in self.buf:
                if len(self.buf) > 8192:
                    raise ProbeError("no SSH identification line")
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise ProbeError("connection closed by server")
                self.buf += chunk
            line, self.buf = self.buf.split(b"\n", 1)
            line = line.rstrip(b"\r")
            if line.startswith(b"SSH-"):
                if not line.startswith((b"SSH-2.0-", b"SSH-1.99-")):
                    raise ProbeError("server does not speak SSH 2")
                return line
        raise ProbeError("no SSH identification line")

    def send(self, payload: bytes) -> None:
        pad = 8 - (len(payload) + 5) % 8
        if pad < 4:
            pad += 8
        packet = struct.pack("!IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad
        self.sock.sendall(packet)

    def recv(self) -> bytes:
        self._fill(5)
        length, pad = struct.unpack("!IB", self.buf[:5])
        if length > MAX_PACKET or pad + 1 > length:
            raise ProbeError("malformed SSH packet")
        self._fill(4 + length)
        payload = self.buf[5 : 4 + length - pad]
        self.buf = self.buf[4 + length :]
        return payload

    def recv_msg(self) -> bytes:
        """Next message, skipping IGNORE / DEBUG / UNIMPLEMENTED."""
        while True:
            msg = self.recv()
            if not msg:
                raise ProbeError("empty SSH packet")
            if msg[0] in (2, 3, 4):
                continue
            if msg[0] == 1:  # DISCONNECT
                r = _Reader(msg[1:])
                r.u32()
                reason = r.string().decode("utf-8", "replace")
                raise ProbeError(f"server disconnected: {reason}")
            return msg


def _kexinit(cookie: bytes, kex, hostkey) -> bytes:
    ciphers = ["aes128-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com",
               "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"]
    macs = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512"]
    return (
        b"\x14" + cookie
        + namelist(kex) + namelist(hostkey)
        + namelist(ciphers) + namelist(ciphers)
        + namelist(macs) + namelist(macs)
        + namelist(["none"]) + namelist(["none"])
        + namelist([]) + namelist([])
        + b"\x00" + b"\x00\x00\x00\x00"
    )


def _parse_kexinit(msg: bytes) -> tuple[list[str], list[str]]:
    r = _Reader(msg)
    if r.take(1) != b"\x14":
        raise ProbeError("expected KEXINIT")
    r.take(16)
    return r.names(), r.names()


def _negotiate(client: list[str], server: list[str]) -> str | None:
    return next((c for c in client if c in server), None)


def _open(host: str, port: int, timeout: float):
    sock = socket.create_connection((host, port), timeout=timeout)
    conn = _Conn(sock)
    sock.sendall(CLIENT_VERSION + b"\r\n")
    v_s = conn.read_version()
    i_s = conn.recv_msg()
    server_kex, server_hk = _parse_kexinit(i_s)
    return sock, conn, v_s, i_s, server_kex, server_hk


def server_hostkey_algs(host: str, port: int, timeout: float) -> tuple[str, list[str], list[str]]:
    """The server's version string, kex and host-key algorithm lists."""
    sock, _conn, v_s, _i_s, kex, hk = _open(host, port, timeout)
    sock.close()
    return v_s.decode("utf-8", "replace"), kex, hk


def key_exchange(host: str, port: int, hostkey_alg: str, timeout: float) -> KexResult:
    """Run the key exchange up to KEX_ECDH_REPLY with one host-key algorithm."""
    import os

    sock, conn, v_s, i_s, server_kex, server_hk = _open(host, port, timeout)
    try:
        kex = _negotiate(list(_KEX), server_kex)
        if kex is None:
            raise ProbeError("no supported (EC)DH key exchange: " + ",".join(server_kex))
        if hostkey_alg not in server_hk:
            raise ProbeError(f"server does not offer {hostkey_alg}")
        i_c = _kexinit(os.urandom(16), [kex], [hostkey_alg])
        conn.send(i_c)

        curve, halg = _KEX[kex]
        if curve == "x25519":
            priv = x25519.X25519PrivateKey.generate()
            q_c = priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            priv = ec.generate_private_key(curve())
            q_c = priv.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        conn.send(b"\x1e" + sstring(q_c))  # KEX_ECDH_INIT (30)

        reply = conn.recv_msg()
        if reply[0] != 31:
            raise ProbeError(f"expected KEX_ECDH_REPLY, got message {reply[0]}")
        r = _Reader(reply[1:])
        k_s, q_s, sig_blob = r.string(), r.string(), r.string()

        if curve == "x25519":
            shared = priv.exchange(x25519.X25519PublicKey.from_public_bytes(q_s))
        else:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(curve(), q_s)
            shared = priv.exchange(ec.ECDH(), peer)
        k = int.from_bytes(shared, "big")

        h_in = (
            sstring(CLIENT_VERSION) + sstring(v_s) + sstring(i_c) + sstring(i_s)
            + sstring(k_s) + sstring(q_c) + sstring(q_s) + mpint(k)
        )
        hh = hashes.Hash(halg())
        hh.update(h_in)
        exchange_hash = hh.finalize()
    finally:
        sock.close()

    key_type = _Reader(k_s).string().decode("ascii", "replace")
    import base64

    key_line = f"{key_type} {base64.b64encode(k_s).decode()}"
    res = KexResult(hostkey_alg=hostkey_alg, key_line=key_line,
                    server_version=v_s.decode("utf-8", "replace"))
    if hostkey_alg in _ECDSA_HASH:
        _fill_ecdsa(res, key_line, sig_blob, exchange_hash, _ECDSA_HASH[hostkey_alg])
    return res


def _fill_ecdsa(res: KexResult, key_line: str, sig_blob: bytes,
                exchange_hash: bytes, halg) -> None:
    r = _Reader(sig_blob)
    if r.string().decode() != res.hostkey_alg:
        raise ProbeError("signature type does not match host-key algorithm")
    inner = _Reader(r.string())
    sr, ss = inner.mpint(), inner.mpint()
    pub = serialization.load_ssh_public_key(key_line.encode())
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ProbeError("ECDSA host-key algorithm with a non-EC key")
    res.r, res.s, res.curve = sr, ss, pub.curve.name
    try:
        pub.verify(encode_dss_signature(sr, ss), exchange_hash, ec.ECDSA(halg()))
    except InvalidSignature:
        return  # keep r, s; z unknown
    res.verified = True
    res.z = message_hash(exchange_hash, halg(), pub.curve.key_size)


def distinct_hostkey_algs(server_hk: list[str]) -> list[str]:
    """One algorithm per distinct key type the server offers."""
    out, seen = [], set()
    for alg in HOSTKEY_ALGS:
        if alg in server_hk:
            ktype = _KEY_TYPE.get(alg, alg)
            if ktype not in seen:
                seen.add(ktype)
                out.append(alg)
    return out


def signing_algs(server_hk: list[str]) -> list[str]:
    """Host-key algorithms whose signatures carry a random nonce."""
    return [a for a in distinct_hostkey_algs(server_hk) if a in _ECDSA_HASH]

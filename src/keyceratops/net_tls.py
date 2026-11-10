"""Collecting certificates and ECDSA signatures from TLS servers.

Two probes per target:

* ``fetch_chain``: an ordinary handshake through :mod:`ssl` (any protocol
  version) that records the certificate chain the server presents.
* ``probe_ske``: a hand-built TLS 1.2 ClientHello that offers only
  ECDHE_ECDSA cipher suites. The server answers with ServerHello,
  Certificate and ServerKeyExchange, all in clear text. The ServerKeyExchange
  carries an ECDSA signature by the server's long-term key over
  ``client_random || server_random || ECDH params``, made with a fresh nonce
  on every connection. That is exactly the material the nonce checks need.
  We stop reading at ServerHelloDone and close: no key exchange is completed,
  no application data is sent.

TLS 1.3 encrypts its CertificateVerify, so signatures can only be collected
from servers that still speak TLS 1.2 with an ECDSA certificate.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# ECDHE_ECDSA suites: AES-GCM, ChaCha20, AES-CBC (SHA-2 and SHA-1 variants).
_SUITES = (0xC02B, 0xC02C, 0xCCA9, 0xC023, 0xC024, 0xC009, 0xC00A)
# named groups: x25519, secp256r1, secp384r1, secp521r1
_GROUPS = (0x001D, 0x0017, 0x0018, 0x0019)
# signature_algorithms: ecdsa with sha256/384/512/sha1
_SIGALGS = (0x0403, 0x0503, 0x0603, 0x0203)
_HASH_BY_ID = {
    2: hashes.SHA1,
    4: hashes.SHA256,
    5: hashes.SHA384,
    6: hashes.SHA512,
}

MAX_RECORD = 1 << 18  # refuse handshakes above 256 KiB


class ProbeError(Exception):
    """The server did not give us what we asked for (not necessarily a bug)."""


@dataclass
class SkeSignature:
    r: int
    s: int
    z: int | None  # None when the signature did not verify (z unknown)
    curve: str
    verified: bool


@dataclass
class SkeResult:
    chain: list[bytes] = field(default_factory=list)  # DER, leaf first
    signature: SkeSignature | None = None


# --------------------------------------------------------------------------
# certificate chain through the ssl module
# --------------------------------------------------------------------------


def _der_list(chain) -> list[bytes]:
    out = []
    for c in chain or []:
        if isinstance(c, (bytes, bytearray)):
            out.append(bytes(c))
        else:  # _ssl.Certificate (Python 3.13+)
            out.append(c.public_bytes(ssl._ssl.ENCODING_DER))
    return out


def fetch_chain(host: str, port: int, timeout: float, sni: str | None = None) -> list[bytes]:
    """The certificate chain a server presents, leaf first, unverified.

    Verification is off on purpose: we are auditing what is deployed, and
    self-signed device certificates are the interesting ones.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni or _sni(host)) as tls:
            getter = getattr(tls, "get_unverified_chain", None)
            chain = _der_list(getter()) if getter else []
            if not chain:
                leaf = tls.getpeercert(binary_form=True)
                chain = [leaf] if leaf else []
            return chain


def _sni(host: str) -> str | None:
    """SNI must be a DNS name, never an IP literal."""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return None
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return None
    except OSError:
        return host


# --------------------------------------------------------------------------
# raw TLS 1.2 ServerKeyExchange probe
# --------------------------------------------------------------------------


def _u8(b: bytes) -> bytes:
    return struct.pack("!B", len(b)) + b


def _u16(b: bytes) -> bytes:
    return struct.pack("!H", len(b)) + b


def _u24(b: bytes) -> bytes:
    return struct.pack("!I", len(b))[1:] + b


def _ext(kind: int, body: bytes) -> bytes:
    return struct.pack("!H", kind) + _u16(body)


def client_hello(client_random: bytes, sni: str | None) -> bytes:
    """A TLS 1.2 ClientHello record offering only ECDHE_ECDSA suites."""
    exts = b""
    if sni:
        name = sni.encode("idna")
        exts += _ext(0x0000, _u16(b"\x00" + _u16(name)))
    exts += _ext(0x000A, _u16(b"".join(struct.pack("!H", g) for g in _GROUPS)))
    exts += _ext(0x000B, _u8(b"\x00"))  # ec_point_formats: uncompressed
    exts += _ext(0x000D, _u16(b"".join(struct.pack("!H", a) for a in _SIGALGS)))
    exts += _ext(0xFF01, _u8(b""))  # renegotiation_info (some servers insist)
    body = (
        b"\x03\x03"
        + client_random
        + _u8(b"")  # session id
        + _u16(b"".join(struct.pack("!H", s) for s in _SUITES))
        + _u8(b"\x00")  # compression: null
        + _u16(exts)
    )
    hs = b"\x01" + _u24(body)
    return b"\x16\x03\x01" + _u16(hs)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProbeError("connection closed by server")
        buf += chunk
    return buf


def _handshake_messages(sock: socket.socket):
    """Yield (type, body) handshake messages, reassembling across records."""
    pending = b""
    total = 0
    while True:
        header = _recv_exact(sock, 5)
        ctype, _ver, length = struct.unpack("!BHH", header)
        total += length
        if total > MAX_RECORD:
            raise ProbeError("handshake too large")
        payload = _recv_exact(sock, length)
        if ctype == 0x15:
            desc = payload[1] if len(payload) > 1 else -1
            raise ProbeError(f"server sent alert {desc} (no TLS 1.2 ECDSA support?)")
        if ctype != 0x16:
            raise ProbeError(f"unexpected record type {ctype}")
        pending += payload
        while len(pending) >= 4:
            mlen = int.from_bytes(pending[1:4], "big")
            if len(pending) < 4 + mlen:
                break
            yield pending[0], pending[4 : 4 + mlen]
            pending = pending[4 + mlen :]


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.d, self.i = data, 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise ProbeError("truncated handshake message")
        out = self.d[self.i : self.i + n]
        self.i += n
        return out

    def int(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def vec(self, n: int) -> bytes:
        return self.take(self.int(n))


def _parse_certificates(body: bytes) -> list[bytes]:
    r = _Reader(body)
    blob = _Reader(r.vec(3))
    certs = []
    while blob.i < len(blob.d):
        certs.append(blob.vec(3))
    return certs


def _verify_ske(
    leaf_der: bytes, signed: bytes, sig_der: bytes, hash_id: int
) -> SkeSignature:
    cert = x509.load_der_x509_certificate(leaf_der)
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ProbeError("server certificate is not ECDSA")
    r, s = decode_dss_signature(sig_der)
    halg = _HASH_BY_ID.get(hash_id)
    if halg is None:
        raise ProbeError(f"unsupported hash id {hash_id}")
    try:
        pub.verify(sig_der, signed, ec.ECDSA(halg()))
    except InvalidSignature:
        # r and s are still evidence (a repeated r is a repeated nonce), but
        # without a verified message we do not claim to know z.
        return SkeSignature(r, s, None, pub.curve.name, False)
    return SkeSignature(r, s, message_hash(signed, halg(), pub.curve.key_size),
                        pub.curve.name, True)


def message_hash(data: bytes, alg: hashes.HashAlgorithm, order_bits: int) -> int:
    """ECDSA's z: the leftmost ``order_bits`` bits of the hash."""
    h = hashes.Hash(alg)
    h.update(data)
    digest = h.finalize()
    z = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - order_bits
    return z >> excess if excess > 0 else z


def probe_ske(host: str, port: int, timeout: float, sni: str | None = None) -> SkeResult:
    client_random = os.urandom(32)
    result = SkeResult()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(client_hello(client_random, sni or _sni(host)))
        server_random = None
        for mtype, body in _handshake_messages(sock):
            if mtype == 2:  # ServerHello
                r = _Reader(body)
                version = r.int(2)
                if version != 0x0303:
                    raise ProbeError(f"server chose version {version:#06x}")
                server_random = r.take(32)
            elif mtype == 11:  # Certificate
                result.chain = _parse_certificates(body)
            elif mtype == 12:  # ServerKeyExchange
                if server_random is None or not result.chain:
                    raise ProbeError("ServerKeyExchange out of order")
                r = _Reader(body)
                start = r.i
                if r.int(1) != 3:  # named_curve
                    raise ProbeError("explicit curve parameters not supported")
                r.take(2)  # curve id
                r.vec(1)  # public point
                params = body[start : r.i]
                hash_id, sig_id = r.int(1), r.int(1)
                if sig_id != 3:
                    raise ProbeError("ServerKeyExchange not signed with ECDSA")
                sig_der = r.vec(2)
                result.signature = _verify_ske(
                    result.chain[0], client_random + server_random + params,
                    sig_der, hash_id,
                )
            elif mtype == 14:  # ServerHelloDone
                break
        # Polite close: fatal alert user_canceled is not defined pre-handshake,
        # so just send close_notify.
        try:
            sock.sendall(b"\x15\x03\x03\x00\x02\x01\x00")
        except OSError:
            pass
    if result.signature is None:
        raise ProbeError("no ServerKeyExchange signature received")
    return result


# --------------------------------------------------------------------------
# TLS 1.3 key-exchange group probe (post-quantum hybrids)
# --------------------------------------------------------------------------
#
# A ClientHello that lists one group in supported_groups but sends no key
# share for it: a TLS 1.3 server that supports the group must answer with a
# HelloRetryRequest naming it (RFC 8446 section 4.1.4); one that does not
# supports none of our groups and aborts. No ML-KEM arithmetic is needed.

# SHA-256("HelloRetryRequest"): the fixed ServerHello.random of an HRR
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def client_hello_13(group: int, sni: str | None) -> bytes:
    exts = b""
    if sni:
        exts += _ext(0x0000, _u16(b"\x00" + _u16(sni.encode("idna"))))
    exts += _ext(0x002B, _u8(b"\x03\x04"))  # supported_versions: TLS 1.3
    exts += _ext(0x000A, _u16(struct.pack("!H", group)))  # supported_groups
    exts += _ext(0x0033, _u16(b""))  # key_share: none
    sigalgs = (0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808,
               0x0401, 0x0501, 0x0601, 0x0904, 0x0905, 0x0906)
    exts += _ext(0x000D, _u16(b"".join(struct.pack("!H", a) for a in sigalgs)))
    exts += _ext(0x002D, _u8(b"\x01"))  # psk_key_exchange_modes: psk_dhe_ke
    body = (
        b"\x03\x03" + os.urandom(32) + _u8(os.urandom(32))
        + _u16(b"\x13\x01\x13\x02\x13\x03") + _u8(b"\x00") + _u16(exts)
    )
    return b"\x16\x03\x01" + _u16(b"\x01" + _u24(body))


def probe_group(host: str, port: int, group: int, timeout: float,
                sni: str | None = None) -> bool:
    """True if the server negotiates ``group`` in TLS 1.3, False if it refuses.

    Raises ProbeError when the answer is neither (for example a TLS 1.2-only
    server that picks TLS 1.2).
    """
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(client_hello_13(group, sni or _sni(host)))
        try:
            mtype, body = next(_handshake_messages(sock))
        except ProbeError as exc:
            if "alert" in str(exc):
                return False
            raise
    if mtype != 2:
        raise ProbeError(f"unexpected handshake message {mtype}")
    r = _Reader(body)
    r.take(2)
    random_ = r.take(32)
    r.vec(1)  # session id
    r.take(3)  # cipher suite, compression
    exts = _Reader(r.vec(2)) if r.i < len(body) else _Reader(b"")
    selected_version, selected_group = None, None
    while exts.i < len(exts.d):
        etype, edata = exts.int(2), exts.vec(2)
        if etype == 0x002B and len(edata) == 2:
            selected_version = int.from_bytes(edata, "big")
        elif etype == 0x0033 and len(edata) >= 2:
            selected_group = int.from_bytes(edata[:2], "big")
    if selected_version != 0x0304:
        raise ProbeError("server does not speak TLS 1.3")
    if random_ == HRR_RANDOM:
        return selected_group == group
    raise ProbeError("server answered without a retry request")

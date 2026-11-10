"""Regressions found by running the tool on a real /etc/ssl/certs and
~/.ssh/known_hosts: every case here was a false alarm in v0.1."""

import datetime as dt
import os
import random
import warnings

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec

from conftest import scan
from rngaudit import synth
from rngaudit.checks import AuditConfig, check_serials
from rngaudit.ingest import Corpus, load_paths
from rngaudit.audit import run_audit
from rngaudit.model import KeyRecord, Severity

PEM = serialization.Encoding.PEM


def selfsigned_pem(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    return synth.make_cert(cn, key.public_key(), key).public_bytes(PEM)


# ---- trust-store layout: named files + hash links + one big bundle ---------------


@pytest.fixture()
def truststore(tmp_path):
    names = [f"Root_{i}.pem" for i in range(8)]
    pems = [selfsigned_pem(n) for n in names]
    for i, (n, p) in enumerate(zip(names, pems)):
        (tmp_path / n).write_bytes(p)
        os.symlink(n, tmp_path / f"{i:08x}.0")  # c_rehash-style link
    (tmp_path / "ca-certificates.crt").write_bytes(b"".join(pems))
    return tmp_path


def test_trust_store_does_not_flag_every_ca_key(truststore):
    report = scan([truststore])
    assert report.findings == []


def test_symlink_aliases_are_collapsed_and_counted(truststore):
    corpus = load_paths([truststore])
    assert corpus.files_skipped == 8
    assert corpus.files_read == 9  # 8 named files + the bundle
    labels = {k.source.split("#")[0].rsplit("/", 1)[-1] for k in corpus.keys}
    assert not any(l.endswith(".0") for l in labels)  # readable names win


def test_real_sharing_is_still_found_next_to_a_bundle(truststore):
    """A key that really appears in two stand-alone files stays a finding."""
    (truststore / "Root_0_copy.pem").write_bytes((truststore / "Root_0.pem").read_bytes())
    report = scan([truststore])
    assert [f.check for f in report.findings] == ["duplicate-key"]
    assert report.findings[0].data["holders"] == 2


# ---- known_hosts -----------------------------------------------------------------


def _ssh(key):
    return key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()


def test_known_hosts_same_key_twice_is_medium_with_alias_note(tmp_path):
    k1, k2 = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    (tmp_path / "known_hosts").write_text(
        f"example.org {_ssh(k1)}\n93.184.216.34 {_ssh(k1)}\nother {_ssh(k2)}\n"
    )
    [f] = scan([tmp_path]).findings
    assert f.check == "duplicate-key"
    assert f.severity == Severity.MEDIUM
    assert f.data["note"] == "alias_or_clone"


def test_known_hosts_three_hosts_with_one_key_is_high(tmp_path):
    k = ed25519.Ed25519PrivateKey.generate()
    (tmp_path / "known_hosts").write_text("".join(f"h{i} {_ssh(k)}\n" for i in range(3)))
    [f] = scan([tmp_path]).findings
    assert f.severity == Severity.HIGH and f.data["note"] == "alias_or_clone"


# ---- serial numbers ----------------------------------------------------------------


def rec(i, serial, issued="2024-01-01T00:00:00+00:00", issuer="CN=CA"):
    return KeyRecord(
        source=f"c{i}.pem#0", algorithm="ec", fingerprint=f"key{i}", cert_serial=serial,
        cert_issuer=issuer, cert_subject=f"CN=d{i}", cert_not_before=issued,
        cert_fingerprint=f"cert{i}",
    )


CFG = AuditConfig()


def test_certificates_older_than_the_rule_are_not_judged():
    old = [rec(i, 5 + i, issued="2009-05-01T00:00:00+00:00") for i in range(3)]
    assert check_serials(old, CFG) == []
    new = [rec(i, 5 + i, issued="2020-05-01T00:00:00+00:00", issuer=f"CN=I{i}") for i in range(3)]
    assert [f.check for f in check_serials(new, CFG)] == ["serial-short"]


def test_exemption_is_reported_in_the_finding():
    mixed = [rec(1, 7, issued="2009-01-01T00:00:00+00:00"),
             rec(2, 7, issued="2021-01-01T00:00:00+00:00", issuer="CN=Other")]
    [f] = check_serials(mixed, CFG)
    assert f.data == {"count": 1, "exempt_before_2016_09_30": 1}


def test_random_64_bit_serials_are_not_flagged_but_63_bit_issuers_are():
    rng = random.Random(5)
    ok = [rec(i, rng.getrandbits(64)) for i in range(40)]
    assert check_serials(ok, CFG) == []  # about half have bit_length 64: fine
    bad = [rec(i, rng.getrandbits(63)) for i in range(40)]
    assert {f.check for f in check_serials(bad, CFG)} == {"serial-short", "serial-predictable"}


def test_single_mid_length_serial_is_not_flagged():
    assert check_serials([rec(1, (1 << 56) + 12345)], CFG) == []  # 57 bits: chance for a 64-bit draw
    assert [f.check for f in check_serials([rec(1, (1 << 31) + 5)], CFG)] == ["serial-short"]


def test_non_positive_serials_are_reported_with_age_aware_severity():
    old = [rec(1, -128, issued="2005-01-01T00:00:00+00:00")]
    [f] = check_serials(old, CFG)
    assert (f.check, f.severity) == ("serial-invalid", Severity.INFO)
    new = [rec(2, 0, issued="2024-01-01T00:00:00+00:00")]
    [f] = check_serials(new, CFG)
    assert (f.check, f.severity) == ("serial-invalid", Severity.LOW)


# ---- a real certificate with a negative serial: no warning noise, a finding ---------


def _der_len(n):
    return bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")


def with_negative_serial(cert):
    """Rewrite the serial of a DER certificate to the single byte 0x80 (-128)."""
    der = cert.public_bytes(serialization.Encoding.DER)
    tbs = cert.tbs_certificate_bytes
    h_out = synth._tlv_header(der, 0)[0]
    h_tbs = synth._tlv_header(tbs, 0)[0]
    pos = h_tbs + 5  # skip [0] version (a0 03 02 01 02)
    assert tbs[pos] == 0x02
    h, l = synth._tlv_header(tbs, pos)
    new_tbs_body = tbs[h_tbs:pos] + b"\x02\x01\x80" + tbs[pos + h + l :]
    new_tbs = b"\x30" + _der_len(len(new_tbs_body)) + new_tbs_body
    rest = der[h_out + len(tbs) :]
    body = new_tbs + rest
    return b"\x30" + _der_len(len(body)) + body


def test_negative_serial_cert_loads_quietly_and_is_reported(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = synth.make_cert("old-root", key.public_key(), key)
    (tmp_path / "old.der").write_bytes(with_negative_serial(cert))
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any leaked warning would raise
        corpus = load_paths([tmp_path])
        report = run_audit(corpus, CFG)
    assert corpus.keys[0].cert_serial == -128
    assert [f.check for f in report.findings] == ["serial-invalid"]

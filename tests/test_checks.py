"""Unit tests for individual checks, including false-positive guards."""

import random

from keyceratops import synth
from keyceratops.audit import run_audit
from keyceratops.checks import (
    AuditConfig,
    check_ecdsa,
    check_serials,
    holder,
)
from keyceratops.ingest import Corpus
from keyceratops.model import KeyRecord, Severity, SignatureRecord
from keyceratops.report import render_json, render_markdown, render_text

CFG = AuditConfig()


def sig(signer, r, s, curve=None):
    return SignatureRecord(source=f"{signer}/{r}/{s}", pub_fingerprint=signer, r=r, s=s, curve=curve)


# ---- ECDSA ------------------------------------------------------------------


def test_same_r_different_s_same_key_is_critical():
    out = check_ecdsa([sig("A", 5, 10), sig("A", 5, 11)], CFG)
    assert [f.check for f in out] == ["ecdsa-nonce-reuse"]
    assert out[0].severity == Severity.CRITICAL


def test_identical_signature_seen_twice_is_not_nonce_reuse():
    assert check_ecdsa([sig("A", 5, 10), sig("A", 5, 10)], CFG) == []


def test_same_r_across_keys_is_high_not_critical():
    out = check_ecdsa([sig("A", 5, 10), sig("B", 5, 12)], CFG)
    assert [(f.check, f.severity) for f in out] == [("ecdsa-shared-r", Severity.HIGH)]


def test_distinct_nonces_clean():
    rng = random.Random(1)
    sigs = [sig(f"K{i % 4}", rng.getrandbits(256), rng.getrandbits(256), "secp256r1") for i in range(500)]
    assert check_ecdsa(sigs, CFG) == []


def test_small_r_flags_bias_only_with_known_curve():
    small = (1 << 200) + 12345  # 201 bits: 55 bits shorter than the order
    assert [f.check for f in check_ecdsa([sig("A", small, 7, "secp256r1")], CFG)] == ["ecdsa-biased-nonce"]
    assert check_ecdsa([sig("A", small, 7, None)], CFG) == []
    # 24 bits short is within chance for a large corpus, must not trigger
    ok = (1 << 231) + 1
    assert check_ecdsa([sig("A", ok, 7, "secp256r1")], CFG) == []


def test_real_nonce_reuse_is_algebraically_real():
    """Sanity-check the premise: reusing k with the planted signer really does
    give equal r and different s."""
    d, k = 0x1234567, 0xABCDEF1
    r1, s1 = synth.ecdsa_sign_p256(d, b"m1", k)
    r2, s2 = synth.ecdsa_sign_p256(d, b"m2", k)
    assert r1 == r2 and s1 != s2


# ---- serials ------------------------------------------------------------------


def cert(i, serial, issuer="CN=CA", fp=None):
    return KeyRecord(
        source=f"c{i}.pem#0", algorithm="ec", fingerprint=f"key{i}", cert_serial=serial,
        cert_issuer=issuer, cert_subject=f"CN=d{i}", cert_fingerprint=fp or f"cert{i}",
    )


def test_random_long_serials_are_clean():
    rng = random.Random(2)
    keys = [cert(i, rng.getrandbits(127) | 1 << 126) for i in range(200)]
    assert check_serials(keys, CFG) == []


def test_counter_serials_are_flagged_low():
    keys = [cert(i, 1000 + i) for i in range(60)]
    out = check_serials(keys, CFG)
    assert {f.check for f in out} == {"serial-short", "serial-predictable"}
    assert next(f for f in out if f.check == "serial-predictable").severity == Severity.LOW


def test_small_population_gets_no_statistical_verdict():
    keys = [cert(i, (1 << 70) + i) for i in range(10)]
    assert check_serials(keys, CFG) == []


def test_same_certificate_seen_twice_is_not_a_collision():
    keys = [cert(1, 1 << 100, fp="same"), cert(1, 1 << 100, fp="same")]
    assert check_serials(keys, CFG) == []


def test_serial_collision_across_issuers_is_fine():
    keys = [cert(1, 1 << 100, issuer="CN=A"), cert(2, 1 << 100, issuer="CN=B")]
    assert check_serials(keys, CFG) == []


# ---- holders ------------------------------------------------------------------


def test_holder_resolution():
    mk = lambda src: KeyRecord(source=src, algorithm="rsa", fingerprint="x")
    assert holder(mk("/a/b/c.pem#3")) == "file:/a/b/c.pem"
    assert holder(mk("/a/b/kh:7 [web1.example]")) == "host:web1.example"
    assert holder(mk("/a/b/c.pem#0"), "dir") == "dir:/a/b"


# ---- reporting never leaks private material ------------------------------------


def test_reports_never_contain_recovered_primes():
    rng = random.Random(11)
    p = synth.rand_prime(512, rng)
    q1, q2 = synth.rand_prime(512, rng), synth.rand_prime(512, rng)
    from keyceratops.ingest import key_record
    from cryptography.hazmat.primitives.asymmetric import rsa

    corpus = Corpus()
    for i, q in enumerate((q1, q2)):
        pub = rsa.RSAPublicNumbers(65537, p * q).public_key()
        corpus.keys.append(key_record(pub, f"dev{i}.pem#0"))
    report = run_audit(corpus, CFG)
    assert [f.check for f in report.findings if f.check == "shared-prime"]
    for text in (render_json(report), render_text(report, True), render_markdown(report)):
        for secret in (p, q1, q2):
            assert str(secret) not in text
            assert format(secret, "x") not in text
            assert hex(secret) not in text


def _rsa_record(i, n, e=65537):
    return KeyRecord(source=f"k{i}.pem#0", algorithm="rsa", fingerprint=f"fp{i}-{e}",
                     bits=n.bit_length(), modulus=n, exponent=e)


def test_tiny_modulus_is_critical_and_short_is_high():
    rng = random.Random(21)
    tiny = synth.rand_prime(256, rng) * synth.rand_prime(256, rng)      # 512 bits
    short = synth.rand_prime(768, rng) * synth.rand_prime(768, rng)     # 1536 bits
    fine = synth.rand_prime(1024, rng) * synth.rand_prime(1024, rng)    # 2048 bits
    corpus = Corpus(keys=[_rsa_record(1, tiny), _rsa_record(2, short), _rsa_record(3, fine)])
    sev = {f.check: f.severity for f in run_audit(corpus, CFG).findings}
    assert sev == {"rsa-tiny": Severity.CRITICAL, "rsa-short": Severity.HIGH}


def test_modulus_two_bits_under_2048_is_not_flagged():
    """Some generators emit 2047-bit moduli for '2048-bit' keys; not a finding."""
    rng = random.Random(22)
    # primes just above 2^1023 (only the top bit set) multiply to 2047 bits
    # (spread them out: primes within ~2^64 of each other are, correctly, flagged)
    p = synth.next_prime((1 << 1023) + rng.getrandbits(1000), rng)
    q = synth.next_prime((1 << 1023) + rng.getrandbits(1000), rng)
    n = p * q
    assert n.bit_length() == 2047
    assert run_audit(Corpus(keys=[_rsa_record(1, n)]), CFG).findings == []


def test_common_modulus_with_different_exponents():
    rng = random.Random(23)
    n = synth.rand_prime(1024, rng) * synth.rand_prime(1024, rng)
    corpus = Corpus(keys=[_rsa_record(1, n, 65537), _rsa_record(2, n, 17)])
    checks = {f.check for f in run_audit(corpus, CFG).findings}
    assert "common-modulus" in checks


def test_invalid_exponent_is_high():
    rng = random.Random(24)
    n = synth.rand_prime(1024, rng) * synth.rand_prime(1024, rng)
    corpus = Corpus(keys=[_rsa_record(1, n, 4), _rsa_record(2, n + 2, 1)])
    sev = {f.check: f.severity for f in run_audit(corpus, CFG).findings}
    assert sev["rsa-bad-exponent"] == Severity.HIGH


def test_warns_when_large_scan_runs_without_gmpy2(monkeypatch):
    import pytest

    from keyceratops import checks
    from keyceratops import numtheory as nt

    rng = random.Random(9)
    keys = [
        KeyRecord(source=f"k{i}", algorithm="rsa", fingerprint=f"f{i}",
                  modulus=rng.getrandbits(256) | 1, exponent=65537)
        for i in range(checks.PURE_PYTHON_WARN_AT + 1)
    ]
    monkeypatch.setattr(nt, "HAVE_GMPY2", False)
    with pytest.warns(RuntimeWarning, match="gmpy2"):
        checks.check_shared_factors(keys, CFG, set())


# ---- structural RSA edge cases ---------------------------------------------------


def test_rsa_exponent_findings():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from keyceratops.ingest import key_record

    rng = random.Random(8)
    n = synth.rand_prime(1024, rng) * synth.rand_prime(1024, rng)
    corpus = Corpus()
    corpus.keys.append(key_record(rsa.RSAPublicNumbers(3, n).public_key(), "e3.pem#0"))
    checks = {f.check: f.severity for f in run_audit(corpus, CFG).findings}
    assert checks == {"rsa-low-exponent": Severity.LOW}

    clean = Corpus()
    clean.keys.append(key_record(rsa.RSAPublicNumbers(65537, n).public_key(), "e65537.pem#0"))
    assert run_audit(clean, CFG).findings == []

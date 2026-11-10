"""End-to-end: every planted failure is found, nothing else is reported."""

from cryptography import x509

from conftest import scan
from keyceratops.model import Severity

# manifest key -> check name that must fire
EXPECTED = {
    "shared-prime": "shared-prime",
    "duplicate-key": "duplicate-key",
    "rsa-even": "rsa-even",
    "rsa-small-factor": "rsa-small-factor",
    "rsa-square": "rsa-square",
    "rsa-close-primes": "rsa-close-primes",
    "rsa-short": "rsa-short",
    "ecdsa-shared-r": "ecdsa-shared-r",
    "ecdsa-nonce-reuse": "ecdsa-nonce-reuse",
    "ecdsa-nonce-reuse-jsonl": "ecdsa-nonce-reuse",
    "serial-short": "serial-short",
    "serial-collision": "serial-collision",
}


def _full_scan(fleet):
    root, manifest = fleet
    return scan([root], sigs=[root / "signatures.jsonl"]), manifest


def test_every_planted_failure_is_detected(fleet):
    report, manifest = _full_scan(fleet)
    for planted, check in EXPECTED.items():
        sources = [s for f in report.findings if f.check == check for s in f.sources]
        for rel in manifest[planted]:
            assert any(rel in s for s in sources), f"{planted}: {rel} not reported by {check}"


def test_no_unexpected_checks_fire(fleet):
    report, _ = _full_scan(fleet)
    assert {f.check for f in report.findings} == set(EXPECTED.values())


def test_healthy_devices_produce_no_findings(fleet):
    root, _ = fleet
    report = scan([root / "healthy"])
    assert report.findings == []
    assert report.stats["unique_keys"] == 16 + 8 + 8  # rsa + ec + ssh


def test_shared_prime_clusters_are_separated_correctly(fleet):
    report, manifest = _full_scan(fleet)
    clusters = [f for f in report.findings if f.check == "shared-prime"]
    assert sorted(f.data["moduli"] for f in clusters) == [3, 3]
    groups = [sorted(s.rsplit("/", 1)[-1] for s in f.sources) for f in clusters]
    assert ["sharedprime-0.pem#0", "sharedprime-1.pem#0", "sharedprime-2.pem#0"] in groups
    assert ["sharedprime-x.pem#0", "sharedprime-y.pem#0", "sharedprime-z.pem#0"] in groups


def test_severities(fleet):
    report, _ = _full_scan(fleet)
    sev = {}
    for f in report.findings:
        sev.setdefault(f.check, set()).add(f.severity)
    assert sev["shared-prime"] == {Severity.CRITICAL}
    assert sev["ecdsa-nonce-reuse"] == {Severity.CRITICAL}
    assert sev["duplicate-key"] == {Severity.CRITICAL}  # 12 holders
    assert sev["ecdsa-shared-r"] == {Severity.HIGH}
    assert sev["serial-short"] == {Severity.MEDIUM}
    # a serial collision among 127-bit serials is stronger evidence than among short ones
    assert sev["serial-collision"] == {Severity.HIGH, Severity.MEDIUM}


def test_findings_are_sorted_most_severe_first(fleet):
    report, _ = _full_scan(fleet)
    sev = [int(f.severity) for f in report.findings]
    assert sev == sorted(sev, reverse=True)


def test_holder_modes(fleet):
    # With holder=dir every flawed/ file is one holder, so the 12 default keys
    # (all in flawed/) are one holder and stop being a duplicate-key finding.
    from keyceratops.checks import AuditConfig

    root, _ = fleet
    report = scan([root / "flawed"], cfg=AuditConfig(holder_mode="dir"))
    assert not [f for f in report.findings if f.check == "duplicate-key"]


def test_resigned_certificates_are_valid(fleet):
    """The planted-nonce certificates must be genuine, verifiable certificates;
    otherwise the test above would be testing the parser, not the audit."""
    root, _ = fleet
    for name in ("samenonce-0.pem", "samenonce-1.pem"):
        cert = x509.load_pem_x509_certificate((root / "flawed" / name).read_bytes())
        cert.verify_directly_issued_by(cert)

"""Attribution (which software / model the affected holders share) and ROCA."""

import json
import math
import random

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import scan
from keyceratops import attribute, collect, numtheory, synth
from keyceratops.audit import run_audit
from keyceratops.checks import AuditConfig
from keyceratops.cli import main
from keyceratops.ingest import load_paths
from keyceratops.report import render_markdown, render_text
from test_collect import FakeSSH

CFG = AuditConfig(min_rsa_bits=1024)

# ---- ROCA -------------------------------------------------------------------


def _is_prime(n, rng):
    if numtheory.HAVE_GMPY2:
        import gmpy2

        return bool(gmpy2.is_prime(n))
    return synth._is_probable_prime(n, rng)


def roca_prime(bits, rng):
    """A prime with RSALib's structure: k*M + (65537^a mod M)."""
    m = math.prod(numtheory.ROCA_PRIMES)
    while True:
        k = rng.getrandbits(bits - m.bit_length()) | (1 << (bits - m.bit_length() - 1))
        p = k * m + pow(65537, rng.randrange(1, 1 << 20), m)
        if p.bit_length() == bits and _is_prime(p, rng):
            return p


def test_roca_fingerprint_positive_and_negative():
    rng = random.Random(5)
    n = roca_prime(512, rng) * roca_prime(512, rng)
    assert numtheory.roca_fingerprint(n)
    # ordinary moduli: the chance of a false positive is far below 2^-100
    for _ in range(40):
        assert not numtheory.roca_fingerprint(synth.rand_prime(256, rng) * synth.rand_prime(256, rng))
    assert not numtheory.roca_fingerprint(n + 2)


def test_roca_masks_match_published_values():
    # first entries of the masks in the authors' detector (crocs-muni/roca)
    assert [m for _r, m in numtheory._ROCA_MASKS[:6]] == [6, 30, 126, 1026, 5658, 107286]


def _rsa_pem(n, e=65537):
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def test_roca_key_is_reported_with_its_cause(tmp_path):
    rng = random.Random(9)
    (tmp_path / "token.pem").write_bytes(_rsa_pem(roca_prime(512, rng) * roca_prime(512, rng)))
    (tmp_path / "ok.pem").write_bytes(_rsa_pem(synth.rand_prime(512, rng) * synth.rand_prime(512, rng)))
    report = scan([tmp_path], cfg=CFG)
    roca = [f for f in report.findings if f.check == "rsa-roca"]
    assert len(roca) == 1
    assert roca[0].severity.name == "CRITICAL"  # 1024-bit
    assert roca[0].data["count"] == 1 and "token.pem" in roca[0].sources[0]
    assert "CVE-2017-15361" in roca[0].data["cause"]
    text = render_text(report, lang="ja")
    assert "ROCA" in text and "Infineon" in text


# ---- labels -------------------------------------------------------------------


@pytest.mark.parametrize("banner, want", [
    ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", {"software": "OpenSSH 9.6p1", "product": "OpenSSH"}),
    ("SSH-2.0-dropbear_2014.63", {"software": "dropbear 2014.63", "product": "dropbear"}),
    ("SSH-2.0-ROSSSH", {"software": "ROSSSH", "product": "ROSSSH"}),
    ("SSH-2.0-Cisco-1.25", {"software": "Cisco 1.25", "product": "Cisco"}),
    ("garbage", {}),
])
def test_parse_ssh_banner(banner, want):
    assert attribute.parse_ssh_banner(banner) == want


def test_load_inventory(tmp_path):
    f = tmp_path / "inv.csv"
    f.write_text("Host,Vendor,Model,Firmware,Location\n"
                 "cam1,Acme,X1,1.2,lobby\n"
                 "cam2,Acme,,,\n"
                 ",Acme,X1,1.2,\n")
    inv = attribute.load_inventory(f)
    assert inv == {"cam1": {"vendor": "Acme", "model": "Acme X1", "firmware": "Acme X1 1.2"},
                   "cam2": {"vendor": "Acme"}}
    bad = tmp_path / "bad.csv"
    bad.write_text("name,vendor\ncam1,Acme\n")
    with pytest.raises(ValueError):
        attribute.load_inventory(bad)


def test_fisher_exact_values():
    # all 3 affected holders carry the label, which 3 of 10 holders have
    assert attribute.fisher_greater(3, 3, 3, 10) == pytest.approx(1 / 120)
    # no enrichment at all: P(X >= 0) = 1
    assert attribute.fisher_greater(0, 4, 3, 10) == pytest.approx(1.0)
    # against a direct sum of the hypergeometric distribution
    want = sum(math.comb(5, x) * math.comb(15, 8 - x) for x in range(3, 6)) / math.comb(20, 8)
    assert attribute.fisher_greater(3, 8, 5, 20) == pytest.approx(want)


# ---- fleets with labels -------------------------------------------------------


def _snapshot(path, records):
    lines = [{"kind": "meta", "tool": "keyceratops", "format": 1}] + records
    path.write_text("".join(json.dumps(r) + "\n" for r in lines))


def _ssh_line(n):
    pub = rsa.RSAPublicNumbers(65537, n).public_key()
    return pub.public_bytes(serialization.Encoding.OpenSSH,
                            serialization.PublicFormat.OpenSSH).decode()


def _fleet(tmp_path, bad=6, good=14, seed=3):
    """bad hosts run dropbear 2014.63 and share one prime; good hosts run OpenSSH."""
    rng = random.Random(seed)
    shared = synth.rand_prime(512, rng)
    recs = []
    for i in range(bad + good):
        host = f"10.0.0.{i + 1}"
        if i < bad:
            n, banner = shared * synth.rand_prime(512, rng), "SSH-2.0-dropbear_2014.63"
        else:
            n, banner = synth.rand_prime(512, rng) * synth.rand_prime(512, rng), "SSH-2.0-OpenSSH_9.6"
        recs.append({"kind": "software", "host": host, "port": 22, "proto": "ssh", "banner": banner})
        recs.append({"kind": "sshkey", "host": host, "port": 22, "key": _ssh_line(n)})
    _snapshot(tmp_path / "fleet.jsonl", recs)
    return tmp_path / "fleet.jsonl"


def test_affected_software_is_singled_out(tmp_path):
    report = scan([_fleet(tmp_path)], cfg=CFG)
    assert [f.check for f in report.findings] == ["shared-prime"]
    assert report.findings[0].data["software"] == {"dropbear 2014.63": 6}
    top = report.associations[0]
    assert (top.dimension, top.label) == ("software", "dropbear 2014.63")
    assert (top.affected, top.holders, top.affected_other, top.holders_other) == (6, 6, 0, 14)
    assert top.significant and top.checks == ["shared-prime"]
    # "product dropbear" covers exactly the same hosts: reported once, not twice
    assert len(report.associations) == 1

    text = render_text(report, lang="ja")
    assert "原因の手がかり" in text and "SSHソフト dropbear 2014.63: 6/6台" in text
    md = render_markdown(report, lang="en")
    assert "## Leads" in md
    data = json.loads(main_json(tmp_path))
    assert data["associations"][0]["label"] == "dropbear 2014.63"


def main_json(tmp_path):
    out = tmp_path / "r.json"
    main(["scan", str(tmp_path / "fleet.jsonl"), "-f", "json", "-o", str(out),
          "--min-rsa-bits", "1024"])
    return out.read_text()


def test_no_lead_when_the_problem_is_spread_evenly(tmp_path):
    rng = random.Random(4)
    shared = synth.rand_prime(512, rng)
    recs = []
    for i in range(12):
        host = f"h{i}"
        n = shared * synth.rand_prime(512, rng) if i % 4 == 0 else (
            synth.rand_prime(512, rng) * synth.rand_prime(512, rng))
        banner = "SSH-2.0-OpenSSH_9.6" if i % 2 == 0 else "SSH-2.0-dropbear_2022.83"
        recs += [{"kind": "software", "host": host, "banner": banner},
                 {"kind": "sshkey", "host": host, "key": _ssh_line(n)}]
    _snapshot(tmp_path / "s.jsonl", recs)
    report = scan([tmp_path / "s.jsonl"], cfg=CFG)
    assert report.findings and not any(a.significant for a in report.associations)


def test_lead_survives_the_source_cap(tmp_path):
    """Attribution counts every holder even though findings list only max_list."""
    key = _ssh_line(synth.rand_prime(512, random.Random(1)) * synth.rand_prime(512, random.Random(2)))
    rng = random.Random(8)
    recs = []
    for i in range(100):
        host = f"cam{i}"
        clone = i < 60
        line = key if clone else _ssh_line(synth.rand_prime(512, rng) * synth.rand_prime(512, rng))
        recs += [{"kind": "software", "host": host,
                  "banner": "SSH-2.0-dropbear_2012.55" if clone else "SSH-2.0-OpenSSH_9.6"},
                 {"kind": "sshkey", "host": host, "key": line}]
    _snapshot(tmp_path / "s.jsonl", recs)
    report = scan([tmp_path / "s.jsonl"], cfg=CFG)
    dup = [f for f in report.findings if f.check == "duplicate-key"][0]
    assert len(dup.sources) == AuditConfig().max_list and dup.data["holders"] == 60
    assert dup.data["software"] == {"dropbear 2012.55": 60}  # counted before the cap
    top = report.associations[0]
    assert (top.label, top.affected, top.holders) == ("dropbear 2012.55", 60, 60)


def test_inventory_by_directory(tmp_path):
    rng = random.Random(6)
    shared = synth.rand_prime(512, rng)
    rows = ["host,vendor,model,firmware"]
    for i in range(10):
        d = tmp_path / "fleet" / f"dev{i:02d}"
        d.mkdir(parents=True)
        bad = i < 4
        n = shared * synth.rand_prime(512, rng) if bad else (
            synth.rand_prime(512, rng) * synth.rand_prime(512, rng))
        (d / "key.pem").write_bytes(_rsa_pem(n))
        rows.append(f"{d},Acme,{'R2' if bad else 'R3'},{'1.0' if bad else '2.4'}")
    inv = tmp_path / "inv.csv"
    inv.write_text("\n".join(rows) + "\n")
    corpus = load_paths([tmp_path / "fleet"])
    report = run_audit(corpus, CFG, attribute.load_inventory(inv))
    top = report.associations[0]
    # firmware and model cover the same four devices: the specific one is kept
    assert (top.dimension, top.label, top.affected, top.holders) == ("firmware", "Acme R2 1.0", 4, 4)
    assert report.stats["labelled_holders"] == 10


def test_self_signed_certificate_organisation_is_a_label(tmp_path):
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Acme, Inc."),
                      x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "cam")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime(2024, 1, 1)).not_valid_after(dt.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    corpus = load_paths([tmp_path])
    labels = attribute.holder_labels(corpus.keys, corpus.signatures, {}, None)
    assert list(labels.values()) == [{"cert-org": "Acme, Inc."}]


def test_no_labels_means_no_attribution_section(tmp_path):
    report = scan([_fleet(tmp_path)], cfg=CFG)
    report.stats["labelled_holders"] = 0
    assert "原因の手がかり" not in render_text(report, lang="ja")


def test_cli_inventory_errors(tmp_path, capsys):
    path = _fleet(tmp_path)
    assert main(["scan", str(path), "--inventory", str(tmp_path / "missing.csv")]) == 2
    bad = tmp_path / "bad.csv"
    bad.write_text("name\nx\n")
    assert main(["scan", str(path), "--inventory", str(bad)]) == 2


# ---- collect records the software --------------------------------------------


def test_collect_records_the_ssh_banner(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec

    d = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
    srv = FakeSSH(d, nonce=12345)
    try:
        snap = tmp_path / "s.jsonl"
        t = collect.Target("ssh", "127.0.0.1", srv.port)
        collect.collect([t], snap, samples=2, timeout=5, delay=0)
        collect.collect([t], snap, samples=1, timeout=5, delay=0)
    finally:
        srv.close()
    recs = [json.loads(x) for x in snap.read_text().splitlines()]
    sw = [r for r in recs if r["kind"] == "software"]
    assert len(sw) == 1 and sw[0]["banner"] == "SSH-2.0-FakeSSH_1.0"  # stored once
    report = scan([snap])
    reuse = [f for f in report.findings if f.check == "ecdsa-nonce-reuse"][0]
    assert reuse.data["software"] == {"FakeSSH 1.0": 1}

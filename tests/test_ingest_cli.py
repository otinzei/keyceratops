import hashlib
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from conftest import scan
from rngaudit import synth
from rngaudit.cli import main
from rngaudit.ingest import load_file, load_paths, load_signatures

PEM, DER = serialization.Encoding.PEM, serialization.Encoding.DER
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def ssh_line(key):
    return key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()


# ---- ingest ----------------------------------------------------------------


def test_ssh_authorized_keys_and_known_hosts(tmp_path):
    a, b = ed25519.Ed25519PrivateKey.generate(), ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "authorized_keys").write_text(
        "# comment\n" + 'command="x",no-pty ' + ssh_line(a) + " me@laptop\n"
    )
    (tmp_path / "known_hosts").write_text(f"web1.example {ssh_line(b)}\n\n")
    corpus = load_paths([tmp_path])
    assert sorted(k.algorithm for k in corpus.keys) == ["ec", "ed25519"]
    assert any("[web1.example]" in k.source for k in corpus.keys)
    assert corpus.errors == []


def test_der_certificate_and_der_public_key(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = synth.make_cert("d", key.public_key(), key)
    (tmp_path / "c.der").write_bytes(cert.public_bytes(DER))
    (tmp_path / "k.der").write_bytes(
        ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(DER, SPKI)
    )
    corpus = load_paths([tmp_path])
    assert {k.curve for k in corpus.keys} == {"secp256r1", "secp384r1"}
    assert corpus.keys[0].cert_serial is not None or corpus.keys[1].cert_serial is not None


def test_private_keys_are_never_read(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "priv.pem").write_bytes(
        key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    corpus = load_file(tmp_path / "priv.pem")
    assert corpus.keys == []
    assert any("private key skipped" in m for _, m in corpus.errors)


def test_garbage_and_missing_inputs_do_not_crash(tmp_path):
    (tmp_path / "bad.pem").write_bytes(
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    )
    (tmp_path / "junk.crt").write_bytes(b"\x00\x01\x02")
    corpus = load_paths([tmp_path, tmp_path / "nope.pem"])
    assert corpus.keys == []
    assert len(corpus.errors) == 3


def test_certificate_bundle_yields_each_block(tmp_path):
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    bundle = b"".join(
        synth.make_cert(f"d{i}", k.public_key(), k).public_bytes(PEM) for i, k in enumerate(keys)
    )
    (tmp_path / "b.pem").write_bytes(bundle)
    assert len(load_paths([tmp_path]).keys) == 3


def test_signature_jsonl_variants(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(PEM, SPKI).decode()
    der_hex = key.public_key().public_bytes(DER, SPKI).hex()
    lines = [
        {"pub": pem, "r": "0x10", "s": "20"},
        {"pub": der_hex, "sig": encode_dss_signature(0x10, 0x21).hex(), "z": "ff"},
        {"key_id": "dev-1", "r": 5, "s": 6, "source": "capture-1"},
        {"r": "1", "s": "2"},  # no signer -> error, others unaffected
    ]
    p = tmp_path / "s.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\nnot json\n")
    corpus = load_signatures(p)
    assert len(corpus.signatures) == 3
    assert len(corpus.errors) == 2
    # PEM and DER-hex forms of the same key give the same signer id
    assert corpus.signatures[0].pub_fingerprint == corpus.signatures[1].pub_fingerprint
    assert corpus.signatures[0].r == 0x10 and corpus.signatures[1].s == 0x21
    assert corpus.signatures[2].source == "capture-1"


def test_signature_file_missing(tmp_path):
    corpus = load_signatures(tmp_path / "nope.jsonl")
    assert corpus.signatures == [] and corpus.errors


# ---- CLI ----------------------------------------------------------------------


def test_cli_exit_codes(fleet, capsys, tmp_path):
    root, _ = fleet
    assert main(["scan", str(root / "healthy")]) == 0
    assert main(["scan", str(root)]) == 1
    assert main(["scan", str(root), "--fail-on", "never"]) == 0
    assert main(["scan", str(root), "--fail-on", "bogus"]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["scan", str(empty)]) == 2
    capsys.readouterr()


def test_cli_fail_on_threshold(fleet):
    root, _ = fleet
    only_medium = root / "flawed"  # contains critical; narrow to the serial files instead
    files = [str(p) for p in only_medium.glob("legacy-*.pem")]
    assert main(["scan", *files]) == 0  # medium < default high
    assert main(["scan", *files, "--fail-on", "medium"]) == 1


def test_cli_json_and_output_file(fleet, tmp_path, capsys):
    root, _ = fleet
    out = tmp_path / "r.json"
    code = main(["scan", str(root), "--sigs", str(root / "signatures.jsonl"),
                 "-f", "json", "-o", str(out), "--fail-on", "never"])
    assert code == 0 and capsys.readouterr().out == ""
    doc = json.loads(out.read_text())
    assert doc["tool"] == "rngaudit"
    assert doc["summary"]["CRITICAL"] >= 8
    assert all({"check", "severity", "title", "detail", "sources", "fingerprints"} <= set(f)
               for f in doc["findings"])


def test_cli_markdown_and_text(fleet, capsys):
    root, _ = fleet
    main(["scan", str(root), "-f", "md", "--fail-on", "never"])
    md = capsys.readouterr().out
    assert md.startswith("# rngaudit") and "CRITICAL" in md and "shared-prime" in md
    main(["scan", str(root / "healthy"), "--lang", "en", "--color", "never"])
    out = capsys.readouterr().out
    assert "no problems" in out.lower() and "\x1b[" not in out
    main(["scan", str(root / "healthy"), "--lang", "ja"])
    assert "判定" in capsys.readouterr().out


def test_cli_text_language_and_truncation(fleet, capsys):
    root, _ = fleet
    main(["scan", str(root), "--lang", "ja", "--fail-on", "never", "--max-items", "1"])
    ja = capsys.readouterr().out
    assert "判定" in ja and "何が問題か" in ja
    assert ja.count("[shared-prime]") == 1  # explanation printed once per check
    main(["scan", str(root), "--lang", "en", "--fail-on", "never", "--color", "always"])
    assert "\x1b[" in capsys.readouterr().out


def test_cli_entropy(tmp_path, capsys):
    import os

    good, stuck = tmp_path / "good.bin", tmp_path / "stuck.bin"
    good.write_bytes(os.urandom(200_000))
    stuck.write_bytes(b"\x00" * 10_000)
    assert main(["entropy", str(good), "--claim-h", "7"]) == 0
    assert main(["entropy", str(stuck)]) == 1
    assert main(["entropy", str(tmp_path / "missing.bin")]) == 2
    assert main(["entropy", str(good), "--bits", "9"]) == 2
    capsys.readouterr()
    main(["entropy", str(good), "--claim-h", "7", "-f", "json"])
    assert json.loads(capsys.readouterr().out)["healthy"] is True
    # over-claiming exits non-zero
    assert main(["entropy", str(good), "--claim-h", "8"]) == 1


def test_cli_demo_roundtrip(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", str(out)]) == 0
    assert main(["demo", str(out)]) == 2  # refuses to write into a non-empty dir
    capsys.readouterr()
    assert main(["scan", str(out), "--sigs", str(out / "signatures.jsonl")]) == 1
    assert "shared-prime" in capsys.readouterr().out


def test_scan_is_deterministic(fleet):
    root, _ = fleet
    a = scan([root], sigs=[root / "signatures.jsonl"])
    b = scan([root], sigs=[root / "signatures.jsonl"])
    assert [f.to_dict() for f in a.findings] == [f.to_dict() for f in b.findings]


def test_fingerprint_is_sha256_of_spki(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "k.pem").write_bytes(key.public_key().public_bytes(PEM, SPKI))
    k = load_paths([tmp_path]).keys[0]
    assert k.fingerprint == hashlib.sha256(key.public_key().public_bytes(DER, SPKI)).hexdigest()

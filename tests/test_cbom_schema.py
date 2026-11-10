"""The CBOM output validates against the official CycloneDX 1.6 schema."""

import datetime as dt
import json
import random
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from conftest import scan
from keyceratops import synth
from keyceratops.cbom import render_cbom
from test_pqc import _write, cert

jsonschema = pytest.importorskip("jsonschema")
referencing = pytest.importorskip("referencing")

SCHEMAS = Path(__file__).parent / "data" / "cyclonedx"


def validator():
    from referencing.jsonschema import DRAFT7

    resources = []
    for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        doc = json.loads((SCHEMAS / name).read_text())
        resources.append((doc["$id"], DRAFT7.create_resource(doc)))
    registry = referencing.Registry().with_resources(resources)
    schema = json.loads((SCHEMAS / "bom-1.6.schema.json").read_text())
    return jsonschema.Draft7Validator(
        schema, registry=registry, format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER)


def _errors(bom):
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message}"
            for e in validator().iter_errors(bom)]


def _snapshot(path, records):
    lines = [{"kind": "meta", "tool": "keyceratops", "format": 1}] + records
    path.write_text("".join(json.dumps(r) + "\n" for r in lines))


def test_full_cbom_is_schema_valid(tmp_path):
    shared = rsa.generate_private_key(65537, 1024)
    _write(tmp_path / "a.pem", cert(shared, "a"))
    _write(tmp_path / "b.pem", cert(shared, "b"))  # duplicate key -> vulnerability
    _write(tmp_path / "c.pem", cert(ec.generate_private_key(ec.SECP384R1()), "c",
                                    not_after=dt.datetime(2034, 1, 1)))
    _write(tmp_path / "d.pem", cert(ed25519.Ed25519PrivateKey.generate(), "d", alg=None))
    # post-quantum public keys (OIDs only matter to the inventory)
    mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    pq = mldsa.MLDSA65PrivateKey.generate().public_key()
    (tmp_path / "pq.pem").write_bytes(pq.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    rng = random.Random(1)
    n = synth.rand_prime(512, rng) * synth.rand_prime(512, rng)
    ssh = rsa.RSAPublicNumbers(65537, n).public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    _snapshot(tmp_path / "net.jsonl", [
        {"kind": "software", "host": "10.0.0.9", "port": 22, "banner": "SSH-2.0-dropbear_2020.81",
         "kex": ["curve25519-sha256", "ecdh-sha2-nistp256"]},
        {"kind": "sshkey", "host": "10.0.0.9", "port": 22, "key": ssh},
        {"kind": "tls-groups", "host": "10.0.0.9", "port": 443,
         "groups": {"X25519MLKEM768": True, "SecP256r1MLKEM768": False}},
    ])
    report = scan([tmp_path])
    bom = json.loads(render_cbom(report))

    kinds = {c["cryptoProperties"]["assetType"] for c in bom["components"]}
    assert kinds == {"algorithm", "related-crypto-material", "certificate", "protocol"}
    assert bom.get("vulnerabilities")
    assert any(c["name"] == "ML-DSA-65" for c in bom["components"])
    assert _errors(bom) == []


def test_empty_cbom_is_schema_valid(tmp_path):
    (tmp_path / "x.txt").write_text("nothing here\n")
    report = scan([tmp_path])
    assert _errors(json.loads(render_cbom(report))) == []


def test_validator_catches_a_bad_bom():
    """Guard against a validator that accepts anything."""
    bad = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "components": [{"type": "cryptographic-asset", "name": "x",
                           "cryptoProperties": {"assetType": "not-a-type"}}]}
    assert _errors(bad)

"""CycloneDX 1.6 CBOM (cryptography bill of materials).

Components:

* one ``algorithm`` asset per algorithm / parameter set,
* one ``related-crypto-material`` asset (public key) per distinct key, with
  every place it was seen as an evidence occurrence,
* one ``certificate`` asset per distinct certificate,
* one ``protocol`` asset per TLS / SSH endpoint seen by ``collect``.

Findings become CycloneDX ``vulnerabilities`` that reference the affected key
components, so the CBOM carries the health check along with the inventory.
Nothing secret is included: keys appear by fingerprint, never by value.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from collections import defaultdict

from . import __version__, pqc
from .audit import Report
from .explain import advice_en

_CRYPTO_FUNCTIONS = {"signature": ["sign", "verify"], "kem": ["keygen", "encapsulate", "decapsulate"]}


def _alg_ref(info: pqc.AlgInfo) -> str:
    return "alg:" + info.name.replace(" ", "-")


def _algorithm_component(info: pqc.AlgInfo) -> dict:
    props: dict = {
        "primitive": info.primitive,
        "nistQuantumSecurityLevel": info.nist_level,
    }
    if info.classical_bits is not None:
        props["classicalSecurityLevel"] = info.classical_bits
    if info.family == "ec":
        props["curve"] = info.name.split(" ", 1)[1]
    elif info.family in ("rsa", "dsa"):
        props["parameterSetIdentifier"] = info.name.split("-", 1)[1]
    elif info.family in ("ml-dsa", "ml-kem", "slh-dsa"):
        props["parameterSetIdentifier"] = info.name
    if info.primitive in _CRYPTO_FUNCTIONS:
        props["cryptoFunctions"] = _CRYPTO_FUNCTIONS[info.primitive]
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": _alg_ref(info),
        "name": info.name,
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props},
    }
    if info.oid:
        comp["cryptoProperties"]["oid"] = info.oid
    return comp


def render_cbom(report: Report, **_ignored) -> str:
    keys = report.keys
    by_fp = defaultdict(list)
    for k in keys:
        by_fp[k.fingerprint].append(k)

    components: list[dict] = []
    algs: dict[str, pqc.AlgInfo] = {}
    for ks in by_fp.values():
        info = pqc.classify(ks[0])
        algs.setdefault(_alg_ref(info), info)
    components += [_algorithm_component(info) for _ref, info in sorted(algs.items())]

    for fp, ks in sorted(by_fp.items()):
        info = pqc.classify(ks[0])
        material: dict = {"type": "public-key", "id": fp, "algorithmRef": _alg_ref(info),
                          "format": "SPKI-SHA256"}
        if ks[0].bits:
            material["size"] = ks[0].bits
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"key:{fp}",
            "name": f"{info.name} public key {fp[:16]}",
            "cryptoProperties": {"assetType": "related-crypto-material",
                                 "relatedCryptoMaterialProperties": material},
            "evidence": {"occurrences": [{"location": src}
                                         for src in sorted({k.source for k in ks})]},
        })

    seen_certs = set()
    for k in sorted(keys, key=lambda k: k.source):
        if not k.cert_fingerprint or k.cert_fingerprint in seen_certs:
            continue
        seen_certs.add(k.cert_fingerprint)
        cert_props = {
            "subjectName": k.cert_subject, "issuerName": k.cert_issuer,
            "notValidBefore": k.cert_not_before, "notValidAfter": k.cert_not_after,
            "subjectPublicKeyRef": f"key:{k.fingerprint}", "certificateFormat": "X.509",
        }
        comp = {
            "type": "cryptographic-asset",
            "bom-ref": f"cert:{k.cert_fingerprint}",
            "name": k.cert_subject or k.cert_fingerprint[:16],
            "cryptoProperties": {"assetType": "certificate",
                                 "certificateProperties": {a: b for a, b in cert_props.items()
                                                           if b is not None}},
            "evidence": {"occurrences": [{"location": k.source}]},
        }
        if k.cert_sig_oid:
            comp["properties"] = [{"name": "rngaudit:signatureAlgorithmOid",
                                   "value": k.cert_sig_oid}]
        components.append(comp)

    if report.crypto:
        for label, e in sorted(report.crypto.endpoint_detail.items()):
            props = [{"name": "rngaudit:postQuantumKeyExchange",
                      "value": str(bool(e.get("pq_kex"))).lower()}]
            for name, ok in sorted(e.get("groups", {}).items()):
                props.append({"name": f"rngaudit:tlsGroup:{name}", "value": str(ok).lower()})
            for name in e.get("kex", []):
                props.append({"name": "rngaudit:sshKex", "value": name})
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": f"endpoint:{label}",
                "name": label,
                "cryptoProperties": {"assetType": "protocol",
                                     "protocolProperties": {"type": e["proto"]}},
                "properties": props,
            })

    refs = {c["bom-ref"] for c in components}
    vulns = []
    for i, f in enumerate(report.findings, 1):
        affects = [{"ref": f"key:{fp}"} for fp in f.fingerprints if f"key:{fp}" in refs]
        v = {
            "bom-ref": f"finding:{i}",
            "id": f"rngaudit:{f.check}",
            "source": {"name": "rngaudit"},
            "ratings": [{"severity": f.severity.name.lower(), "method": "other"}],
            "description": f"{f.title}. {f.detail}",
        }
        advice = advice_en(f.check)
        if advice:
            v["recommendation"] = advice
        if affects:
            v["affects"] = affects
        vulns.append(v)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "rngaudit",
                                      "version": __version__}]},
        },
        "components": components,
    }
    if vulns:
        bom["vulnerabilities"] = vulns
    return json.dumps(bom, indent=2, ensure_ascii=False) + "\n"

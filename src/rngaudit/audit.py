"""Orchestration: run every check over a corpus and assemble a report."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import checks, numtheory
from .ingest import Corpus
from .model import Finding, Severity


@dataclass
class Report:
    findings: list[Finding]
    stats: dict
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def at_least(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= severity]


def run_audit(corpus: Corpus, cfg: checks.AuditConfig | None = None) -> Report:
    cfg = cfg or checks.AuditConfig()

    findings: list[Finding] = []
    findings += checks.check_duplicate_keys(corpus.keys, cfg)
    rsa_findings, excluded = checks.check_rsa_structure(corpus.keys, cfg)
    findings += rsa_findings
    findings += checks.check_shared_factors(corpus.keys, cfg, excluded)
    findings += checks.check_ecdsa(corpus.signatures, cfg)
    findings += checks.check_serials(corpus.keys, cfg)

    findings.sort(key=lambda f: (-int(f.severity), f.check, f.title))

    uniq_keys = {k.fingerprint: k for k in corpus.keys}
    algos: dict[str, int] = {}
    for k in uniq_keys.values():
        algos[k.algorithm] = algos.get(k.algorithm, 0) + 1
    stats = {
        "files_read": corpus.files_read,
        "files_skipped": corpus.files_skipped,
        "key_records": len(corpus.keys),
        "unique_keys": len(uniq_keys),
        "unique_keys_by_algorithm": dict(sorted(algos.items())),
        "certificates": len({k.cert_fingerprint for k in corpus.keys if k.cert_fingerprint}),
        "signatures": len({(s.pub_fingerprint, s.r, s.s) for s in corpus.signatures}),
        "holders": len({checks.holder(k, cfg.holder_mode) for k in corpus.keys}),
        "gmpy2": numtheory.HAVE_GMPY2,
    }
    return Report(findings=findings, stats=stats, errors=list(corpus.errors))

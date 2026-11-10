import pytest

from rngaudit import synth
from rngaudit.audit import run_audit
from rngaudit.checks import AuditConfig
from rngaudit.ingest import load_paths, load_signatures


@pytest.fixture(scope="session")
def fleet(tmp_path_factory):
    """A synthetic fleet with planted failures and its ground-truth manifest."""
    root = tmp_path_factory.mktemp("fleet")
    manifest = synth.build_fleet(root, seed=7, healthy=16)
    return root, manifest


def scan(paths, sigs=(), cfg=None):
    corpus = load_paths(paths)
    for s in sigs:
        corpus.extend(load_signatures(s))
    return run_audit(corpus, cfg or AuditConfig())

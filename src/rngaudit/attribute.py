"""Attribution: which software, model or firmware do the affected holders share?

A finding says *that* keys are broken; operators then need *why*. Holders
(hosts, files, directories) carry labels from three sources:

* ``ssh``: the SSH identification string recorded by ``collect``
  (``dropbear_2014.63`` -> software "dropbear 2014.63", product "dropbear");
* ``inventory``: a CSV the operator supplies (host, vendor, model, firmware);
* ``cert-org``: the organisation in a self-signed certificate, which on
  embedded devices usually names the vendor.

For every label we compare how often its holders are affected with how often
everyone else is, using a one-sided Fisher exact test, Bonferroni-corrected
over all labels tested. A label is reported when its affected share is
unusually high; that is a lead to investigate, not proof of a cause.
"""

from __future__ import annotations

import csv
import math
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .checks import file_of
from .model import Finding, KeyRecord, Severity, SignatureRecord

# Dimensions, most specific first. Each holder has at most one label per dimension.
DIMENSIONS = ("firmware", "model", "vendor", "software", "product", "cert-org")

_HOST_LABEL = re.compile(r"\[(.+)\]$")


def holder_of(source: str, mode: str = "file") -> str:
    """Holder id of a source label (same rule as checks.holder)."""
    m = _HOST_LABEL.search(source)
    if m:
        return "host:" + m.group(1)
    path = file_of(source)
    if mode == "dir":
        return "dir:" + os.path.dirname(path)
    return "file:" + path


# --------------------------------------------------------------------------
# label sources
# --------------------------------------------------------------------------


def parse_ssh_banner(banner: str) -> dict[str, str]:
    """``SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13`` -> software/product labels."""
    m = re.match(r"SSH-[\d.]+-(\S+)", banner.strip())
    if not m:
        return {}
    ident = m.group(1)
    parts = re.split(r"[_-]", ident, maxsplit=1)
    product = parts[0]
    if len(parts) == 2 and re.match(r"\d", parts[1]):
        return {"software": f"{product} {parts[1]}", "product": product}
    return {"software": ident, "product": product}


INVENTORY_COLUMNS = ("host", "vendor", "model", "firmware")


def load_inventory(path: str | Path) -> dict[str, dict[str, str]]:
    """CSV with a header row; ``host`` is required, the rest optional.

    ``host`` is matched against host labels (``collect`` targets, known_hosts
    entries) and, if it is a path, against the files and directories scanned.
    """
    out: dict[str, dict[str, str]] = {}
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "host" not in [c.strip().lower() for c in reader.fieldnames]:
            raise ValueError(f"{path}: inventory needs a header row with a 'host' column")
        for row in reader:
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            host = row.get("host", "")
            if not host or host.startswith("#"):
                continue
            vendor, model, fw = row.get("vendor", ""), row.get("model", ""), row.get("firmware", "")
            labels = {}
            if vendor:
                labels["vendor"] = vendor
            if model:
                labels["model"] = f"{vendor} {model}".strip()
            if fw:
                labels["firmware"] = f"{vendor} {model} {fw}".strip()
            out[host] = labels
    return out


def _inventory_lookup(holder: str, inv: dict[str, dict[str, str]]) -> dict[str, str]:
    kind, _, ident = holder.partition(":")
    if kind == "host":
        return inv.get(ident, {})
    # file / dir: the path itself or its nearest listed parent directory
    norm = {os.path.abspath(k): v for k, v in inv.items() if "/" in k or os.sep in k}
    p = os.path.abspath(ident)
    while True:
        if p in norm:
            return norm[p]
        parent = os.path.dirname(p)
        if parent == p:
            return {}
        p = parent


def _cert_org(k: KeyRecord) -> str | None:
    if not k.cert_subject or k.cert_subject != k.cert_issuer:
        return None
    m = re.search(r"(?:^|,)O=((?:\\.|[^,])+)", k.cert_subject)
    return m.group(1).replace("\\", "") if m else None


def holder_labels(
    keys: list[KeyRecord],
    sigs: list[SignatureRecord],
    host_info: dict[str, dict[str, str]],
    inventory: dict[str, dict[str, str]] | None,
    mode: str = "file",
) -> dict[str, dict[str, str]]:
    """Every holder seen in the corpus, with whatever labels are known."""
    labels: dict[str, dict[str, str]] = {}
    for k in keys:
        h = holder_of(k.source, mode)
        lab = labels.setdefault(h, {})
        org = _cert_org(k)
        if org:
            lab.setdefault("cert-org", org)
    for s in sigs:
        labels.setdefault(holder_of(s.source, mode), {})
    for h, lab in labels.items():
        lab.update(host_info.get(h, {}))
        if inventory:
            lab.update(_inventory_lookup(h, inventory))
    return labels


# --------------------------------------------------------------------------
# statistics
# --------------------------------------------------------------------------


def _log_comb(n: int, k: int) -> float:
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def fisher_greater(a: int, n: int, k_total: int, n_total: int) -> float:
    """P(X >= a), X ~ Hypergeometric(population n_total, k_total successes, n draws).

    a: affected holders with the label, n: holders with the label,
    k_total: affected holders overall, n_total: all holders.
    """
    lo, hi = max(a, n + k_total - n_total, 0), min(n, k_total)
    if lo > hi:
        return 0.0
    denom = _log_comb(n_total, n)
    p = 0.0
    for x in range(lo, hi + 1):
        p += math.exp(_log_comb(k_total, x) + _log_comb(n_total - k_total, n - x) - denom)
    return min(1.0, p)


@dataclass
class Association:
    dimension: str
    label: str
    affected: int  # affected holders with this label
    holders: int  # holders with this label
    affected_other: int  # affected holders without it
    holders_other: int  # holders without it (among those labelled in this dimension or not)
    p_value: float  # one-sided Fisher, Bonferroni-corrected
    checks: list[str]

    @property
    def significant(self) -> bool:
        return self.p_value < 0.01

    def to_dict(self) -> dict:
        return {
            "dimension": self.dimension, "label": self.label,
            "affected": self.affected, "holders": self.holders,
            "affected_other": self.affected_other, "holders_other": self.holders_other,
            "p_value": self.p_value, "significant": self.significant,
            "checks": self.checks,
        }


def affected_holders(findings: list[Finding], mode: str = "file",
                     min_severity: Severity = Severity.MEDIUM) -> dict[str, set[str]]:
    """holder -> checks it is involved in (findings at min_severity or above).

    Signatures harvested from certificates are attributed to the issuer
    (``issuer:...``), not to a holder, so issuer-level checks only count the
    certificate holders they list.
    """
    out: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        if f.severity < min_severity:
            continue
        for src in f.sources:
            out[holder_of(src, mode)].add(f.check)
    return out


def associations(
    labels: dict[str, dict[str, str]],
    affected: dict[str, set[str]],
    max_results: int = 10,
) -> list[Association]:
    n_total = len(labels)
    k_total = sum(1 for h in labels if h in affected)
    if n_total < 2 or k_total == 0:
        return []
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for h, lab in labels.items():
        for dim, value in lab.items():
            groups[(dim, value)].append(h)
    tested = [(key, hs) for key, hs in groups.items() if len(hs) >= 2]
    m = max(1, len(tested))
    out = []
    for (dim, value), hs in tested:
        a = sum(1 for h in hs if h in affected)
        if a < 2:
            continue
        p = min(1.0, fisher_greater(a, len(hs), k_total, n_total) * m)
        checks = sorted({c for h in hs if h in affected for c in affected[h]})
        out.append(Association(dim, value, a, len(hs), k_total - a, n_total - len(hs),
                               p, checks))
    rank = {d: i for i, d in enumerate(DIMENSIONS)}
    out.sort(key=lambda x: (x.p_value, -x.affected / x.holders, rank.get(x.dimension, 99)))
    # A firmware label and its model / vendor often describe the same holders;
    # keep the most specific one for each set of affected holders.
    kept, seen = [], set()
    for x in out:
        members = frozenset(h for h, lab in labels.items()
                            if lab.get(x.dimension) == x.label and h in affected)
        if members in seen:
            continue
        seen.add(members)
        kept.append(x)
    return kept[:max_results]


def annotate(findings: list[Finding], labels: dict[str, dict[str, str]],
             mode: str = "file", top: int = 3) -> None:
    """Add ``data['software']``: the most specific labels of a finding's holders."""
    for f in findings:
        counts: dict[str, int] = defaultdict(int)
        for h in {holder_of(s, mode) for s in f.sources}:
            lab = labels.get(h, {})
            best = next((lab[d] for d in DIMENSIONS if d in lab), None)
            if best:
                counts[best] += 1
        if counts:
            f.data["software"] = dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top])

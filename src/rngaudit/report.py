"""Rendering: text (for people), Markdown (for reports) and JSON (for tools).

The text and Markdown views group findings by check, explain each check once
(what is wrong, what to do) and then list the individual cases compactly.
"""

from __future__ import annotations

import json
import os
import re
import textwrap
from collections import defaultdict
from dataclasses import dataclass

from . import __version__
from .audit import Report
from .checks import file_of
from .explain import NOTES, SEVERITY_LABEL, UI, advice_en, check_text, instance_label
from .model import Finding, Severity

# ---------------------------------------------------------------------------
# verdict and grouping
# ---------------------------------------------------------------------------


def verdict(report: Report) -> str:
    """action | review | minor | clean"""
    top = report.max_severity
    if top is None:
        return "clean"
    if top >= Severity.HIGH:
        return "action"
    if top >= Severity.MEDIUM:
        return "review"
    return "minor"


def _counts(report: Report) -> dict[str, int]:
    out = {s.name: 0 for s in sorted(Severity, reverse=True)}
    for f in report.findings:
        out[f.severity.name] += 1
    return out


@dataclass
class Group:
    check: str
    findings: list[Finding]

    @property
    def severity(self) -> Severity:
        return max(f.severity for f in self.findings)


def groups(report: Report) -> list[Group]:
    by_check: dict[str, list[Finding]] = defaultdict(list)
    for f in report.findings:
        by_check[f.check].append(f)
    out = [Group(c, fs) for c, fs in by_check.items()]
    out.sort(key=lambda g: (-int(g.severity), -len(g.findings), g.check))
    return out


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------

_HASHED_HOST = re.compile(r"\[\|1\|[^\]]*\]")


def common_root(report: Report) -> str | None:
    """Longest directory shared by all path-like sources, if worth stripping."""
    files = []
    for f in report.findings:
        for s in f.sources:
            if s.startswith("/"):
                files.append(os.path.dirname(file_of(_HASHED_HOST.sub("", s).rstrip())))
    if len(files) < 2:
        return None
    try:
        root = os.path.commonpath(files)
    except ValueError:
        return None
    return root if len(root) > 1 else None


def pretty_source(s: str, root: str | None, lang: str) -> str:
    s = _HASHED_HOST.sub(f"[{UI[lang]['hashed']}]", s)
    s = re.sub(r"#0$", "", s)
    if root and s.startswith(root + "/"):
        s = s[len(root) + 1 :]
    return s


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def to_dict(report: Report) -> dict:
    findings = []
    for f in report.findings:
        d = f.to_dict()
        d["advice"] = advice_en(f.check)
        findings.append(d)
    return {
        "tool": "rngaudit",
        "version": __version__,
        "verdict": verdict(report),
        "stats": report.stats,
        "summary": _counts(report),
        "findings": findings,
        "associations": [a.to_dict() for a in report.associations],
        "errors": [{"source": s, "message": m} for s, m in report.errors],
    }


def render_json(report: Report, **_ignored) -> str:
    return json.dumps(to_dict(report), indent=2, sort_keys=False, ensure_ascii=False)


# ---------------------------------------------------------------------------
# text
# ---------------------------------------------------------------------------

_ANSI = {
    "bold": "1", "dim": "2", "red": "31", "yellow": "33", "cyan": "36", "green": "32",
    "bred": "1;31", "bgreen": "1;32", "byellow": "1;33",
}
_SEV_STYLE = {
    Severity.CRITICAL: "bred", Severity.HIGH: "red", Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan", Severity.INFO: "dim",
}
_VERDICT_STYLE = {"action": "bred", "review": "byellow", "minor": "cyan", "clean": "bgreen"}


def _paint(text: str, style: str, on: bool) -> str:
    return f"\033[{_ANSI[style]}m{text}\033[0m" if on else text


_NO_LINE_START = set("、。，．）」』】）,.)")


def _wrap(text: str, indent: str, width: int = 78) -> str:
    """Wrap at word boundaries for English; for Japanese (no spaces) break by
    display width, never starting a line with closing punctuation."""
    if not any(ord(ch) > 0x2E7F for ch in text):
        return textwrap.fill(text, width, initial_indent=indent, subsequent_indent=indent)
    out, line, cols = [], "", 0
    limit = width - len(indent)
    for ch in text:
        w = 2 if ord(ch) > 0x2E7F else 1
        if cols + w > limit and ch not in _NO_LINE_START:
            out.append(line)
            line, cols = "", 0
        line += ch
        cols += w
    if line:
        out.append(line)
    return "\n".join(indent + piece for piece in out)


def _summary_counts(report: Report, lang: str) -> str:
    c = _counts(report)
    labels = SEVERITY_LABEL[lang]
    parts = [f"{labels[Severity[n]]} {k}" for n, k in c.items() if k]
    return " · ".join(parts) if parts else "—"


def _verdict_text(report: Report, lang: str) -> str:
    return UI[lang]["verdict_" + verdict(report)]


def _software(f: Finding) -> str:
    return ", ".join(f"{label} ×{n}" for label, n in f.data["software"].items())


def _fmt_p(p: float) -> str:
    return "<0.0001" if p < 1e-4 else f"{p:.2g}"


def _attribution_lines(report: Report, lang: str, p) -> list[str]:
    T = UI[lang]
    labelled = report.stats.get("labelled_holders", 0)
    if not labelled or not report.findings:
        return []
    out = []
    if not report.associations:
        out.append(p(T["attr_none"].format(n=labelled), "dim"))
        out.append("")
        return out
    out.append(p("■ " + T["attr_title"], "bold"))
    for a in report.associations:
        row = T["attr_row"].format(label=f"{T['dim_' + a.dimension]} {a.label}", a=a.affected,
                                   n=a.holders, ao=a.affected_other, no=a.holders_other)
        verdict_ = T["attr_sig"] if a.significant else T["attr_weak"]
        out.append(f"    - {row}  {p(T['attr_p'].format(p=_fmt_p(a.p_value)) + ' · ' + verdict_, 'dim')}")
        out.append(p(f"        [{', '.join(a.checks)}]", "dim"))
    out.append(p("  " + T["attr_note"], "dim"))
    out.append("")
    return out


def render_text(
    report: Report,
    verbose: bool = False,
    lang: str = "en",
    color: bool = False,
    max_items: int = 5,
) -> str:
    T = UI[lang]
    labels = SEVERITY_LABEL[lang]
    st = report.stats
    root = common_root(report)
    p = lambda text, style: _paint(text, style, color)  # noqa: E731

    lines: list[str] = []
    lines.append(p(T["banner"].format(version=__version__), "bold"))
    skipped = T["skipped"].format(n=st["files_skipped"]) if st.get("files_skipped") else ""
    lines.append(T["scanned"].format(files=st["files_read"], skipped=skipped, keys=st["unique_keys"],
                                     certs=st["certificates"], sigs=st["signatures"]))
    lines.append("")
    v = verdict(report)
    lines.append(f"{T['verdict']}: {p(_verdict_text(report, lang), _VERDICT_STYLE[v])}"
                 + (f"   {_summary_counts(report, lang)}" if report.findings else ""))

    gs = groups(report)
    if gs and v in ("action", "review"):
        top = [g for g in gs if g.severity >= Severity.MEDIUM][:4]
        lines.append(f"{T['start']}: " + ", ".join(f"{g.check} ({len(g.findings)})" for g in top))
    if root:
        lines.append(p(T["base"].format(root=root), "dim"))
    lines.append("")

    for g in gs:
        title, meaning, advice = check_text(g.check, lang)
        sev_text = labels[g.severity]
        head = f"■ {sev_text}  {title}"
        lines.append(p(head, _SEV_STYLE[g.severity]) + p(f"  [{g.check}] {T['count'].format(n=len(g.findings))}", "dim"))
        if meaning:
            lines.append(f"  {p(T['what'], 'bold')}:")
            lines.append(_wrap(meaning, "    "))
        if advice:
            lines.append(f"  {p(T['todo'], 'bold')}:")
            lines.append(_wrap(advice, "    "))
        notes = {f.data.get("note") for f in g.findings if f.data.get("note")}
        for n in sorted(notes):
            lines.append(f"  {p(T['note'], 'bold')}:")
            lines.append(_wrap(NOTES[n][lang], "    "))
        lines.append(f"  {p(T['found'], 'bold')}:")

        mixed = len({f.severity for f in g.findings}) > 1
        shown = g.findings if verbose else g.findings[:max_items]
        for i, f in enumerate(shown, 1):
            tag = f"[{labels[f.severity]}] " if mixed else ""
            lines.append(f"    {i}. {tag}{instance_label(f, lang)}")
            if f.fingerprints:
                fps = f.fingerprints if verbose else f.fingerprints[:3]
                more = len(f.fingerprints) - len(fps)
                extra = f" {T['more_places'].format(n=more)}" if more > 0 else ""
                lines.append(f"         {T['keys']}: " + ", ".join(x[:12] for x in fps) + extra)
            if f.sources:
                srcs = [pretty_source(s, root, lang) for s in f.sources]
                shown_s = srcs if verbose else srcs[:3]
                more = len(srcs) - len(shown_s)
                extra = f" {T['more_places'].format(n=more)}" if more > 0 else ""
                lines.append(f"         {T['where']}: " + ", ".join(shown_s) + extra)
            if f.data.get("software"):
                lines.append(f"         {T['software']}: " + _software(f))
        if len(g.findings) > len(shown):
            lines.append("    " + T["more_items"].format(n=len(g.findings) - len(shown)))
        lines.append("")

    lines += _attribution_lines(report, lang, p)

    if v == "clean":
        lines.append(T["caveat"])
        lines.append("")

    private = [m for _s, m in report.errors if "private key skipped" in m]
    other = [(s, m) for s, m in report.errors if "private key skipped" not in m]
    if private:
        lines.append(p(T["private_skipped"].format(n=len(private)), "dim"))
    if other:
        lines.append(f"{T['inputs']}: {len(other)}")
        for s, m in other if verbose else other[:5]:
            lines.append(f"    {pretty_source(s, root, lang)}: {m}")
        if not verbose and len(other) > 5:
            lines.append("    " + T["more_items"].format(n=len(other) - 5))
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def render_markdown(report: Report, lang: str = "en", max_items: int = 20, **_ignored) -> str:
    T = UI[lang]
    labels = SEVERITY_LABEL[lang]
    st = report.stats
    root = common_root(report)
    out = [
        f"# {T['banner'].format(version=__version__)}",
        "",
        "- " + T["scanned"].format(
            files=st["files_read"],
            skipped=T["skipped"].format(n=st["files_skipped"]) if st.get("files_skipped") else "",
            keys=st["unique_keys"], certs=st["certificates"], sigs=st["signatures"]),
        f"- {T['verdict']}: **{_verdict_text(report, lang)}**"
        + (f" ({_summary_counts(report, lang)})" if report.findings else ""),
    ]
    if root:
        out.append("- " + T["base"].format(root=f"`{root}`"))
    out.append("")
    if not report.findings:
        out += [T["caveat"], ""]
    for g in groups(report):
        title, meaning, advice = check_text(g.check, lang)
        out += [f"## {labels[g.severity]} — {title}  `{g.check}` ({T['count'].format(n=len(g.findings))})", ""]
        if meaning:
            out += [f"**{T['what']}**: {meaning}", ""]
        if advice:
            out += [f"**{T['todo']}**: {advice}", ""]
        for n in sorted({f.data.get("note") for f in g.findings if f.data.get("note")}):
            out += [f"**{T['note']}**: {NOTES[n][lang]}", ""]
        mixed = len({f.severity for f in g.findings}) > 1
        for i, f in enumerate(g.findings[:max_items], 1):
            tag = f"[{labels[f.severity]}] " if mixed else ""
            out.append(f"{i}. {tag}{instance_label(f, lang)}")
            if f.fingerprints:
                out.append(f"   - {T['keys']}: " + ", ".join(f"`{x[:12]}`" for x in f.fingerprints[:5]))
            if f.sources:
                out.append(f"   - {T['where']}: " + ", ".join(f"`{pretty_source(s, root, lang)}`" for s in f.sources[:5]))
            if f.data.get("software"):
                out.append(f"   - {T['software']}: {_software(f)}")
        if len(g.findings) > max_items:
            out.append("   " + T["more_items"].format(n=len(g.findings) - max_items))
        out.append("")
    attr = _attribution_lines(report, lang, lambda text, _style: text)
    if attr:
        out += [line.replace("■ ", "## ", 1) if line.startswith("■ ") else line for line in attr]
    other = [(s, m) for s, m in report.errors if "private key skipped" not in m]
    if other:
        out += [f"## {T['inputs']}", ""]
        out += [f"- `{s}`: {m}" for s, m in other]
    return "\n".join(out).rstrip() + "\n"


FORMATS = ("text", "json", "md")

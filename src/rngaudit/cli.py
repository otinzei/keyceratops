"""Command line interface.

    rngaudit scan PATH... [--sigs FILE.jsonl] [--format text|json|md]
    rngaudit entropy FILE --bits 8 [--claim-h 6.0]
    rngaudit demo DIR            (synthetic fleet with planted failures)
    rngaudit collect TARGET... -o SNAPSHOT.jsonl   (TLS / SSH servers)

Exit status: 0 clean, 1 findings at or above ``--fail-on`` (scan) / unhealthy
source (entropy), 2 usage or input error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, entropy
from .audit import run_audit
from .checks import AuditConfig
from .explain import UI, detect_language
from .ingest import Corpus, load_paths, load_signatures
from .model import Severity
from .report import FORMATS, render_json, render_markdown, render_text


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rngaudit",
        description="Find randomness failures in what a fleet of devices publishes.",
    )
    p.add_argument("--version", action="version", version=f"rngaudit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="audit public keys, certificates and signatures")
    s.add_argument("paths", nargs="+", help="files or directories (PEM, DER, OpenSSH)")
    s.add_argument("--sigs", action="append", default=[], metavar="FILE",
                   help="JSON Lines of ECDSA signatures (repeatable)")
    s.add_argument("--format", "-f", choices=FORMATS, default="text")
    s.add_argument("--output", "-o", help="write the report here instead of stdout")
    s.add_argument("--lang", choices=["auto", "ja", "en"], default="auto",
                   help="report language (auto: from the locale)")
    s.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    s.add_argument("--max-items", type=int, default=5, metavar="N",
                   help="cases shown per check in text output (default 5; -v shows all)")
    s.add_argument("--fail-on", default="high", metavar="SEVERITY",
                   help="exit 1 if any finding is at least this severe "
                        "(info|low|medium|high|critical|never; default: high)")
    s.add_argument("--holder", choices=["file", "dir"], default="file",
                   help="what counts as one device when judging duplicate keys")
    s.add_argument("--fermat-iterations", type=int, default=1024,
                   help="bound for the close-prime (Fermat) test; 0 disables")
    s.add_argument("--min-rsa-bits", type=int, default=2048)
    s.add_argument("-v", "--verbose", action="store_true", help="show every case and path")

    c = sub.add_parser(
        "collect",
        help="gather keys, certificates and signatures from TLS / SSH servers",
        description="Targets: tls://host[:port], ssh://host[:port], or a bare host "
                    "(both TLS 443 and SSH 22). Only contact servers you own or are "
                    "authorised to test.",
    )
    c.add_argument("targets", nargs="*", help="servers to contact")
    c.add_argument("--targets-file", "-T", action="append", default=[], metavar="FILE",
                   help="file with one target per line (# comments allowed)")
    c.add_argument("--output", "-o", required=True, metavar="SNAPSHOT",
                   help="snapshot file (JSON Lines); appended to if it exists")
    c.add_argument("--samples", "-n", type=int, default=1,
                   help="signatures to collect per ECDSA key (default 1)")
    c.add_argument("--timeout", type=float, default=10.0, help="seconds per connection")
    c.add_argument("--delay", type=float, default=0.5,
                   help="pause between connections to one server (seconds)")
    c.add_argument("--lang", choices=["auto", "ja", "en"], default="auto")
    c.add_argument("-q", "--quiet", action="store_true", help="no progress output")

    d = sub.add_parser("demo", help="write a synthetic fleet with planted failures")
    d.add_argument("outdir", help="directory to create the demo fleet in")
    d.add_argument("--seed", type=int, default=1)

    e = sub.add_parser("entropy", help="assess raw entropy-source samples (SP 800-90B subset)")
    e.add_argument("file", help="raw samples taken before any conditioning")
    e.add_argument("--bits", type=int, default=8, help="bits per sample (1..8)")
    e.add_argument("--packed", action="store_true",
                   help="file is a packed bitstream of 1-bit samples")
    e.add_argument("--claim-h", type=float, default=None,
                   help="claimed min-entropy per sample (default: the MCV estimate)")
    e.add_argument("--format", "-f", choices=["text", "json"], default="text")
    e.add_argument("--lang", choices=["auto", "ja", "en"], default="auto")
    return p


def _language(choice: str) -> str:
    return detect_language() if choice == "auto" else choice


def _use_color(choice: str, to_file: bool) -> bool:
    if choice == "always":
        return True
    if choice == "never" or to_file:
        return False
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.fail_on.lower() == "never":
        threshold = None
    else:
        try:
            threshold = Severity.parse(args.fail_on)
        except ValueError as exc:
            print(f"rngaudit: {exc}", file=sys.stderr)
            return 2

    corpus: Corpus = load_paths(args.paths)
    for sig_file in args.sigs:
        corpus.extend(load_signatures(sig_file))

    if not corpus.keys and not corpus.signatures:
        print("rngaudit: no keys, certificates or signatures found in the input",
              file=sys.stderr)
        for src, msg in corpus.errors[:10]:
            print(f"  {src}: {msg}", file=sys.stderr)
        return 2

    cfg = AuditConfig(
        fermat_iterations=args.fermat_iterations,
        min_rsa_bits=args.min_rsa_bits,
        holder_mode=args.holder,
    )
    report = run_audit(corpus, cfg)

    lang = _language(args.lang)
    if args.format == "json":
        text = render_json(report)
    elif args.format == "md":
        text = render_markdown(report, lang=lang, max_items=10**6 if args.verbose else 20)
    else:
        text = render_text(
            report,
            verbose=args.verbose,
            lang=lang,
            color=_use_color(args.color, to_file=bool(args.output)),
            max_items=args.max_items,
        )
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    if threshold is not None and report.at_least(threshold):
        return 1
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    from . import synth  # test-only generators; imported lazily

    out = Path(args.outdir)
    if out.exists() and any(out.iterdir()):
        print(f"rngaudit: {out} is not empty", file=sys.stderr)
        return 2
    manifest = synth.build_fleet(out, seed=args.seed)
    planted = sum(len(v) for v in manifest.values())
    print(f"wrote a synthetic fleet to {out} ({planted} flawed files across "
          f"{len(manifest)} failure types; keys are NOT secure)")
    print(f"try:  rngaudit scan {out} --sigs {out / 'signatures.jsonl'}")
    return 0


_ENTROPY_TEXT = {
    "ja": {
        "samples": "サンプル数: {n} × {b}ビット",
        "mcv": "最頻値(MCV)による最小エントロピー推定: {h:.3f} ビット/サンプル"
               "（最頻値 {mode}、出現率 {frac:.4f}）",
        "claim": "主張するエントロピー: {h:.3f} ビット/サンプル",
        "contradicted": "  ← データと矛盾しています",
        "rct": "反復回数テスト(RCT): 閾値 {c}、失敗 {f}回",
        "apt": "適応的比率テスト(APT): 窓 {w}、閾値 {c}、失敗 {f}回",
        "ok": "判定: 問題は検出されませんでした",
        "ng": "判定: 不合格",
        "note": "注: MCVはSP 800-90Bの10個の推定器の1つです。評価値は全推定器の最小値なので、"
                "ここで合格しても認証の証拠にはなりません。",
    },
    "en": {
        "samples": "samples: {n} x {b} bit",
        "mcv": "MCV min-entropy estimate: {h:.3f} bits/sample "
               "(most common value {mode} at {frac:.4f})",
        "claim": "claimed entropy:          {h:.3f} bits/sample",
        "contradicted": "   <-- CONTRADICTED by the data",
        "rct": "repetition count test:    cutoff {c}, failures {f}",
        "apt": "adaptive proportion test: window {w}, cutoff {c}, failures {f}",
        "ok": "verdict: no problem detected",
        "ng": "verdict: FAIL",
        "note": "note: MCV is one of ten SP 800-90B estimators; the assessed entropy is the "
                "minimum over all of them, so a passing result here is not a certification.",
    },
}


def _cmd_entropy(args: argparse.Namespace) -> int:
    try:
        data = Path(args.file).read_bytes()
        bits = 1 if args.packed else args.bits
        samples = entropy.to_samples(data, bits, packed=args.packed)
        rep = entropy.assess(samples, bits, args.claim_h)
    except (OSError, ValueError) as exc:
        print(f"rngaudit: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        t = _ENTROPY_TEXT[_language(args.lang)]
        print(t["samples"].format(n=rep.samples, b=rep.bits_per_sample))
        print(t["mcv"].format(h=rep.mcv_min_entropy, mode=rep.most_common_value,
                              frac=rep.most_common_fraction))
        print(t["claim"].format(h=rep.claimed_h)
              + ("" if rep.claim_consistent else t["contradicted"]))
        print(t["rct"].format(c=rep.rct_cutoff, f=rep.rct_failures))
        print(t["apt"].format(w=rep.apt_window, c=rep.apt_cutoff, f=rep.apt_failures))
        print(t["ok"] if rep.healthy else t["ng"])
        print(t["note"])
    return 0 if rep.healthy else 1


def _cmd_collect(args: argparse.Namespace) -> int:
    from . import collect

    t = UI[_language(args.lang)]
    try:
        specs = list(args.targets)
        for f in args.targets_file:
            specs += collect.read_targets_file(f)
        targets = collect.expand(specs)
    except (OSError, ValueError) as exc:
        print(f"rngaudit: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print("rngaudit: no targets given", file=sys.stderr)
        return 2
    if not 1 <= args.samples <= collect.MAX_SAMPLES:
        print(f"rngaudit: --samples must be 1..{collect.MAX_SAMPLES}", file=sys.stderr)
        return 2

    err = sys.stderr
    if not args.quiet:
        print(t["c_notice"], file=err)
    progress = None if args.quiet else (
        lambda tg: print(t["c_target"].format(label=tg.label), file=err))
    out = Path(args.output)
    try:
        sm = collect.collect(targets, out, samples=args.samples, timeout=args.timeout,
                             delay=max(0.0, args.delay), progress=progress)
    except (OSError, ValueError) as exc:
        print(f"rngaudit: {exc}", file=sys.stderr)
        return 2

    print(t["c_done"].format(targets=sm.targets, certs=sm.certs, keys=sm.ssh_keys,
                             sigs=sm.signatures, out=out))
    if sm.unverified:
        print(t["c_unverified"].format(n=sm.unverified))
    if sm.errors:
        print(t["c_errors"])
        for label, msg in sm.errors:
            print(f"  {label}: {msg}")
    print(t["c_next"].format(out=out))
    if args.samples == 1 and sm.signatures:
        print(t["c_more"])
    # No target answered at all: a failure. Partial results are not.
    return 0 if sm.reached else 2


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.cmd == "scan":
        return _cmd_scan(args)
    if args.cmd == "collect":
        return _cmd_collect(args)
    if args.cmd == "demo":
        return _cmd_demo(args)
    return _cmd_entropy(args)


if __name__ == "__main__":
    sys.exit(main())

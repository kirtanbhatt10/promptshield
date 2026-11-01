"""Command-line interface: ``scan``, ``scrub``, ``spotlight``, ``bench``, ``serve``, ``canary``, ``detectors``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .canary import make_canary
from .detector import registry
from .policy import Policy, PolicyError
from .report import to_html, to_json, to_sarif, to_text
from .scanner import VERDICTS, Scanner
from .scrub import scrub
from .spotlight import MODES, Spotlight

EXIT_OK, EXIT_FLAGGED, EXIT_USAGE = 0, 1, 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="promptshield", description="Prompt-injection and LLM output leak scanner.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan text, a file or stdin")
    scan.add_argument("text", nargs="?", help="text to scan (omit to read --file or stdin)")
    scan.add_argument("-f", "--file", type=Path, help="read text from a file")
    scan.add_argument("-m", "--mode", choices=("input", "output"), default="input", help="scan user input or model output")
    scan.add_argument("-p", "--policy", type=Path, help="policy file (.toml or .json)")
    scan.add_argument("-c", "--canary", action="append", default=[], help="canary token to look for (repeatable)")
    scan.add_argument("--format", choices=("text", "json", "html", "sarif"), default="text")
    scan.add_argument("-o", "--output", type=Path, help="write the report to a file")
    scan.add_argument("--fail-on", choices=VERDICTS[1:], default="block", help="exit 1 at or above this verdict")

    canary = sub.add_parser("canary", help="generate a canary token")
    canary.add_argument("--prefix", default="PS")

    sub.add_parser("detectors", help="list built-in detectors")

    scrub_p = sub.add_parser("scrub", help="remove secrets, PII, canaries and tracking images from model output")
    scrub_p.add_argument("text", nargs="?")
    scrub_p.add_argument("-f", "--file", type=Path)
    scrub_p.add_argument("-c", "--canary", action="append", default=[])
    scrub_p.add_argument("--allow-domain", action="append", default=[], help="image host that may stay (repeatable)")
    scrub_p.add_argument("--keep-emails", action="store_true")
    scrub_p.add_argument("--json", action="store_true", help="print the text and removal counts as JSON")

    spot = sub.add_parser("spotlight", help="wrap untrusted text in an unforgeable data boundary")
    spot.add_argument("text", nargs="?")
    spot.add_argument("-f", "--file", type=Path)
    spot.add_argument("--mode", choices=MODES, default="delimit")
    spot.add_argument("--source", default="external")
    spot.add_argument("--instructions", action="store_true", help="also print the system-prompt paragraph")

    bench = sub.add_parser("bench", help="measure precision, recall and latency on a labelled corpus")
    bench.add_argument("--corpus", type=Path, help="JSONL corpus (default: built-in)")
    bench.add_argument("-p", "--policy", type=Path)
    bench.add_argument("--json", action="store_true")
    bench.add_argument("--min-f1", type=float, default=0.0, help="exit 1 if F1 falls below this")

    serve = sub.add_parser("serve", help="run the HTTP sidecar")
    serve.add_argument("--host", default=os.environ.get("PROMPTSHIELD_HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("PROMPTSHIELD_PORT", "8787")))
    serve.add_argument("-p", "--policy", type=Path, default=os.environ.get("PROMPTSHIELD_POLICY") or None)
    serve.add_argument("--token", default=os.environ.get("PROMPTSHIELD_TOKEN") or None, help="require this bearer token")
    return parser


def _read_text(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    if args.file is not None:
        return args.file.read_text(encoding="utf-8")
    if sys.stdin.isatty():
        raise ValueError("nothing to scan: pass TEXT, --file, or pipe text on stdin")
    return sys.stdin.read()


def _cmd_scan(args: argparse.Namespace) -> int:
    policy = Policy.from_file(args.policy) if args.policy else Policy()
    scanner = Scanner(policy, canaries=args.canary)
    text = _read_text(args)
    result = scanner.scan(text, args.mode)
    uri = str(args.file) if args.file else "stdin"
    renderers = {
        "text": to_text,
        "json": lambda r: to_json([r]),
        "html": lambda r: to_html([r]),
        "sarif": lambda r: to_sarif([r], uri, text),
    }
    rendered = renderers[args.format](result)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return EXIT_FLAGGED if VERDICTS.index(result.verdict) >= VERDICTS.index(args.fail_on) else EXIT_OK


def _cmd_detectors() -> int:
    for name, cls in registry().items():
        print(f"{name:<26} {cls.kind:<7} {cls.description}")
    return EXIT_OK


def _cmd_scrub(args: argparse.Namespace) -> int:
    result = scrub(_read_text(args), args.canary, args.allow_domain, emails=not args.keep_emails)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2) if args.json else result.text)
    return EXIT_OK


def _cmd_spotlight(args: argparse.Namespace) -> int:
    spot = Spotlight(args.mode)
    if args.instructions:
        print(spot.instructions(), end="\n\n")
    print(spot.wrap(_read_text(args), args.source))
    return EXIT_OK


def _cmd_bench(args: argparse.Namespace) -> int:
    from .bench import load_corpus, run_bench

    policy = Policy.from_file(args.policy) if args.policy else Policy()
    report = run_bench(Scanner(policy), load_corpus(args.corpus))
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) if args.json else report.to_text())
    return EXIT_FLAGGED if report.f1 < args.min_f1 else EXIT_OK


def _cmd_serve(args: argparse.Namespace) -> int:
    from .server import serve

    serve(args.host, args.port, Policy.from_file(args.policy) if args.policy else Policy(), args.token)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "canary":
            print(make_canary(args.prefix))
            return EXIT_OK
        handlers = {"scrub": _cmd_scrub, "spotlight": _cmd_spotlight, "bench": _cmd_bench, "serve": _cmd_serve}
        if args.command in handlers:
            return handlers[args.command](args)
        return _cmd_detectors()
    except (PolicyError, ValueError, OSError) as exc:
        print(f"promptshield: error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())

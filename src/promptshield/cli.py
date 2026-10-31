"""Command-line interface: ``promptshield scan``, ``canary`` and ``detectors``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .canary import make_canary
from .detector import registry
from .policy import Policy, PolicyError
from .report import to_html, to_json, to_text
from .scanner import VERDICTS, Scanner

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
    scan.add_argument("--format", choices=("text", "json", "html"), default="text")
    scan.add_argument("-o", "--output", type=Path, help="write the report to a file")
    scan.add_argument("--fail-on", choices=VERDICTS[1:], default="block", help="exit 1 at or above this verdict")

    canary = sub.add_parser("canary", help="generate a canary token")
    canary.add_argument("--prefix", default="PS")

    sub.add_parser("detectors", help="list built-in detectors")
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
    result = scanner.scan(_read_text(args), args.mode)
    rendered = {"text": to_text, "json": lambda r: to_json([r]), "html": lambda r: to_html([r])}[args.format](result)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return EXIT_FLAGGED if VERDICTS.index(result.verdict) >= VERDICTS.index(args.fail_on) else EXIT_OK


def _cmd_detectors() -> int:
    for name, cls in registry().items():
        print(f"{name:<26} {cls.kind:<7} {cls.description}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "canary":
            print(make_canary(args.prefix))
            return EXIT_OK
        return _cmd_detectors()
    except (PolicyError, ValueError, OSError) as exc:
        print(f"promptshield: error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())

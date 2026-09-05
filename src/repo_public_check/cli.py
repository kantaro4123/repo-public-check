from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .checks import scan_repository
from .git import GitError, discover_repository
from .model import Finding, Report, Severity
from .sarif import report_to_sarif


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-public-check",
        description="Check whether a Git repository is ready to be made public.",
    )
    parser.add_argument("path", nargs="?", default=".", help="repository path (default: .)")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", dest="json_output", help="emit machine-readable JSON")
    output.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 for code-scanning integrations")
    parser.add_argument("--strict", action="store_true", help="treat warnings as a failing result")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _colors() -> dict[str, str]:
    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if not enabled:
        return {key: "" for key in ("red", "yellow", "green", "blue", "bold", "reset")}
    return {
        "red": "\033[31m",
        "yellow": "\033[33m",
        "green": "\033[32m",
        "blue": "\033[34m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }


def _location(finding: Finding) -> str:
    if not finding.path:
        return ""
    if finding.line is not None:
        return f" ({finding.path}:{finding.line})"
    return f" ({finding.path})"


def _render_human(report: Report) -> None:
    c = _colors()
    print(f"{c['bold']}repo-public-check v{__version__}{c['reset']}")
    print(f"Repository: {report.repository}")
    print(f"Scanned: {report.scanned_files} tracked file(s)")
    print()

    if report.findings:
        print(f"{c['bold']}Findings{c['reset']}")
        symbols = {
            Severity.BLOCKER: ("✗", c["red"]),
            Severity.WARNING: ("!", c["yellow"]),
            Severity.INFO: ("·", c["blue"]),
        }
        for severity in (Severity.BLOCKER, Severity.WARNING, Severity.INFO):
            for finding in report.findings:
                if finding.severity is not severity:
                    continue
                symbol, color = symbols[severity]
                print(f"  {color}{symbol}{c['reset']} {finding.title}{_location(finding)}")
                print(f"    {finding.message}")
    else:
        print(f"{c['green']}✓{c['reset']} No issues found")

    print()
    print(f"{c['bold']}Public Readiness{c['reset']}")
    print(f"  Score: {report.score}/100")
    print(f"  Blockers: {report.blockers}")
    print(f"  Warnings: {report.warnings}")
    if report.ready:
        print(f"  {c['green']}READY{c['reset']} — no definite publication blockers found")
    else:
        print(f"  {c['red']}NOT READY{c['reset']} — fix blockers before making the repository public")


def _render_json(report: Report) -> None:
    payload = report.to_dict()
    payload["version"] = __version__
    print(json.dumps(payload, indent=2, sort_keys=True))


def _render_sarif(report: Report) -> None:
    print(json.dumps(report_to_sarif(report, __version__), indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = discover_repository(args.path)
        report = scan_repository(root)
    except (GitError, OSError) as exc:
        if args.json_output:
            print(json.dumps({"error": str(exc), "version": __version__}))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json_output:
        _render_json(report)
    elif args.sarif:
        _render_sarif(report)
    else:
        _render_human(report)

    if not report.ready:
        return 1
    if args.strict and report.warnings:
        return 1
    return 0

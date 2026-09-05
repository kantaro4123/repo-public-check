from __future__ import annotations

import argparse

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-public-check",
        description="Check whether a Git repository is ready to be made public.",
    )
    parser.add_argument("path", nargs="?", default=".", help="repository path (default: .)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.error("checks are not implemented yet")
    return 2

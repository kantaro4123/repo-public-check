from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def _run_git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise GitError(message)
    return result


def discover_repository(path: str | Path) -> Path:
    candidate = Path(path).expanduser().resolve()
    start = candidate if candidate.is_dir() else candidate.parent
    result = _run_git(start, "rev-parse", "--show-toplevel", check=False)
    if result.returncode != 0:
        raise GitError(f"not a Git repository: {candidate}")
    return Path(result.stdout.strip()).resolve()


def tracked_files(root: Path) -> list[Path]:
    result = _run_git(root, "ls-files", "-z")
    return [root / item for item in result.stdout.split("\0") if item]


def tracked_ignored_files(root: Path) -> list[str]:
    result = _run_git(root, "ls-files", "-ci", "--exclude-standard", "-z")
    return [item for item in result.stdout.split("\0") if item]


def history_paths(root: Path) -> set[str]:
    result = _run_git(root, "log", "--all", "--name-only", "--pretty=format:", check=False)
    if result.returncode != 0:
        return set()
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def remote_urls(root: Path) -> list[tuple[str, str]]:
    remotes = _run_git(root, "remote", check=False)
    if remotes.returncode != 0:
        return []

    result: list[tuple[str, str]] = []
    for name in (line.strip() for line in remotes.stdout.splitlines()):
        if not name:
            continue
        urls = _run_git(root, "remote", "get-url", "--all", name, check=False)
        if urls.returncode != 0:
            continue
        for url in (line.strip() for line in urls.stdout.splitlines()):
            if url:
                result.append((name, url))
    return result


def remote_url(root: Path) -> str | None:
    for name, url in remote_urls(root):
        if name == "origin":
            return url
    return None

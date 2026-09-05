from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from .git import history_paths, remote_urls, tracked_files, tracked_ignored_files
from .model import Finding, Report, Severity

MAX_TEXT_BYTES = 2 * 1024 * 1024
WARN_FILE_BYTES = 10 * 1024 * 1024
BLOCK_FILE_BYTES = 100 * 1024 * 1024

SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("private-key", "Private key material", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("github-token", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("openai-api-key", "OpenAI API key", re.compile(r"\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}\b")),
    ("anthropic-api-key", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("npm-token", "npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
    ("gitlab-token", "GitLab access token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", "AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("stripe-live-key", "Stripe live secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("google-api-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
)

GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*[\"']?([^\s\"']{8,})"
)

PERSONAL_PATH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("macOS user path", re.compile(r"/Users/[A-Za-z0-9._-]+/")),
    ("Linux home path", re.compile(r"/home/[A-Za-z0-9._-]+/")),
    ("Windows user path", re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+\\", re.IGNORECASE)),
)

LOCAL_URL_RE = re.compile(
    r"(?i)https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|[A-Za-z0-9.-]+\.(?:local|internal))(?::\d+)?"
)
PRIVATE_IP_RE = re.compile(
    r"(?i)https?://(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?::\d+)?"
)
REMOTE_CREDENTIALS_RE = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@")
PRIVATE_REMOTE_RE = re.compile(
    r"(?i)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|(?:^|[.@/])[^/@/:]+\.(?:local|internal)(?=[:/]|$)|"
    r"10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})"
)
TODO_RE = re.compile(r"\b(?:TODO|FIXME)\b")

SENSITIVE_BASENAME_PATTERNS = (
    ".env",
    ".env.*",
    "id_rsa",
    "id_dsa",
    "id_ed25519",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "credentials.json",
    "service-account*.json",
)
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist")
ARTIFACT_PARTS = {"node_modules", ".venv", "venv", "__pycache__", "coverage", ".pytest_cache"}
ARTIFACT_NAMES = {".DS_Store"}


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_sensitive_name(path: str) -> bool:
    name = Path(path).name.lower()
    if name.startswith(".env") and name.endswith(SAFE_ENV_SUFFIXES):
        return False
    return any(fnmatch.fnmatch(name, pattern.lower()) for pattern in SENSITIVE_BASENAME_PATTERNS)


def _read_text(path: Path) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_TEXT_BYTES:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    return data.decode("utf-8", errors="replace")


def _line_number(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def _check_metadata(root: Path, tracked: list[Path], report: Report) -> None:
    root_names = {path.name.lower() for path in tracked if path.parent == root}
    all_relative = {_relative(root, path).lower() for path in tracked}

    if not any(name.startswith("readme") for name in root_names):
        report.add(Finding("missing-readme", Severity.WARNING, "README missing", "Add a README before publishing."))
    if not any(name.startswith("license") or name.startswith("copying") for name in root_names):
        report.add(Finding("missing-license", Severity.WARNING, "License missing", "Add an explicit open-source license before publishing."))
    if ".gitignore" not in root_names:
        report.add(Finding("missing-gitignore", Severity.WARNING, ".gitignore missing", "Add a .gitignore to reduce accidental commits."))
    if "security.md" not in root_names and ".github/security.md" not in all_relative:
        report.add(Finding("missing-security-policy", Severity.INFO, "SECURITY.md missing", "A security policy is recommended for public repositories."))


def _check_symlink(root: Path, path: Path, report: Report) -> None:
    rel = _relative(root, path)
    try:
        target = path.readlink()
    except OSError:
        report.add(Finding("tracked-symlink", Severity.INFO, "Tracked symbolic link", "The link target could not be inspected safely.", rel))
        return

    report.add(Finding("tracked-symlink", Severity.INFO, "Tracked symbolic link", f"Link target: {target}", rel))

    target_path = target if target.is_absolute() else path.parent / target
    try:
        resolved = target_path.resolve(strict=False)
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        report.add(
            Finding(
                "symlink-outside-repo",
                Severity.WARNING,
                "Symbolic link points outside the repository",
                "The scanner will not follow this link. Verify that publishing the link target is intentional.",
                rel,
            )
        )


def _check_tracked_paths(root: Path, tracked: list[Path], report: Report) -> None:
    ignored = set(tracked_ignored_files(root))
    for path in tracked:
        rel = _relative(root, path)
        parts = set(Path(rel).parts)
        name = path.name

        if path.is_symlink():
            _check_symlink(root, path, report)

        if _is_sensitive_name(rel):
            report.add(Finding("sensitive-filename", Severity.BLOCKER, "Sensitive-looking file is tracked", "Remove the file from Git and rotate credentials if it contained secrets.", rel))
        elif rel in ignored:
            report.add(Finding("tracked-ignored-file", Severity.WARNING, "Ignored file is still tracked", "The file matches .gitignore but remains in Git history.", rel))

        if parts & ARTIFACT_PARTS or name in ARTIFACT_NAMES:
            report.add(Finding("tracked-artifact", Severity.WARNING, "Generated artifact is tracked", "Consider removing generated or machine-specific files before publishing.", rel))

        try:
            size = path.lstat().st_size
        except OSError:
            continue
        if size > BLOCK_FILE_BYTES:
            report.add(Finding("file-over-100mb", Severity.BLOCKER, "File exceeds 100 MiB", "GitHub blocks normal Git pushes of files larger than 100 MiB.", rel))
        elif size > WARN_FILE_BYTES:
            report.add(Finding("large-file", Severity.WARNING, "Large tracked file", f"Tracked file is {size / (1024 * 1024):.1f} MiB; consider Git LFS or removing it.", rel))


def _check_text_file(root: Path, path: Path, report: Report) -> None:
    rel = _relative(root, path)
    text = _read_text(path)
    if text is None:
        return

    for code, title, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            report.add(Finding(code, Severity.BLOCKER, title, "Potential credential material is present in a tracked file. Remove it and rotate the credential before publishing.", rel, _line_number(text, match.start())))

    generic = GENERIC_SECRET_RE.search(text)
    if generic:
        report.add(Finding("generic-secret-assignment", Severity.WARNING, "Secret-like assignment", "A password/token/key-like assignment was found. Verify that the value is not a real secret.", rel, _line_number(text, generic.start())))

    for label, pattern in PERSONAL_PATH_PATTERNS:
        match = pattern.search(text)
        if match:
            report.add(Finding("personal-path", Severity.WARNING, "Personal absolute path", f"Found a {label}; replace machine-specific paths with relative paths or placeholders.", rel, _line_number(text, match.start())))
            break

    match = LOCAL_URL_RE.search(text) or PRIVATE_IP_RE.search(text)
    if match:
        report.add(Finding("private-url", Severity.WARNING, "Local or private URL", "Verify that internal development endpoints are not being published accidentally.", rel, _line_number(text, match.start())))

    todo_count = len(TODO_RE.findall(text))
    if todo_count:
        report.add(Finding("todo", Severity.INFO, "TODO/FIXME markers", f"{todo_count} TODO/FIXME marker(s) remain in this file.", rel))


def _check_history(root: Path, current_paths: set[str], report: Report) -> None:
    historical_sensitive = sorted(
        path for path in history_paths(root) if path not in current_paths and _is_sensitive_name(path)
    )
    for path in historical_sensitive[:10]:
        report.add(Finding("sensitive-history-path", Severity.WARNING, "Sensitive-looking file exists in Git history", "Deleting a file in the latest commit does not remove it from Git history. Review the old commits before publishing.", path))
    if len(historical_sensitive) > 10:
        report.add(Finding("sensitive-history-more", Severity.WARNING, "More sensitive history paths found", f"{len(historical_sensitive) - 10} additional sensitive-looking historical path(s) were omitted from the display."))


def _check_remotes(root: Path, report: Report) -> None:
    remotes = remote_urls(root)
    if not remotes:
        report.add(Finding("missing-remote", Severity.INFO, "No Git remote", "The repository has no Git remote configured."))
        return

    for name, url in remotes:
        location = f"remote:{name}"
        if REMOTE_CREDENTIALS_RE.search(url):
            report.add(
                Finding(
                    "remote-credentials",
                    Severity.BLOCKER,
                    "Credentials embedded in Git remote",
                    "Remove credentials from the remote URL and rotate them if they are real. The credential value is intentionally not displayed.",
                    location,
                )
            )
        if PRIVATE_REMOTE_RE.search(url) or url.startswith(("file://", "/", "~/")):
            report.add(
                Finding(
                    "private-remote",
                    Severity.WARNING,
                    "Local or private Git remote",
                    "Verify that this remote does not reveal an internal hostname, private network address, or machine-specific path.",
                    location,
                )
            )


def scan_repository(root: Path) -> Report:
    tracked = tracked_files(root)
    report = Report(repository=str(root), scanned_files=len(tracked))

    _check_metadata(root, tracked, report)
    _check_tracked_paths(root, tracked, report)
    for path in tracked:
        if path.is_symlink():
            continue
        if path.is_file():
            _check_text_file(root, path, report)

    current_paths = {_relative(root, path) for path in tracked}
    _check_history(root, current_paths, report)
    _check_remotes(root, report)

    return report

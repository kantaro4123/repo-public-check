from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from repo_public_check.checks import scan_repository


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def make_repo() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    temp = tempfile.TemporaryDirectory()
    root = Path(temp.name)
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Test User")
    git(root, "config", "user.email", "test@example.com")
    (root / "README.md").write_text("# example\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / ".gitignore").write_text(".env\n", encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-m", "initial")
    return temp, root


class SecretPatternTests(unittest.TestCase):
    def test_modern_developer_tokens_are_blockers(self) -> None:
        cases = {
            "openai-api-key": "sk-proj-" + ("a" * 40),
            "anthropic-api-key": "sk-ant-api03-" + ("b" * 40),
            "npm-token": "npm_" + ("c" * 36),
            "gitlab-token": "glpat-" + ("d" * 32),
        }

        for expected_code, secret in cases.items():
            with self.subTest(expected_code=expected_code):
                temp, root = make_repo()
                try:
                    (root / "config.txt").write_text(f"value={secret}\n", encoding="utf-8")
                    git(root, "add", "config.txt")
                    git(root, "commit", "-m", "add token")
                    report = scan_repository(root)
                    codes = {finding.code for finding in report.findings}
                    self.assertIn(expected_code, codes)
                    self.assertFalse(report.ready)
                finally:
                    temp.cleanup()


if __name__ == "__main__":
    unittest.main()

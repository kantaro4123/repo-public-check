from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from repo_public_check.checks import scan_repository
from repo_public_check.cli import main
from repo_public_check.git import discover_repository


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def commit_all(root: Path, message: str) -> None:
    git(root, "add", "-A")
    git(root, "commit", "-m", message)


class RepositoryFixture:
    def __enter__(self) -> Path:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        git(root, "init", "-b", "main")
        git(root, "config", "user.name", "Test User")
        git(root, "config", "user.email", "test@example.com")
        (root / "README.md").write_text("# example\n", encoding="utf-8")
        (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
        (root / ".gitignore").write_text(".env\n", encoding="utf-8")
        commit_all(root, "initial")
        self.root = root
        return root

    def __exit__(self, exc_type, exc, tb) -> None:
        self.temp.cleanup()


class RepoPublicCheckTests(unittest.TestCase):
    def test_discovers_repository_from_nested_path(self) -> None:
        with RepositoryFixture() as root:
            nested = root / "src" / "app"
            nested.mkdir(parents=True)
            self.assertEqual(discover_repository(nested), root.resolve())

    def test_clean_repository_has_no_blockers(self) -> None:
        with RepositoryFixture() as root:
            report = scan_repository(root)
            self.assertTrue(report.ready)
            self.assertEqual(report.blockers, 0)
            self.assertEqual(report.score, 100)

    def test_tracked_env_file_is_a_blocker(self) -> None:
        with RepositoryFixture() as root:
            env_file = root / ".env"
            env_file.write_text("APP_MODE=dev\n", encoding="utf-8")
            git(root, "add", "-f", ".env")
            git(root, "commit", "-m", "add env")
            report = scan_repository(root)
            codes = {finding.code for finding in report.findings}
            self.assertIn("sensitive-filename", codes)
            self.assertFalse(report.ready)

    def test_high_confidence_token_is_a_blocker(self) -> None:
        with RepositoryFixture() as root:
            fake = "ghp_" + ("a" * 30)
            (root / "config.txt").write_text(f"TOKEN={fake}\n", encoding="utf-8")
            commit_all(root, "add config")
            report = scan_repository(root)
            codes = {finding.code for finding in report.findings}
            self.assertIn("github-token", codes)

    def test_personal_absolute_path_is_a_warning(self) -> None:
        with RepositoryFixture() as root:
            personal_path = "/Users/" + "example/Library/cache"
            (root / "config.txt").write_text(f"cache={personal_path}\n", encoding="utf-8")
            commit_all(root, "add path")
            report = scan_repository(root)
            codes = {finding.code for finding in report.findings}
            self.assertIn("personal-path", codes)
            self.assertTrue(report.ready)

    def test_windows_personal_path_is_a_warning(self) -> None:
        with RepositoryFixture() as root:
            windows_path = "C:\\" + "Users\\example\\AppData\\Local"
            (root / "config.txt").write_text(f"cache={windows_path}\n", encoding="utf-8")
            commit_all(root, "add windows path")
            report = scan_repository(root)
            codes = {finding.code for finding in report.findings}
            self.assertIn("personal-path", codes)
            self.assertTrue(report.ready)

    def test_tracked_symlink_is_not_followed(self) -> None:
        with RepositoryFixture() as root:
            outside = root.parent / f"{root.name}-outside-secret.txt"
            outside.write_text("TOKEN=ghp_" + ("a" * 30) + "\n", encoding="utf-8")
            try:
                link = root / "external-secret.txt"
                link.symlink_to(outside)
                commit_all(root, "add symlink")
                report = scan_repository(root)
                codes = {finding.code for finding in report.findings}
                self.assertIn("tracked-symlink", codes)
                self.assertFalse(
                    any(
                        finding.code == "github-token" and finding.path == "external-secret.txt"
                        for finding in report.findings
                    )
                )
            finally:
                outside.unlink(missing_ok=True)

    def test_credentials_in_non_origin_remote_are_blocked(self) -> None:
        with RepositoryFixture() as root:
            token = "ghp_" + ("a" * 30)
            git(root, "remote", "add", "backup", f"https://user:{token}@example.com/repo.git")
            report = scan_repository(root)
            codes = {finding.code for finding in report.findings}
            self.assertIn("remote-credentials", codes)
            self.assertFalse(report.ready)

    def test_private_remote_host_is_a_warning(self) -> None:
        with RepositoryFixture() as root:
            git(root, "remote", "add", "origin", "ssh://git@source.internal/team/repo.git")
            report = scan_repository(root)
            codes = {finding.code for finding in report.findings}
            self.assertIn("private-remote", codes)
            self.assertTrue(report.ready)

    def test_sensitive_file_removed_from_head_is_found_in_history(self) -> None:
        with RepositoryFixture() as root:
            env_file = root / ".env"
            env_file.write_text("OLD_VALUE=example\n", encoding="utf-8")
            git(root, "add", "-f", ".env")
            git(root, "commit", "-m", "accidentally add env")
            env_file.unlink()
            commit_all(root, "remove env")
            report = scan_repository(root)
            codes = {finding.code for finding in report.findings}
            self.assertIn("sensitive-history-path", codes)
            self.assertTrue(report.ready)

    def test_json_output_is_machine_readable(self) -> None:
        with RepositoryFixture() as root:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([str(root), "--json"])
            payload = json.loads(output.getvalue())
            self.assertEqual(status, 0)
            self.assertTrue(payload["ready"])
            self.assertEqual(payload["repository"], str(root.resolve()))
            self.assertIn("score", payload)


if __name__ == "__main__":
    unittest.main()

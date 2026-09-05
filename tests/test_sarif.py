from __future__ import annotations

import json
import unittest

from repo_public_check.model import Finding, Report, Severity
from repo_public_check.sarif import report_to_sarif


class SarifTests(unittest.TestCase):
    def test_report_is_converted_to_sarif_210(self) -> None:
        report = Report(repository="/tmp/example", scanned_files=3)
        report.add(
            Finding(
                "github-token",
                Severity.BLOCKER,
                "GitHub token",
                "Potential token found.",
                "src/app.py",
                7,
            )
        )
        report.add(
            Finding(
                "missing-license",
                Severity.WARNING,
                "License missing",
                "Add a license.",
            )
        )

        payload = report_to_sarif(report, "0.2.0")
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "repo-public-check")
        self.assertEqual({rule["id"] for rule in run["tool"]["driver"]["rules"]}, {"github-token", "missing-license"})
        self.assertEqual(run["results"][0]["level"], "error")
        location = run["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "src/app.py")
        self.assertEqual(location["region"]["startLine"], 7)
        self.assertEqual(run["results"][1]["level"], "warning")
        json.dumps(payload)


if __name__ == "__main__":
    unittest.main()

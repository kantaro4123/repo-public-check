from __future__ import annotations

from .model import Finding, Report, Severity


_LEVELS = {
    Severity.BLOCKER: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}


def _rule(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.code,
        "name": finding.code.replace("-", "_"),
        "shortDescription": {"text": finding.title},
        "help": {"text": finding.message},
        "defaultConfiguration": {"level": _LEVELS[finding.severity]},
    }


def _result(finding: Finding) -> dict[str, object]:
    result: dict[str, object] = {
        "ruleId": finding.code,
        "level": _LEVELS[finding.severity],
        "message": {"text": f"{finding.title}: {finding.message}"},
    }
    if finding.path and not finding.path.startswith("remote:"):
        physical: dict[str, object] = {
            "artifactLocation": {"uri": finding.path},
        }
        if finding.line is not None:
            physical["region"] = {"startLine": finding.line}
        result["locations"] = [{"physicalLocation": physical}]
    return result


def report_to_sarif(report: Report, version: str) -> dict[str, object]:
    unique_rules: dict[str, Finding] = {}
    for finding in report.findings:
        unique_rules.setdefault(finding.code, finding)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "repo-public-check",
                        "version": version,
                        "informationUri": "https://github.com/kantaro4123/repo-public-check",
                        "rules": [_rule(finding) for finding in unique_rules.values()],
                    }
                },
                "results": [_result(finding) for finding in report.findings],
                "properties": {
                    "repository": report.repository,
                    "score": report.score,
                    "ready": report.ready,
                    "scannedFiles": report.scanned_files,
                },
            }
        ],
    }

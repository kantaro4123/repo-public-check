from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    BLOCKER = "blocker"
    WARNING = "warning"
    INFO = "info"


@dataclass(slots=True)
class Finding:
    code: str
    severity: Severity
    title: str
    message: str
    path: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(slots=True)
class Report:
    repository: str
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0

    @property
    def blockers(self) -> int:
        return sum(item.severity is Severity.BLOCKER for item in self.findings)

    @property
    def warnings(self) -> int:
        return sum(item.severity is Severity.WARNING for item in self.findings)

    @property
    def ready(self) -> bool:
        return self.blockers == 0

    @property
    def score(self) -> int:
        blocker_penalty = min(100, self.blockers * 25)
        warning_penalty = min(30, self.warnings * 5)
        return max(0, 100 - blocker_penalty - warning_penalty)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "ready": self.ready,
            "score": self.score,
            "scanned_files": self.scanned_files,
            "summary": {
                "blockers": self.blockers,
                "warnings": self.warnings,
                "info": sum(item.severity is Severity.INFO for item in self.findings),
            },
            "findings": [item.to_dict() for item in self.findings],
        }

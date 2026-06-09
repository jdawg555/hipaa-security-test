from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    MANUAL = "manual"
    SKIP = "skip"
    ERROR = "error"


class ControlType(str, Enum):
    AUTOMATED = "automated"
    MANUAL = "manual"
    HYBRID = "hybrid"


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: CheckStatus
    message: str
    evidence_path: str | None = None
    remediation: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Control:
    id: str
    title: str
    category: str
    citation: str
    description: str
    control_type: ControlType
    severity: str
    checks: list[dict[str, Any]]
    nist_csf: list[str] = field(default_factory=list)
    soc2_mapping: list[str] = field(default_factory=list)


@dataclass
class ControlResult:
    control: Control
    results: list[CheckResult]

    @property
    def status(self) -> CheckStatus:
        statuses = {r.status for r in self.results}
        if CheckStatus.FAIL in statuses or CheckStatus.ERROR in statuses:
            return CheckStatus.FAIL
        if CheckStatus.WARN in statuses:
            return CheckStatus.WARN
        if CheckStatus.MANUAL in statuses and len(statuses) == 1:
            return CheckStatus.MANUAL
        if CheckStatus.SKIP in statuses and len(statuses) == 1:
            return CheckStatus.SKIP
        return CheckStatus.PASS


@dataclass
class AuditReport:
    org_name: str
    repo_path: str
    controls: list[ControlResult]
    generated_at: str
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in CheckStatus}
        for cr in self.controls:
            counts[cr.status.value] += 1
        return counts

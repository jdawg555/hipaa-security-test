"""Export hipaa-audit results for import into Probo (getprobo/probo)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hipaa_audit import __version__
from hipaa_audit.models import AuditReport, CheckStatus
from hipaa_audit.posture import compute_posture


def to_probo_bundle(report: AuditReport) -> dict[str, Any]:
    posture = compute_posture(report)
    measures: list[dict[str, Any]] = []
    evidence_items: list[dict[str, Any]] = []

    for cr in report.controls:
        status = cr.status.value
        measures.append(
            {
                "external_id": cr.control.id,
                "name": cr.control.title,
                "framework": "HIPAA",
                "citation": cr.control.citation,
                "category": cr.control.category,
                "severity": cr.control.severity,
                "implementation_state": _probo_state(status),
                "description": cr.control.description,
            }
        )
        for result in cr.results:
            if result.evidence_path:
                evidence_items.append(
                    {
                        "control_id": cr.control.id,
                        "check_id": result.check_id,
                        "status": result.status.value,
                        "message": result.message,
                        "file_path": result.evidence_path,
                    }
                )

    return {
        "format": "hipaa-audit-probo-v1",
        "source": "hipaa-audit",
        "version": __version__,
        "org_name": report.org_name,
        "generated_at": report.generated_at,
        "repo_path": report.repo_path,
        "posture_score": posture["score"],
        "summary": report.summary,
        "framework": "HIPAA Security Rule",
        "measures": measures,
        "evidence": evidence_items,
        "import_hints": {
            "probo_repo": "https://github.com/getprobo/probo",
            "cli": "prb measure create / prb evidence create --file <path>",
            "mcp": "Use Probo MCP tools to bulk-import measures from this JSON",
        },
    }


def _probo_state(status: str) -> str:
    return {
        "pass": "implemented",
        "warn": "partial",
        "fail": "not_implemented",
        "error": "not_implemented",
        "manual": "manual_review",
        "skip": "not_applicable",
    }.get(status, "unknown")


def write_probo_export(report: AuditReport, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(to_probo_bundle(report), indent=2))
    return output

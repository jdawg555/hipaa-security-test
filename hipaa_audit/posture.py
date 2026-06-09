from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hipaa_audit.models import AuditReport, CheckStatus

SEVERITY_WEIGHT = {"required": 3.0, "addressable": 1.0}


def compute_posture(report: AuditReport) -> dict[str, Any]:
    """Weighted posture score (required controls count 3x addressable)."""
    total_weight = 0.0
    earned = 0.0
    status_points = {
        CheckStatus.PASS: 100,
        CheckStatus.WARN: 50,
        CheckStatus.FAIL: 0,
        CheckStatus.ERROR: 0,
    }
    by_category: dict[str, list[float]] = {}

    for cr in report.controls:
        weight = SEVERITY_WEIGHT.get(cr.control.severity, 1.0)
        if cr.status in (CheckStatus.MANUAL, CheckStatus.SKIP):
            continue
        points = status_points.get(cr.status, 0)
        total_weight += weight
        earned += weight * (points / 100.0)
        by_category.setdefault(cr.control.category, []).append(points)

    score = round(100 * earned / total_weight, 1) if total_weight else 0.0
    category_scores = {
        cat: round(sum(vals) / len(vals), 1) if vals else 0.0
        for cat, vals in by_category.items()
    }
    failing = [
        {"id": cr.control.id, "title": cr.control.title, "status": cr.status.value}
        for cr in report.controls
        if cr.status in (CheckStatus.FAIL, CheckStatus.ERROR)
    ]
    return {
        "score": score,
        "automated_pass_rate": _automated_pass_rate(report),
        "category_scores": category_scores,
        "summary": report.summary,
        "failing_controls": failing[:20],
        "generated_at": report.generated_at,
    }


def _automated_pass_rate(report: AuditReport) -> float:
    auto = [
        cr
        for cr in report.controls
        if cr.control.control_type.value != "manual"
        and cr.status not in (CheckStatus.SKIP, CheckStatus.MANUAL)
    ]
    if not auto:
        return 0.0
    passed = sum(1 for cr in auto if cr.status == CheckStatus.PASS)
    return round(100 * passed / len(auto), 1)


def record_history(report: AuditReport, repo_path: Path) -> Path:
    posture = compute_posture(report)
    history_dir = repo_path / "evidence" / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    history_file = history_dir / "posture.jsonl"
    line = json.dumps(
        {
            "generated_at": report.generated_at,
            "score": posture["score"],
            "automated_pass_rate": posture["automated_pass_rate"],
            "summary": posture["summary"],
        }
    )
    with history_file.open("a") as fh:
        fh.write(line + "\n")
    snapshot = history_dir / "posture-latest.json"
    snapshot.write_text(json.dumps(posture, indent=2))
    return snapshot

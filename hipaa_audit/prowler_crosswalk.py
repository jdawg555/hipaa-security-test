from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.controls import PACKAGE_ROOT

CROSSWALK_FILES = {
    "aws": "prowler-hipaa-crosswalk.yaml",
    "azure": "prowler-azure-hipaa-crosswalk.yaml",
    "gcp": "prowler-gcp-hipaa-crosswalk.yaml",
}


def load_crosswalk(*, provider: str = "aws") -> dict[str, Any]:
    filename = CROSSWALK_FILES.get(provider, CROSSWALK_FILES["aws"])
    path = PACKAGE_ROOT / "controls" / filename
    if not path.exists():
        return {"requirements": []}
    return yaml.safe_load(path.read_text()) or {"requirements": []}


def _check_id_from_finding(item: dict[str, Any]) -> str:
    for key in ("check_id", "CheckID", "metadata", "event_code"):
        val = item.get(key) if key != "metadata" else item.get("metadata", {}).get("event_code")
        if val:
            return str(val).lower().replace("-", "_")
    title = item.get("check_title") or item.get("Title") or ""
    return str(title).lower().replace(" ", "_").replace("-", "_")[:80]


def _finding_status(item: dict[str, Any]) -> str:
    status = (
        item.get("status")
        or item.get("Status")
        or item.get("status_code")
        or item.get("compliance", {}).get("status")
        or ""
    )
    return str(status).upper()


def collect_finding_statuses(files: list[Path]) -> dict[str, str]:
    """Map prowler check_id → worst status (FAIL > PASS)."""
    statuses: dict[str, str] = {}
    for path in files:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        items: list[Any] = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("findings") or data.get("Results") or data.get("checks") or []
        for item in items:
            if not isinstance(item, dict):
                continue
            cid = _check_id_from_finding(item)
            st = _finding_status(item)
            if not cid:
                continue
            if st in ("FAIL", "FAILED", "FAILURE"):
                statuses[cid] = "FAIL"
            elif cid not in statuses:
                statuses[cid] = st or "PASS"
    return statuses


def rollup_requirements(finding_statuses: dict[str, str], *, provider: str = "aws") -> list[dict[str, Any]]:
    crosswalk = load_crosswalk(provider=provider)
    results: list[dict[str, Any]] = []
    for req in crosswalk.get("requirements", []):
        checks = req.get("prowler_checks", [])
        failed: list[str] = []
        passed: list[str] = []
        unknown: list[str] = []
        for check in checks:
            key = check.lower()
            st = finding_statuses.get(key)
            if st in ("FAIL", "FAILED", "FAILURE"):
                failed.append(check)
            elif st:
                passed.append(check)
            else:
                unknown.append(check)
        if failed:
            status = "fail"
        elif passed and not unknown:
            status = "pass"
        elif passed:
            status = "partial"
        else:
            status = "unknown"
        results.append(
            {
                "id": req["id"],
                "title": req.get("title", ""),
                "hipaa_refs": req.get("hipaa_refs", []),
                "status": status,
                "failed_checks": failed,
                "passed_checks": passed,
                "unknown_checks": unknown,
            }
        )
    return results

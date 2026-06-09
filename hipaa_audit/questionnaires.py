from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.vendors import SIG_LITE_KEYS, load_vendors, review_vendor


def load_questionnaires(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"questionnaires": []}
    return yaml.safe_load(path.read_text()) or {"questionnaires": []}


def save_questionnaires(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def send_questionnaire(
    q_path: Path,
    vendors_path: Path,
    *,
    vendor_id: str,
    contact: str,
    due_days: int = 30,
) -> dict[str, Any] | None:
    vendors = load_vendors(vendors_path)
    vendor = next((v for v in vendors.get("vendors", []) if v.get("id") == vendor_id), None)
    if not vendor:
        return None

    data = load_questionnaires(q_path)
    seq = len(data.get("questionnaires", [])) + 1
    due = (datetime.now(UTC) + timedelta(days=due_days)).strftime("%Y-%m-%d")
    entry = {
        "id": f"QNR-{seq:03d}",
        "vendor_id": vendor_id,
        "vendor_name": vendor.get("name"),
        "contact": contact,
        "sent_at": datetime.now(UTC).strftime("%Y-%m-%d"),
        "due_date": due,
        "status": "pending",
        "responded_at": None,
        "responses": {k: None for k in SIG_LITE_KEYS},
    }
    data.setdefault("questionnaires", []).append(entry)
    save_questionnaires(q_path, data)
    return entry


def respond_questionnaire(
    q_path: Path,
    vendors_path: Path,
    questionnaire_id: str,
    responses: dict[str, Any],
    *,
    reviewer: str = "",
) -> bool:
    data = load_questionnaires(q_path)
    for q in data.get("questionnaires", []):
        if q.get("id") != questionnaire_id:
            continue
        q["responses"].update(responses)
        q["status"] = "responded"
        q["responded_at"] = datetime.now(UTC).strftime("%Y-%m-%d")
        save_questionnaires(q_path, data)
        review_vendor(vendors_path, q["vendor_id"], responses, reviewer=reviewer)
        return True
    return False


def assess_questionnaires(q_path: Path, config: dict[str, Any]) -> tuple[str, str, list[str]]:
    data = load_questionnaires(q_path)
    items = data.get("questionnaires", [])
    if not items:
        return "manual", "No outbound questionnaires — hipaa-audit vendor send", []

    now = datetime.now(UTC).date()
    issues: list[str] = []
    for q in items:
        if q.get("status") == "responded":
            continue
        due = _parse_date(q.get("due_date", ""))
        if due and now > due:
            issues.append(f"{q['id']}: overdue ({q.get('vendor_name')})")
        elif q.get("status") == "pending":
            issues.append(f"{q['id']}: awaiting response ({q.get('vendor_name')})")

    if not issues:
        return "pass", "All vendor questionnaires responded", []
    if len(issues) <= 2:
        return "warn", "; ".join(issues[:3]), issues
    return "fail", f"{len(issues)} questionnaire gap(s)", issues


def _parse_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        return None
